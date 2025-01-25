#include "session.h"

#include "Cruzer-S/linux-lib/file.h"
#include "Cruzer-S/ctemplate/ctemplate.h"

#include <stdbool.h>
#include <errno.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/fcntl.h>

#include "web_server.h"

#define SESSION_ERR(S, E) { (S)->error = (E); return -1; }

enum http_status_code session_errror_to_status_code[] = {
	[SESSION_ERROR_NONE] = HTTP_STATUS_CODE_OK,
	[SESSION_ERROR_CLOSED] = HTTP_STATUS_CODE_INTERNAL,
	[SESSION_ERROR_INTERNAL] = HTTP_STATUS_CODE_INTERNAL,
	[SESSION_ERROR_NOT_FOUND] = HTTP_STATUS_CODE_NOT_FOUND,
	[SESSION_ERROR_BAD_REQUEST] = HTTP_STATUS_CODE_BAD_REQUEST,
	[SESSION_ERROR_TOO_LONG_URI] = HTTP_STATUS_CODE_URI_TOO_LONG,
};

Session session_create(int fd, SSL_CTX *ctx)
{
	Session session;

	session = malloc(sizeof(struct session));
	if (session == NULL)
		goto RETURN_NULL;

	session->fd = fd;
	session->body = NULL;
	session->header.field_head = NULL;
	session->header.headerlen = session->bodylen = 0;

	if (ctx) {
		session->ssl = SSL_new(ctx);
		if (session->ssl == NULL)
			goto FREE_SESSION;

		if (SSL_set_fd(session->ssl, session->fd) != 1)
			goto FREE_SSL;

		while (true) {
			int ret = SSL_accept(session->ssl);
			if (ret == 1)
				break;

			ret = SSL_get_error(session->ssl, ret);
			if (ret == SSL_ERROR_WANT_READ 
			 || ret == SSL_ERROR_WANT_WRITE)
				continue;
		}
	} else {
		session->ssl = NULL;
	}

	return session;

FREE_SSL:	SSL_free(session->ssl);
FREE_SESSION:	free(session);
RETURN_NULL:	return NULL;
}

void session_destroy(Session session)
{
	if (session->ssl)
		SSL_free(session->ssl);

	if (session->body)
		free(session->body);

	free(session);
}

int session_write(Session session, void *buffer, int size)
{
	ssize_t len;

	if (session->ssl) {
		len = SSL_write(session->ssl, buffer, size);

		if (len <= 0)
			return -1;
	} else {
		len = write(session->fd, buffer, size);

		if (len == -1)
			return -1;
	}

	return len;
}

int session_read(Session session, void *buffer, int size)
{
	ssize_t len;

	if (session->ssl) {
		len = SSL_read(session->ssl, buffer, size);

		if (len <= 0) {
			int ret = SSL_get_error(session->ssl, len);
			if (ret == SSL_ERROR_WANT_READ)
				return -1;

			if (ret == SSL_ERROR_ZERO_RETURN)
				return 0;

			return -2;
		}
	} else {
		len = recv(session->fd, buffer, size, 0);
		if (len == -1) {
			if (errno == EAGAIN)
				return -1;

			return -2;
		}

		if (len == 0)
			return 0;
	}

	return len;
}

int session_read_header(Session session)
{
	char *buffer = session->header.buffer;
	int *headerlen = &session->header.headerlen;
	int hlen, len;

	while (true) {
		len = session_read(session, buffer + *headerlen, 1);
		if (len == 0)
			return 2;
		if (len == -1)
			return 0;
		if (len == -2)
			return -1;


		*headerlen += len;
		buffer[*headerlen] = '\0';

		hlen = *headerlen - 4;
		if (hlen < 0)
			hlen = 0;

		if (strstr(&buffer[hlen], "\r\n\r\n"))
			return hlen;

		if (hlen == HTTP_HEADER_MAX_SIZE)
			return -1;
	}

	return -1; // never reach
}

int session_read_body(Session session)
{
	char *buffer = session->body;
	int bodylen = session->bodylen;
	size_t *readlen;
	int fd;

	while (true) {
		ssize_t len;

		len = session_read(
			session, &buffer[*readlen], bodylen - *readlen
		);
		if (len == -1)
			return 0;
		if (len == -2)
			return -1;

		*readlen += len;
		if (*readlen == bodylen)
			return *readlen;
	}

	return -1; // never reach
}

int session_clear(Session session)
{
	http_free_field_list(session->header.field_head);
	session->header.field_head = NULL;
	session->header.headerlen = 0;

	if (session->body)
		free(session->body);
	session->body = NULL;

	session->readlen = session->bodylen = 0;

	return 0;
}

static long int parse_body_len(struct http_request_header *header)
{
	struct http_header_field *field;
	long bodylen;
	char *endptr;

	field = http_find_field(header, "Content-Length: ");
	if (field == NULL)
		return 0;

	errno = 0; bodylen = strtol(field->value, &endptr, 10);
	if (field->value == endptr || errno == ERANGE)
		return -1;

	if (bodylen <= 0)
		return -1;

	return bodylen;
}


int session_parse_header(Session session)
{
	if (http_request_header_parse(&session->header) == -1)
		return -1;

	session->bodylen = parse_body_len(&session->header);
	if (session->bodylen == -1) {
		http_free_field_list(session->header.field_head);
		return -1;
	}

	if (session->bodylen > 0) {
		session->body = malloc(session->bodylen);

		if (session->body == NULL)
			return -1;
	}
	
	return session->bodylen;
}

int session_send_file(Session session, char *filename)
{
	int rfd = open(filename, O_RDWR);
	int total_len = 0;

	if (rfd == -1)
		return -1;

	while (true)
	{
		char buffer[BUFSIZ];
		int readlen = read(rfd, buffer, BUFSIZ);

		if (readlen == 0)
			break;

		if (readlen == -1) {
			close(rfd);
			return -1;
		}

		if (session_write(session, buffer, readlen) == -1) {
			close(rfd);
			return -1;
		}

		total_len += readlen;
	}

	close(rfd);

	return total_len;
}

int session_send_data(Session session, char *data, size_t remain_len)
{
	int total_len = 0, readlen;

	while (total_len < remain_len)
	{
		readlen = session_write(session, data, remain_len);
		if (readlen == -1)
			return -1;

		total_len += readlen;
	}

	return total_len;
}

static int strtlen(int n, ...)
{
	int size = 0;
	va_list varg;

	va_start(varg, n);

	while (n-- > 0)
		size += strlen(va_arg(varg, char *));

	va_end(varg);

	return size;
}

int session_render_template(Session session, enum http_status_code code,
		       	    const char *filename, struct cjson_object *json)
{
	WebServerConfig config;
	char filepath[PATH_MAX];
	long int fsize; char fsize_str[32];
	struct http_response_header *header;
	char *content, *rendered;

	config = web_server_get_config(session->client->server);

	if (strtlen(3, config->basedir, "/", filename) >= PATH_MAX)
		SESSION_ERR(session, SESSION_ERROR_TOO_LONG_URI);

	sprintf(filepath, "%s/%s", config->basedir, filename);
	if (strstr(filepath, ".."))
		SESSION_ERR(session, SESSION_ERROR_BAD_REQUEST);

	if ( !check_file_exists(filepath) )
		SESSION_ERR(session, SESSION_ERROR_NOT_FOUND);
	
	content = read_file(filepath);
	if (content == NULL)
		SESSION_ERR(session, SESSION_ERROR_INTERNAL);

	rendered = ctemplate_render(content, json);
	free(content);

	if (rendered == NULL)
		SESSION_ERR(session, SESSION_ERROR_INTERNAL);

	fsize = strlen(rendered);
	sprintf(fsize_str, "%ld", fsize);

	header = http_make_response_header(
		HTTP_VERSION_1_1, code, 3,
		"Server", config->server_name,
		"Content-Length", fsize_str,
		"Content-Type", "text/html; charset=utf-8"
	);
	if (header == NULL)
		SESSION_ERR(session, SESSION_ERROR_INTERNAL);


	int headerlen = strlen(header->buffer);
	int writelen = 0;
	int retval;
	while (writelen < headerlen) {
		retval = session_write(session, header + writelen, headerlen);
		if (retval == -1) {
			free(rendered);
			free(header);
			SESSION_ERR(session, SESSION_ERROR_CLOSED);
		}
		
		writelen += retval;
	}

	if (session_send_data(session, rendered, fsize) == -1) {
		free(rendered);
		free(header);
		SESSION_ERR(session, SESSION_ERROR_CLOSED);
	}

	free(rendered);
	free(header);

	return 0;
}

int session_render(Session session,
		   enum http_status_code code, const char *filename)
{
	WebServerConfig config;
	char filepath[PATH_MAX];
	size_t fsize; char fsize_str[32];
	struct http_response_header *header;

	config = web_server_get_config(session->client->server);

	if (strtlen(3, config->basedir, "/", filename) >= PATH_MAX)
		SESSION_ERR(session, SESSION_ERROR_TOO_LONG_URI);

	sprintf(filepath, "%s/%s", config->basedir, filename);
	if (strstr(filepath, ".."))
		SESSION_ERR(session, SESSION_ERROR_BAD_REQUEST);

	if ( !check_file_exists(filepath) )
		SESSION_ERR(session, SESSION_ERROR_NOT_FOUND);

	fsize = get_file_size(filepath);
	if (fsize == -1)
		SESSION_ERR(session, SESSION_ERROR_INTERNAL);

	sprintf(fsize_str, "%zu", fsize);

	header = http_make_response_header(
		HTTP_VERSION_1_1, code, 3,
		"Server", "server",
		"Content-Length", fsize_str,
		"Content-Type", "text/html; charset=utf-8"
	);
	if (header == NULL)
		SESSION_ERR(session, SESSION_ERROR_INTERNAL);

	int headerlen = strlen(header->buffer);
	int writelen = 0;
	int retval;
	while (writelen < headerlen) {
		retval = session_write(session, header + writelen, headerlen);
		if (retval == -1) {
			free(header);
			SESSION_ERR(session, SESSION_ERROR_CLOSED);
		}
		
		writelen += retval;
	}

	if (session_send_file(session, filepath) == -1) {
		free(header);
		SESSION_ERR(session, SESSION_ERROR_CLOSED);
	}

	free(header);

	return 0;
}
