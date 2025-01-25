#include "session.h"

#include <stdbool.h>
#include <errno.h>

#include <unistd.h>
#include <sys/socket.h>

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

