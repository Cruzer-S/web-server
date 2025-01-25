#include "web_server_util.h"

#include "web_server.h"
#include "web_client.h"
#include "session.h"

#include "Cruzer-S/linux-lib/file.h"
#include "Cruzer-S/ctemplate/ctemplate.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include <unistd.h>
#include <sys/fcntl.h>
#include <linux/limits.h>

#define SESSION_ERR(S, E) { (S)->error = (E); return -1; }

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
// `ws_render` only accept HTML file.
// Therefore, `Content-Type` is fixed to `text/html; charset=utf-8`
int ws_render_template(Session session, enum http_status_code code,
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

int ws_render(Session session, enum http_status_code code, const char *filename)
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
