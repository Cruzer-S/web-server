#include "web_server_util.h"

#include "Cruzer-S/http/http.h"
#include "Cruzer-S/linux-lib/file.h"
#include "Cruzer-S/event-handler/event-handler.h"
#include "Cruzer-S/event-handler/event-object.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include <unistd.h>
#include <sys/fcntl.h>
#include <linux/limits.h>

#include <openssl/ssl.h>

struct web_server {
	EventHandler handler;

	WebServerHandler callback;

	WebServerConfig config;

	EventObject object;

	SSL_CTX *ctx;
};

enum session_process {
	SESSION_PROCESS_READ_HEADER,
	SESSION_PROCESS_PARSE_HEADER,
	SESSION_PROCESS_READ_BODY,
	SESSION_PROCESS_DONE,
	SESSION_PROCESS_REARMING
};

typedef struct _session {
	struct session _;

	WebServer server;

	size_t readlen;

	EventObject object;

	SSL *ssl;

	enum session_process progress;
} *_Session;

extern int session_write(_Session session, void *buffer, int size);

int session_send_file(_Session session, char *filename)
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

int ws_send_file(Session _, char *filename)
{
	_Session session = (_Session) (
		(void *) _ - (void *) offsetof(struct _session, _)
	);

	char filepath[PATH_MAX];
	size_t fsize; char fsize_str[32];
	struct http_response_header *header;
	WebServerConfig config = session->server->config;

	if (strtlen(3, config->basedir, "/", filename) >= PATH_MAX)
		return -1;

	sprintf(filepath, "%s/%s", config->basedir, filename);
	if (strstr(filepath, ".."))
		return -1;

	if ( !check_file_exists(filepath) )
		return -1;

	fsize = get_file_size(filepath);
	if (fsize == -1)
		return -1;

	sprintf(fsize_str, "%zu", fsize);

	header = http_make_response_header(
		HTTP_VERSION_1_1, 200, 4,
		"Connection", "Keep-Alive",
		"Server", config->server_name,
		"Content-Length", fsize_str,
		"Content-Type", "text/html; charset=utf-8"
	);
	if (header == NULL)
		return -1;

	int headerlen = strlen(header->buffer);
	int writelen = 0;
	int retval;
	while (writelen < headerlen) {
		retval = session_write(session, header + writelen, headerlen);
		if (retval == -1) {
			free(header);
			return -1;
		}
		
		writelen += retval;
	}

	session_send_file(session, filepath);

	free(header);

	return 0;
}
