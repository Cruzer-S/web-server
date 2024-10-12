#include "web_server_util.h"

#include "Cruzer-S/http/http.h"
#include "Cruzer-S/net-util/net-util.h"
#include "Cruzer-S/linux-lib/file.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include <unistd.h>
#include <linux/limits.h>

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

int ws_send_file(WebServer server, int fd, char *filename)
{
	char filepath[PATH_MAX];
	size_t fsize; char fsize_str[32];
	struct http_response_header *header;
	WebServerConfig config;

	config = web_server_get_config(server);

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
	while (writelen < headerlen) {
		int retval = write(fd, header + writelen, headerlen);
		if (retval == -1) {
			free(header);
			return -1;
		}

		writelen += retval;
	}

	send_file(fd, filepath);

	free(header);

	return 0;
}
