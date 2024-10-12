#ifndef WEB_SERVER_H__
#define WEB_SERVER_H__

#include "Cruzer-S/http/http.h"

#include <stddef.h> // size_t

typedef struct web_server_config {
	char *server_name;
	char *basedir;
} *WebServerConfig;

struct request_data {
	int fd;

	struct http_request_header *header;
	char *body;
	size_t bodylen;
};

typedef struct web_server *WebServer;
typedef void (*WebServerHandler)(WebServer , struct request_data *);

WebServer web_server_create(int serv_fd, WebServerConfig config);
void web_server_destroy(WebServer server);

int web_server_start(WebServer server);
void web_server_stop(WebServer server);

void web_server_register_handler(WebServer server, WebServerHandler handler);

WebServerConfig web_server_get_config(WebServer );

#endif
