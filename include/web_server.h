#ifndef WEB_SERVER_H__
#define WEB_SERVER_H__

#include "Cruzer-S/logger/logger.h"
#include "Cruzer-S/http/http.h"

typedef struct web_server *WebServer;
typedef void (*WebServerHandler)(int fd, struct http_request_header *, char *);

WebServer web_server_create(int serv_fd);
void web_server_destroy(WebServer server);

int web_server_start(WebServer server);
void web_server_stop(WebServer server);

int web_server_register_handler(
	enum http_request_method method, WebServerHandler handler
);

void web_server_set_logger(Logger logger);

#endif
