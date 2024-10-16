#ifndef WEB_SERVER_H__
#define WEB_SERVER_H__

#include "Cruzer-S/http/http.h"

#include <stddef.h> // size_t
#include <stdbool.h>

typedef struct web_server_config {
	char *hostname;
	char *service;

	char *server_name;
	char *basedir;

	struct {
		bool use_ssl;
		char *priv_key;
		char *cert_key;
	};
} *WebServerConfig;

typedef struct session {
	int id;

	struct http_request_header header;
	size_t headerlen;

	char *body;
	size_t bodylen;
} *Session;

typedef struct web_server *WebServer;
typedef void (*WebServerHandler)(Session );

WebServer web_server_create(WebServerConfig config);
void web_server_destroy(WebServer server);

int web_server_start(WebServer server);
void web_server_stop(WebServer server);

void web_server_register_handler(WebServer server, WebServerHandler handler);

WebServerConfig web_server_get_config(WebServer );

#endif
