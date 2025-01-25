#ifndef WEB_SERVER_H__
#define WEB_SERVER_H__

#include <stddef.h> // size_t
#include <stdbool.h>

#include "web_client.h"

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

	int nthread;
} *WebServerConfig;

typedef struct web_server *WebServer;
typedef void (*WebServerHandler)(Session );

extern const WebServerConfig web_server_default_config;

WebServer web_server_create(WebServerConfig );
void web_server_destroy(WebServer );

int web_server_start(WebServer );
void web_server_stop(WebServer );

void web_server_register_handler(
		WebServer ,
		WebServerHandler open,
		WebServerHandler request,
		WebServerHandler close
);

WebServerConfig web_server_get_config(WebServer );

#endif
