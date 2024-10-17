#ifndef WEB_SERVER_PRIVATE_H__
#define WEB_SERVER_PRIVATE_H__

#include "web_server.h"

#include "Cruzer-S/event-handler/event-handler.h"
#include "Cruzer-S/event-handler/event-object.h"

#include <openssl/ssl.h>

enum session_process {
	SESSION_PROCESS_READ_HEADER,
	SESSION_PROCESS_PARSE_HEADER,
	SESSION_PROCESS_READ_BODY,
	SESSION_PROCESS_DONE,
	SESSION_PROCESS_REARMING
};

struct web_server {
	EventHandler handler;

	WebServerHandler callback;

	WebServerConfig config;

	EventObject object;

	SSL_CTX *ctx;
};

typedef struct session_private {
	struct SESSION_MEMBER;

	WebServer server;

	size_t readlen;

	EventObject object;

	SSL *ssl;

	enum session_process progress;
} *SessionPrivate;

#endif
