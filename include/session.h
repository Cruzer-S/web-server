#ifndef SESSION_H__
#define SESSION_H__

#include "web_server.h"

#include "Cruzer-S/event-handler/event-object.h"

#include <openssl/ssl.h>

enum session_process {
	SESSION_PROCESS_READ_HEADER,
	SESSION_PROCESS_PARSE_HEADER,
	SESSION_PROCESS_READ_BODY,
	SESSION_PROCESS_DONE,
	SESSION_PROCESS_REARMING
};

typedef struct session_private {
	struct SESSION_MEMBER;

	enum web_server_error error;

	WebServer server;

	size_t readlen;

	EventObject object;

	SSL *ssl;

	enum session_process progress;
} *SessionPrivate;

SessionPrivate session_create(int fd, SSL_CTX *ctx, EventCallback callback);
void session_destroy(SessionPrivate session);

int session_write(SessionPrivate session, void *buffer, int size);
int session_read(SessionPrivate session, void *buffer, int size);

enum web_server_error session_get_error(SessionPrivate );

#endif
