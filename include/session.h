#ifndef SESSION_H__
#define SESSION_H__

#include "Cruzer-S/http/http.h"

#include <openssl/ssl.h>

typedef struct web_client *WebClient;

enum session_error {
	SESSION_ERROR_NONE,
	SESSION_ERROR_BAD_REQUEST,
	SESSION_ERROR_TOO_LONG_URI,
	SESSION_ERROR_NOT_FOUND,
	SESSION_ERROR_CLOSED,
	SESSION_ERROR_INTERNAL
};

typedef struct session {
	struct http_request_header header;

	char *body;
	size_t bodylen;	

	size_t readlen;

	int fd;
	SSL *ssl;

	WebClient client;

	enum session_error error;
} *Session;

extern enum http_status_code session_errror_to_status_code[];

Session session_create(int fd, SSL_CTX *);

int session_read_header(Session session);
int session_read_body(Session session);
int session_parse_header(Session session);

int session_clear(Session session);

void session_destroy(Session );

int session_write(Session , void *buffer, int size);
int session_read(Session , void *buffer, int size);

#endif
