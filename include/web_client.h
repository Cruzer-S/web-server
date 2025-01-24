#ifndef WEB_CLIENT_H__
#define WEB_CLIENT_H__

#include "session.h"

#include "Cruzer-S/event-handler/event_handler.h"
#include "Cruzer-S/event-handler/event.h"

typedef struct web_server *WebServer;
typedef struct web_client *WebClient;

enum web_client_progress {
	WEB_CLIENT_PROGRESS_READ_HEADER,
	WEB_CLIENT_PROGRESS_PARSE_HEADER,
	WEB_CLIENT_PROGRESS_READ_BODY,
	WEB_CLIENT_PROGRESS_DONE,
};

struct web_client {
	WebServer server;

	EventHandler handler;
	Event event;

	Session session;
	size_t readlen;
	enum web_client_progress progress;
};

WebClient web_client_create(WebServer , EventHandler ,
			    EventCallback , int fd, SSL_CTX *);

int web_client_get_request(WebClient );
void web_client_clear(WebClient );

void web_client_destroy(WebClient client);

#endif
