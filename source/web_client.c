#include "web_client.h"
#include "web_server.h"

#include <stdbool.h>

WebClient web_client_create(WebServer server, EventHandler handler,
			    EventCallback callback, int fd, SSL_CTX *ctx) 
{
	WebClient client;
	Session session;

	client = malloc(sizeof(struct web_client));
	if (client == NULL)
		goto RETURN_NULL;

	client->server = server;
	client->handler = handler;

	client->session = session_create(fd, ctx);
	if ( !client->session )
		goto FREE_CLIENT;

	client->session->client = client;

	client->event = event_create(fd, callback, client);
	if (client->event == NULL)
		goto DESTROY_SESSION;

	client->progress = WEB_CLIENT_PROGRESS_READ_HEADER;
	client->readlen = 0;

	return client;

DESTROY_SESSION:session_destroy(client->session);
FREE_CLIENT:	free(client);
RETURN_NULL:	return NULL;
}

void web_client_destroy(WebClient client)
{
	event_destroy(client->event);
	session_destroy(client->session);
	free(client);
}

int web_client_get_request(WebClient client)
{
	int retval;

	switch(client->progress) {
	case WEB_CLIENT_PROGRESS_READ_HEADER:
		retval = session_read_header(client->session);
		if (retval == -1)	return -1;
		if (retval == 0)	break;

		client->progress++;

	case WEB_CLIENT_PROGRESS_PARSE_HEADER:
		if (session_parse_header(client->session) == -1)
			return -1;

		if (client->session->bodylen == 0)
			return 1;

		client->progress++;

	case WEB_CLIENT_PROGRESS_READ_BODY:
		retval = session_read_body(client->session);
		if (retval == -1)	return -1;
		if (retval == 0)	break;

		client->progress++;

	case WEB_CLIENT_PROGRESS_DONE:
		return 1;
	}

	return 0;
}

void web_client_clear(WebClient client)
{
	client->progress = WEB_CLIENT_PROGRESS_READ_HEADER;

	session_clear(client->session);
}
