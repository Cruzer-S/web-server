#include "web_server.h"

#include <string.h>
#include <stdlib.h>

#include <unistd.h>

#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "Cruzer-S/event-handler/event_handler.h"
#include "Cruzer-S/net-util/net-util.h"

#include "web_client.h"

const WebServerConfig web_server_default_config = &(struct web_server_config) {
	.hostname = NULL,
	.service = "80",

	.server_name = "mythos engine",
	.basedir = ".",

	.use_ssl = false,

	.nthread = 4
};

struct web_server {
	int listener_fd;
	Event listener;

	EventHandler *handlers;
	int n_handler;
	int next_handler;

	WebServerHandler open_callback;
	WebServerHandler request_callback;
	WebServerHandler close_callback;

	WebServerConfig config;

	bool is_running;

	SSL_CTX *ctx;
};

static void handle_client(int _, void* arg)
{
	WebClient client = arg;
	WebServer server = client->server;

	int retval = web_client_get_request(arg);

	switch (retval) {
	case -1:
		if (server->close_callback)
			server->close_callback(client->session);

		event_handler_del(client->handler, client->event);
		close(client->session->fd);
		web_client_destroy(client);
		break;

	case 0:
		/* do nothing */ ;
		break;

	case 1:
		if (server->request_callback)
			server->request_callback(client->session);
		web_client_clear(client);
		break;
	}

	return ;
}

static void accept_client(int _, void *arg)
{
	WebServer server;
	WebClient client;
	EventHandler next_handler;
	int clnt_fd;

	server = arg;

	if ( !server->is_running )
		return ;

	clnt_fd = accept(server->listener_fd, NULL, NULL);
	if (clnt_fd == -1)
		goto JUST_RETURN;

	if (fcntl_set_nonblocking(clnt_fd) == -1)
		goto CLOSE_FD;

	server->next_handler = (server->next_handler + 1) % server->n_handler;
	next_handler = server->handlers[server->next_handler];

	client = web_client_create(server, next_handler, handle_client, clnt_fd, server->ctx);
	if (client == NULL)
		goto CLOSE_FD;

	if (server->open_callback)
		server->open_callback(client->session);

	if (event_handler_add(next_handler, client->event) == -1)
		goto CLIENT_DESTROY;

	return ;

CLIENT_DESTROY:	web_client_destroy(client);
CLOSE_FD:	close(clnt_fd);
JUST_RETURN:	return;
}

static int web_server_init_ssl(WebServer server)
{
	int retval;

	server->ctx = SSL_CTX_new(TLS_method());
	if (server->ctx == NULL)
		goto RETURN_ERR;

	retval = SSL_CTX_use_certificate_chain_file(
		server->ctx, server->config->cert_key
	);
	if (retval != 1)
		goto FREE_SSL_CTX;

	retval = SSL_CTX_use_PrivateKey_file(
		server->ctx, server->config->priv_key, SSL_FILETYPE_PEM
	);
	if (retval != 1)
		goto FREE_SSL_CTX;


	if (SSL_CTX_check_private_key(server->ctx) != 1)
		goto FREE_SSL_CTX;

	return 0;

FREE_SSL_CTX:	SSL_CTX_free(server->ctx);
RETURN_ERR:	return -1;
}

WebServer web_server_create(WebServerConfig config)
{
	WebServer server;	

	server = malloc(sizeof(struct web_server));
	if (server == NULL)
		goto RETURN_NULL;

	server->config = config;
	server->n_handler = server->config->nthread;

	if (server->config->use_ssl) {
 		if (web_server_init_ssl(server) == -1)
			goto FREE_SERVER;
	} else {
		server->ctx = NULL;
	}

	server->listener_fd = make_listener(
		config->hostname, config->service, 15, true
	);
	if (server->listener_fd == -1)
		goto FREE_SSL;

	server->handlers = malloc(sizeof(EventHandler) * server->n_handler);
	if (server->handlers == NULL)
		goto CLOSE_LISTENER;

	for (int i = 0; i < server->n_handler; i++) {
		server->handlers[i] = event_handler_create();

		if (server->handlers[i] == NULL) {
			for (int j = i - 1; j >= 0; j--)
				event_handler_destroy(server->handlers[j]);

			goto FREE_HANDLERS;
		}
	}

	server->open_callback = NULL;
	server->request_callback = NULL;
	server->close_callback = NULL;

	server->is_running = false;

	return server;

FREE_HANDLERS:	free(server->handlers);
CLOSE_LISTENER:	close(server->listener_fd);
FREE_SSL:	if (server->ctx)
			SSL_CTX_free(server->ctx);
FREE_SERVER:	free(server);
RETURN_NULL:	return NULL;
}

void web_server_destroy(WebServer server)
{
	if (server->ctx)
		SSL_CTX_free(server->ctx);

	close(server->listener_fd);

	for (int i = 0; i < server->n_handler; i++)
		event_handler_destroy(server->handlers[i]);

	free(server->handlers);
	free(server);
}

int web_server_start(WebServer server)
{
	int retval;

	server->next_handler = 1;

	server->listener = event_create(server->listener_fd,
				 	accept_client, server);
	if ( !server->listener )
		return -1;

	for (int i = 0; i < server->n_handler; i++) {
		retval = event_handler_start(server->handlers[i]);
		if (retval == -1) {
			for (int j = i - 1; j >= 0; j--)
				event_handler_stop(server->handlers[j]);

			return -1;
		}
	}
	
	retval = event_handler_add(server->handlers[0], server->listener);
	if (retval == -1) {
		event_destroy(server->listener);

		for (int i = 0; i < server->n_handler; i++)
			event_handler_stop(server->handlers[i]);

		return -1;
	}

	server->is_running = true;	

	return 0;
}

void web_server_register_handler(
		WebServer server, WebServerHandler open,
		WebServerHandler request, WebServerHandler close
) {
	server->open_callback = open;
	server->request_callback = request;
	server->close_callback = close;
}

void web_server_stop(WebServer server)
{
	WebClient client;
	struct list *events;

	server->is_running = false;

	event_handler_del(server->handlers[0], server->listener);
	event_destroy(server->listener);

	for (int i = 0 ; i < server->n_handler; i++) {
		event_handler_stop(server->handlers[i]);

		events = event_handler_get_events(server->handlers[i]);
		LIST_FOREACH_ENTRY_SAFE(events, event, struct event, list) {
			client = event->arg;
			event_handler_del(client->handler, client->event);
			close(client->session->fd);
			web_client_destroy(client);
		}
	}
}

WebServerConfig web_server_get_config(WebServer server)
{
	return server->config;
}
