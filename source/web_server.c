#include "web_server.h"

#include "session.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <unistd.h>

#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "Cruzer-S/event-handler/event-handler.h"
#include "Cruzer-S/net-util/net-util.h"
#include "Cruzer-S/http/http.h"

struct web_server {
	EventHandler handler;

	WebServerHandler open_callback;
	WebServerHandler close_callback;

	WebServerConfig config;

	EventObject object;

	bool is_running;

	SSL_CTX *ctx;
};

static int read_header(SessionPrivate session)
{
	char *buffer = session->header.buffer;
	int len;

	while (true) {
		len = session_read(session, buffer + session->headerlen, 1);
		if (len == -1)
			return 0;
		if (len == -2)
			return -1;

		session->headerlen += len;
		session->header.buffer[session->headerlen] = '\0';

		int hlen = session->headerlen - 4;
		if (hlen < 0)
			hlen = 0;

		if (strstr(&buffer[hlen], "\r\n\r\n"))
			return hlen;

		if (hlen == HTTP_HEADER_MAX_SIZE)
			return -1;
	}

	return -1; // never reach
}

static long int parse_body_len(struct http_request_header *header)
{
	struct http_header_field *field;
	long bodylen;
	char *endptr;

	field = http_find_field(header, "Content-Length: ");
	if (field == NULL)
		return 0;

	errno = 0; bodylen = strtol(field->value, &endptr, 10);
	if (field->value == endptr || errno == ERANGE)
		return -1;

	if (bodylen <= 0)
		return -1;

	return bodylen;
}

static int read_body(SessionPrivate session)
{
	char *buffer = session->body;
	int fd = event_object_get_fd(session->object);

	while (true) {
		ssize_t readlen = recv(
			fd, &buffer[session->readlen],
			session->bodylen - session->readlen, 0
		);
		if (readlen == -1) {
			if (errno == EAGAIN)
				return 0;

			return -1;
		}

		if (readlen == 0)
			return -1;

		session->readlen += readlen;
		if (session->readlen == session->bodylen)
			return session->readlen;
	}

	return -1; // never reach
}

static int session_rearm(SessionPrivate session)
{
	http_free_field_list(session->header.field_head);
	session->header.field_head = NULL;

	free(session->body);
	session->body = NULL;

	session->readlen = session->bodylen = 0;
	session->headerlen = 0;

	session->progress = SESSION_PROCESS_READ_HEADER;

	return 0;
}

static int parse_header(SessionPrivate session)
{
	if (http_request_header_parse(&session->header) == -1)
		return -1;

	session->bodylen = parse_body_len(&session->header);
	if (session->bodylen == -1) {
		http_free_field_list(session->header.field_head);
		return -1;
	}
	
	return session->bodylen;
}

static void session_cleanup(SessionPrivate session)
{
	if (session->body) {
		free(session->body);
		session->body = NULL;
	}

	if (session->header.field_head) {
		http_free_field_list(session->header.field_head);
		session->header.field_head = NULL;
	}

	event_handler_del(session->server->handler, session->object);
	close(event_object_get_fd(session->object));
	if (session->server->close_callback)
		session->server->close_callback((Session) session);
	session_destroy(session);
}

static void handle_client(EventObject object)
{
	SessionPrivate session = event_object_get_arg(object);
	int retval;

	switch(session->progress) {
	case SESSION_PROCESS_READ_HEADER:
		retval = read_header(session);
		if (retval == -1)	goto SESSION_CLEANUP;
		if (retval == 0)	break;

		session->progress++;

	case SESSION_PROCESS_PARSE_HEADER:
		if (parse_header(session) == -1)
			goto SESSION_CLEANUP;

		if (session->bodylen > 0) {
			session->body = malloc(session->bodylen);

			if (session->body == NULL)
				goto SESSION_CLEANUP;
		} else {
			session->progress++;
		}

		session->progress++;
		if (session->progress == SESSION_PROCESS_DONE)
			goto SESSION_PROCESS_DONE;

	case SESSION_PROCESS_READ_BODY:
		retval = read_body(session);
		if (retval == -1)
			goto SESSION_CLEANUP;

		if (retval == 0)
			break;

		session->progress++;

	SESSION_PROCESS_DONE: case SESSION_PROCESS_DONE:
		if (session->server->open_callback == NULL)
			goto SESSION_CLEANUP;

		session->server->open_callback((Session) session);

		session->progress++;

	case SESSION_PROCESS_REARMING: {
		struct http_header_field *field = http_find_field(
			&session->header, "Connection"
		);

		if ( !field || (field && strcmp(field->value, "keep-alive")) )
			goto SESSION_CLEANUP;

		session_rearm(session);
	}	break;
	}

	return ;

SESSION_CLEANUP: session_cleanup(session);
}

static void accept_client(EventObject arg)
{
	WebServer server = event_object_get_arg(arg);
	EventHandler handler = server->handler;

	int listen_fd = event_object_get_fd(server->object);

	int clnt_fd = accept(listen_fd, NULL, NULL);
	if (clnt_fd == -1)
		goto JUST_RETURN;

	if (fcntl_set_nonblocking(clnt_fd) == -1)
		goto CLOSE_FD;

	SessionPrivate session = session_create(
		clnt_fd, server->ctx, handle_client
	);
	if (session == NULL)
		goto CLOSE_FD;

	if (server->ctx) {
		while (true) {
			int ret = SSL_accept(session->ssl);
			if (ret == 1)
				break;

			ret = SSL_get_error(session->ssl, ret);
			if (ret == SSL_ERROR_WANT_READ 
			 || ret == SSL_ERROR_WANT_WRITE)
				continue;

			char buffer[256];
			printf("%s\n", ERR_error_string(ret, buffer));

			goto DESTROY_SESSION;
		}
	}

	session->server = server;
	if (event_handler_add(server->handler, session->object) == -1)
		goto DESTROY_SESSION;

	return ;

DESTROY_SESSION:session_destroy(session);
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
	WebServer server = malloc(sizeof(struct web_server));
	if (server == NULL)
		goto RETURN_NULL;

	if (config == NULL)
		server->config = &(struct web_server_config)
				  WEB_SERVER_DEFAULT_CONFIG;
	else
		server->config = config;

	if (server->config->use_ssl) {
 		if (web_server_init_ssl(server) == -1)
			goto FREE_SERVER;
	} else {
		server->ctx = NULL;
	}

	if (config->hostname == NULL)
		config->hostname = get_hostname(AF_INET);

	int fd = make_listener(config->hostname, config->service, 15, true);
	if (fd == -1)
		goto FREE_SSL;

	server->handler = event_handler_create();
	if (server->handler == NULL)
		goto CLOSE_FD;

	server->object = event_object_create(
		fd, true, server, accept_client
	);
	if (server->object == NULL)
		goto DESTROY_HANDLER;

	server->open_callback = NULL;
	server->close_callback = NULL;

	server->is_running = false;

	return server;

DESTROY_HANDLER:event_handler_destroy(server->handler);
CLOSE_FD:	close(fd);
FREE_SSL:	if (server->ctx)
			SSL_CTX_free(server->ctx);
FREE_SERVER:	free(server);
RETURN_NULL:	return NULL;
}

void web_server_destroy(WebServer server)
{
	if (server->ctx)
		SSL_CTX_free(server->ctx);

	int fd = event_object_get_fd(server->object);
	close(fd);

	event_object_destroy(server->object);
	event_handler_destroy(server->handler);

	free(server);
}

int web_server_start(WebServer server)
{
	if (event_handler_start(server->handler) == -1)
		return -1;

	if (event_handler_add(server->handler, server->object) == -1) {
		event_handler_stop(server->handler);
		return -1;
	}

	server->is_running = true;

	return 0;
}

void web_server_register_handler(
		WebServer server,
		WebServerHandler open, WebServerHandler close
) {
	server->open_callback = open;
	server->close_callback = close;
}

void web_server_stop(WebServer server)
{
	event_handler_del(server->handler, server->object);
	event_handler_stop(server->handler);

	server->is_running = false;
}

WebServerConfig web_server_get_config(WebServer server)
{
	return server->config;
}
