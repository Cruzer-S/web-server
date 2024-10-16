#include "web_server.h"

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

#define MAKE_ARG(S) (& (struct request_data) { 				\
	.fd = event_object_get_fd((S)->object),				\
	.header = &(S)->header,						\
	.body = (S)->body,						\
	.bodylen = (S)->bodylen						\
} )

#define OVER_ZERO(X) (((X) < 0) ? 0 : (X))

#define msg(...) log(logger, INFO, __VA_ARGS__)
#define err(...) log(logger, ERRN, __VA_ARGS__)

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

typedef struct _session {
	struct session _;

	WebServer server;

	size_t readlen;

	EventObject object;

	SSL *ssl;

	enum session_process progress;
} *_Session;

static void handle_client(EventObject object);

static _Session session_create(int fd, SSL_CTX *ctx)
{
	_Session session;

	session = malloc(sizeof(struct _session));
	if (session == NULL)
		goto RETURN_NULL;

	session->server = NULL;
	session->_.body = NULL;
	session->_.headerlen = session->_.bodylen = 0;
	session->progress = SESSION_PROCESS_READ_HEADER;


	session->object = event_object_create(
		fd, true, session, handle_client
	);
	if (session->object == NULL)
		goto FREE_SESSION;

	if (ctx) {
		session->ssl = SSL_new(ctx);
		if (session->ssl == NULL)
			goto DESTROY_OBJECT;

		if (SSL_set_fd(session->ssl, fd) != 1)
			goto FREE_SSL;

	} else {
		session->ssl = NULL;
	}

	return session;

FREE_SSL:	SSL_free(session->ssl);
DESTROY_OBJECT:	event_object_destroy(session->object);
FREE_SESSION:	free(session);
RETURN_NULL:	return NULL;
}

static void session_destroy(_Session session)
{
	int fd = event_object_get_fd(session->object);

	if (session->ssl)
		SSL_free(session->ssl);

	event_object_destroy(session->object);

	free(session);
}

int session_write(_Session session, char *buffer, int size)
{
	ssize_t len;

	if (session->ssl) {
		len = SSL_write(session->ssl, buffer, size);

		if (len <= 0)
			return -1;
	} else {
		int fd = event_object_get_fd(session->object);

		len = write(fd, buffer, size);
		if (len == -1)
			return -1;
	}

	return len;
}

int session_read(_Session session, char *buffer, int size)
{
	ssize_t len;

	if (session->ssl) {
		len = SSL_read(session->ssl, buffer, size);

		if (len <= 0) {
			int ret = SSL_get_error(session->ssl, len);
			if (ret == SSL_ERROR_WANT_READ)
				return -1;

			if (ret == SSL_ERROR_ZERO_RETURN)
				return 0;

			return -2;
		}
	} else {
		int fd = event_object_get_fd(session->object);

		len = recv(fd, buffer, size, 0);
		if (len == -1) {
			if (errno == EAGAIN)
				return -1;

			return -2;
		}

		if (len == 0)
			return 0;
	}

	return len;
}

static int read_header(_Session session)
{
	char *buffer = session->_.header.buffer;
	int len;

	while (true) {
		len = session_read(session, buffer + session->_.headerlen, 1);
		if (len == -1)
			return 0;
		if (len == -2)
			return -1;

		session->_.headerlen += len;
		session->_.header.buffer[session->_.headerlen] = '\0';

		int hlen = session->_.headerlen;
		if (strstr(&buffer[OVER_ZERO(hlen - 4)], "\r\n\r\n"))
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

static int read_body(_Session session)
{
	char *buffer = session->_.body;
	int fd = event_object_get_fd(session->object);

	while (true) {
		ssize_t readlen = recv(
			fd, &buffer[session->readlen],
			session->_.bodylen - session->readlen, 0
		);
		if (readlen == -1) {
			if (errno == EAGAIN)
				return 0;

			return -1;
		}

		if (readlen == 0)
			return -1;

		session->readlen += readlen;
		if (session->readlen == session->_.bodylen)
			return session->readlen;
	}

	return -1; // never reach
}

int session_rearm(_Session session)
{
	free(session->_.body); session->_.body = NULL;
	session->readlen = session->_.bodylen = 0;
	session->_.headerlen = 0;

	session->progress = SESSION_PROCESS_READ_HEADER;

	return 0;
}

static int parse_header(_Session session)
{
	if (http_request_header_parse(&session->_.header) == -1)
		return -1;

	session->_.bodylen = parse_body_len(&session->_.header);
	if (session->_.bodylen == -1)
		return -1;
	
	return session->_.bodylen;
}

static void handle_client(EventObject object)
{
	_Session session = event_object_get_arg(object);
	int retval;

	switch(session->progress) {
	case SESSION_PROCESS_READ_HEADER:
		retval = read_header(session);
		if (retval == -1)	goto DELETE_EVENT;
		if (retval == 0)	break;

		session->progress++;

	case SESSION_PROCESS_PARSE_HEADER:
		if (parse_header(session) == -1)
			goto DELETE_EVENT;

		if (session->_.bodylen > 0) {
			session->_.body = malloc(session->_.bodylen);

			if (session->_.body == NULL)
				goto DELETE_EVENT;
		} else {
			session->progress++;
		}

		session->progress++;
		if (session->progress == SESSION_PROCESS_DONE)
			goto SESSION_PROCESS_DONE;

	case SESSION_PROCESS_READ_BODY:
		retval = read_body(session);
		if (retval == -1)
			goto FREE_BODY;

		if (retval == 0)
			break;

		session->progress++;

	SESSION_PROCESS_DONE: case SESSION_PROCESS_DONE:
		if (session->server->callback == NULL)
			goto FREE_BODY;

		session->server->callback(&session->_);

		session->progress++;

	case SESSION_PROCESS_REARMING: {
		struct http_header_field *field = http_find_field(
			&session->_.header, "Connection"
		);

		if ( !field || (field && strcmp(field->value, "keep-alive")) )
			goto FREE_BODY;

		session_rearm(session);
	}	break;
	}

	return ;

FREE_BODY:	free(session->_.body); session->_.body = NULL;
DELETE_EVENT:	event_handler_del(session->server->handler, session->object);
CLOSE_FD:	close(event_object_get_fd(session->object));
DESTROY_SESSION:session_destroy(session);
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

	_Session session = session_create(clnt_fd, server->ctx);
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

	server->config = config;

	if (server->config->use_ssl) {
 		if (web_server_init_ssl(server) == -1)
			goto FREE_SERVER;
	} else {
		server->ctx = NULL;
	}

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

	server->callback = NULL;

	
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

	event_handler_del(server->handler, server->object);
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

	return 0;
}

void web_server_register_handler(WebServer server, WebServerHandler handler)
{
	server->callback = handler;
}

void web_server_stop(WebServer server)
{
	event_handler_stop(server->handler);
}

WebServerConfig web_server_get_config(WebServer server)
{
	return server->config;
}
