#include "web_server.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <unistd.h>

#include <sys/socket.h>

#include "Cruzer-S/event-handler/event-handler.h"
#include "Cruzer-S/net-util/net-util.h"
#include "Cruzer-S/logger/logger.h"
#include "Cruzer-S/http/http.h"

static Logger logger = NULL;

#define MAKE_ARG(S) (& (struct request_data) { 				\
	.fd = (S)->fd,							\
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
	int listen_fd;
	EventHandler handler;

	WebServerHandler callback;

	WebServerConfig config;
};

typedef struct session {
	WebServer server;

	int fd;

	struct http_request_header header;
	size_t headerlen;

	char *body;
	size_t bodylen;
	size_t readlen;

	enum session_process progress;
} *Session;

void web_server_set_logger(Logger logg)
{
	logger = logg;
}

static Session session_create(int fd, WebServer server)
{
	Session session = malloc(sizeof(struct session));
	if (session == NULL)
		goto RETURN_NULL;

	session->fd = fd;
	session->server = server;

	session->body = NULL;
	session->headerlen = session->bodylen = 0;
	
	return session;

FREE_DATA:	free(session);
RETURN_NULL:	return NULL;
}

static void session_close(Session session)
{
	int fd = session->fd;

	event_handler_del(session->server->handler, session->fd);
	if (session->body != NULL) free(session->body);
	free(session);

	close(fd);
}

static int read_header(Session session)
{
	char *buffer = session->header.buffer;
	int fd = session->fd;

	while (true) {
		ssize_t readlen = recv(fd, buffer + session->headerlen, 1, 0);
		if (readlen == -1) {
			if (errno == EAGAIN)
				return 0;
			
			msg("client disconnected (ID: %d)", fd);

			return -1;
		}

		session->headerlen += readlen;
		session->header.buffer[session->headerlen] = '\0';

		int hlen = session->headerlen;
		if (strstr(&buffer[OVER_ZERO(hlen - 4)], "\r\n\r\n"))
			return hlen;

		if (hlen == HTTP_HEADER_MAX_SIZE) {
			err("header is too large! (ID: %d)", session->fd);
			return -1;
		}
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

static int read_body(Session session)
{
	char *buffer = session->body;
	int fd = session->fd;

	while (true) {
		ssize_t readlen = recv(fd, &buffer[session->readlen],
				       session->bodylen - session->readlen, 0);
		if (readlen == -1) {
			if (errno == EAGAIN)
				return 0;
			
			msg("client disconnected (ID: %d)", fd);

			return -1;
		}

		session->readlen += readlen;
		if (session->readlen == session->bodylen)
			return session->readlen;
	}

	return -1; // never reach
}

int session_rearm(Session session)
{
	free(session->body); session->body = NULL;
	session->readlen = session->bodylen = 0;

	session->progress = SESSION_PROCESS_READ_BODY;

	return 0;
}

static int parse_header(Session session)
{
	if (http_request_header_parse(&session->header) == -1)
		return -1;

	session->bodylen = parse_body_len(&session->header);
	if (session->bodylen == -1)
		return -1;
	
	return session->bodylen;
}

static void handle_client(int fd, void *ptr)
{
	Session session = ptr;
	int retval;

	switch(session->progress) {
	case SESSION_PROCESS_READ_HEADER:
		retval = read_header(session);
		if (retval == -1)	goto CLOSE_SESSION;
		if (retval == 0)	break;

		session->progress++;

	case SESSION_PROCESS_PARSE_HEADER:
		if (parse_header(session) == -1)
			goto CLOSE_SESSION;

		if (session->bodylen > 0) {
			session->body = malloc(session->bodylen);

			if (session->body == NULL)
				goto CLOSE_SESSION;
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
		if (session->server->callback == NULL) {
			err("callback does not registered (ID: %d)",
       			    session->fd);
			goto FREE_BODY;
		}

		session->server->callback(session->server, MAKE_ARG(session));

		session->progress++;

	case SESSION_PROCESS_REARMING: {
		struct http_header_field *field = http_find_field(
			&session->header, "Connection"
		);

		if (field && strcmp(field->value, "keep-alive"))
			goto FREE_BODY;

		session_rearm(session);
	}	break;
	}

	return ;

FREE_BODY:	free(session->body); session->body = NULL;
CLOSE_SESSION:	session_close(session);
}

static void accept_client(int __, void *arg)
{
	WebServer server = arg;
	EventHandler handler = server->handler;

	int listen_fd = server->listen_fd;

	int clnt_fd = accept(listen_fd, NULL, NULL);
	if (clnt_fd == -1)
		goto JUST_RETURN;

	if (fcntl_set_nonblocking(clnt_fd) == -1) {
		goto CLOSE_CLIENT;
	}

	Session session = session_create(clnt_fd, server);
	if (session == NULL)
		goto CLOSE_CLIENT;

	if (event_handler_add(handler, true, clnt_fd, session, handle_client))
		goto CLOSE_SESSION;

	session->body = NULL;
	session->headerlen = session->bodylen = 0;
	session->progress = SESSION_PROCESS_READ_HEADER;

	msg("client accept (ID: %d)", clnt_fd);

	return ;

CLOSE_SESSION:	session_close(session);
CLOSE_CLIENT:	close(clnt_fd);
JUST_RETURN:	return;
}

WebServer web_server_create(int serv_fd, WebServerConfig config)
{
	WebServer server = malloc(sizeof(struct web_server));
	if (server == NULL)
		goto RETURN_NULL;

	EventHandler handler = event_handler_create();
	if (handler == NULL)
		goto FREE_SERVER;

	if (event_handler_add(handler, true, serv_fd, server, accept_client))
		goto FREE_SERVER;

	server->listen_fd = serv_fd;
	server->handler = handler;

	server->callback = NULL;
	server->config = config;

	return server;

FREE_SERVER:	free(server);
RETURN_NULL:	return NULL;
}

void web_server_destroy(WebServer server)
{
	event_handler_del(server->handler, server->listen_fd);
	event_handler_destroy(server->handler);

	free(server);
}

int web_server_start(WebServer server)
{
	if (event_handler_start(server->handler) == -1)
		return -1;

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
