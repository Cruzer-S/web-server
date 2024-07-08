#include "web_server.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <unistd.h>

#include <sys/socket.h>

#include "Cruzer-S/net-util/net-util.h"
#include "Cruzer-S/list/list.h"
#include "Cruzer-S/event-listener/event_listener.h"
#include "Cruzer-S/logger/logger.h"
#include "Cruzer-S/http/http.h"

#define BOUND(X) (((X) < 0) ? 0 : (X))

static Logger logger = NULL;

#define msg(...) log(logger, INFO, __VA_ARGS__)
#define err(...) log(logger, ERRN, __VA_ARGS__)

struct web_server {
	EventListener listener;
	int listen_fd;
};

typedef struct session {
	EventListener listener;
	int fd;

	char header[HTTP_HEADER_MAX_SIZE + 1];
	size_t headerlen;

	bool is_get_header;

	struct list list;
} *Session;

void web_server_set_logger(Logger logg)
{
	logger = logg;
}

static Session session_create(int fd, EventListener listener)
{
	Session session = malloc(sizeof(struct session));
	if (session == NULL)
		goto RETURN_NULL;

	session->fd = fd;
	session->listener = listener;

	return session;

FREE_DATA:	free(session);
RETURN_NULL:	return NULL;
}

static void session_close(Session data)
{
	int fd = data->fd;

	event_listener_del(data->listener, data->fd);
	list_del(&data->list);
	free(data);

	close(fd);
}

static int read_header(Session data)
{
	while (true) {
		size_t readlen = recv(
			data->fd, &data->header[data->headerlen],
			HTTP_HEADER_MAX_SIZE - data->headerlen, 0
		);
		if (readlen == 0) {
			if (errno == EAGAIN)
				return 0;
			
			msg("client disconnected (ID: %d)", data->fd);

			return -1;
		}

		char *endptr = strstr(data->header, "\r\n\r\n");
		if (endptr != NULL) {
			size_t total_read = data->headerlen + readlen;
			size_t remain;

			endptr = endptr + 4;
			data->headerlen = endptr - data->header;
			remain = total_read - data->headerlen;

			data->header[data->headerlen] = '\0';

			msg("read header succesffuly! (ID: %d)\n%s",
			    data->fd, data->header);

			return 0;
		}
		
		if (data->headerlen == HTTP_HEADER_MAX_SIZE) {
			err("header is too large! (ID: %d)", data->fd);
			return -1;
		}
				
		data->headerlen += readlen;
	}

	return 0;
}

static void handle_client(int fd, void *ptr)
{
	Session data = ptr;

	if ( !data->is_get_header ) {
		if (read_header(data) == -1)
			session_close(data);
	}
}

static void accept_client(int __, void *arg)
{
	struct web_server *server = arg;
	EventListener listener = server->listener;

	int listen_fd = server->listen_fd;

	int clnt_fd = accept(listen_fd, NULL, NULL);
	if (clnt_fd == -1)
		goto JUST_RETURN;

	if (fcntl_set_nonblocking(clnt_fd) == -1) {
		goto CLOSE_CLIENT;
	}

	Session session = session_create(
		clnt_fd, server->listener
	);

	if (session == NULL)
		goto CLOSE_CLIENT;

	if (event_listener_add(listener, clnt_fd,
			       session, handle_client) == -1)
		goto DESTROY_DATA;

	msg("client accept (ID: %d)", clnt_fd);

	return ;

DESTROY_DATA:	session_close(session);
CLOSE_CLIENT:	close(clnt_fd);
JUST_RETURN:	return;
}

WebServer web_server_create(int serv_fd)
{
	WebServer server = malloc(sizeof(struct web_server));
	if (server == NULL)
		goto RETURN_NULL;

	server->listener = event_listener_create();
	if (server->listener == NULL)
		goto FREE_SERVER;

	server->listen_fd = serv_fd;

	if (event_listener_add(server->listener, server->listen_fd,
			       server, accept_client) == -1)
		goto FREE_SERVER;

	return server;

FREE_SERVER:	free(server);
RETURN_NULL:	return NULL;
}

void web_server_destroy(WebServer server)
{
	event_listener_del(server->listener, server->listen_fd);
	event_listener_destroy(server->listener);

	free(server);
}

int web_server_start(WebServer server)
{
	if (event_listener_start(server->listener) == -1)
		return -1;

	return 0;
}

void web_server_stop(WebServer server)
{
	event_listener_stop(server->listener);

}
