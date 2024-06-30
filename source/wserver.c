#include "wserver.h"

#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

#include <sys/socket.h>

#include "Cruzer-S/event-listener/event_listener.h"
#include "Cruzer-S/logger/logger.h"

static Logger logger = NULL;

#define msg(...) log(logger, INFO, __VA_ARGS__)
#define err(...) log(logger, ERRN, __VA_ARGS__)

struct wserver {
	EventListener listener;
	int listen_fd;
};

void wserver_set_logger(Logger logg)
{
	logger = logg;
}

static void accept_client(EventListener listener, int listen_fd)
{
	int clnt_fd = accept(listen_fd, NULL, NULL);
	if (clnt_fd == -1)
		return ;

	if (event_listener_add(listener, clnt_fd, NULL) == -1)
		return ;

	msg("client accept (ID: %d)", clnt_fd);
}

static int read_data(EventListener listener, int fd)
{
	char buffer[BUFSIZ];

	while (true) {
		int readlen = recv(fd, buffer, BUFSIZ, 0);
		if (readlen == 0) {
			if (event_listener_del(listener, fd) == -1) {
				err("failed to event_listener_del()");
				return -1;
			}

			close(fd);

			msg("client disconnected (ID: %d)", fd);

			break;
		}

		msg("client %d send data: \n%.*s\n", fd, readlen, buffer);
	}

	return 0;
}

static void event_handler(int fd, void *arg)
{
	WServer server = arg;

	if (server->listen_fd == fd) {
		accept_client(server->listener, server->listen_fd);
		return ;
	}

	read_data(server->listener, fd);
}

WServer wserver_create(int serv_fd)
{
	WServer server = malloc(sizeof(struct wserver));
	if (server == NULL)
		goto RETURN_NULL;

	server->listener = event_listener_create();
	if (server->listener == NULL)
		goto FREE_SERVER;

	server->listen_fd = serv_fd;

	return server;

FREE_SERVER:	free(server);
RETURN_NULL:	return NULL;
}

int wserver_start(WServer server, char *basedir)
{
	event_listener_set_handler(server->listener, event_handler);
	if (event_listener_add(server->listener, server->listen_fd, NULL) == -1)
		return -1;

	if (event_listener_start(server->listener) == -1)
		return -1;

	return 0;
}

void wserver_stop(WServer server)
{
	event_listener_stop(server->listener);
	event_listener_destroy(server->listener);
}
