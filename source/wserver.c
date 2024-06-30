#include "wserver.h"

#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

#include <sys/socket.h>

#include "Cruzer-S/list/list.h"
#include "Cruzer-S/ring-buffer/ring_buffer.h"
#include "Cruzer-S/event-listener/event_listener.h"
#include "Cruzer-S/logger/logger.h"

static Logger logger = NULL;

#define msg(...) log(logger, INFO, __VA_ARGS__)
#define err(...) log(logger, ERRN, __VA_ARGS__)

typedef struct event_data {
	void (*callback)(void *);
	void *data;
} *EventData;

struct wserver {
	EventListener listener;
	int listen_fd;

	struct list client_list;
	EventData event;
};

typedef struct client_data {
	EventListener listener;
	int fd;
	RingBuffer buffer;

	struct list list;

	EventData event;
} *ClientData;

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

void wserver_set_logger(Logger logg)
{
	logger = logg;
}

static void handle_client(void *arg)
{
	ClientData data = arg;

	read_data(data->listener, data->fd);
}

static ClientData client_data_create(int clnt_fd, EventListener listener, struct list *list_head)
{
	ClientData clnt_data = malloc(sizeof(struct client_data));
	if (clnt_data == NULL)
		goto RETURN_NULL;

	clnt_data->buffer = ring_buffer_create(BUFSIZ);
	if (clnt_data->buffer == NULL) 
		goto FREE_DATA;

	clnt_data->event = malloc(sizeof(struct event_data));
	if (clnt_data->event == NULL)
		goto FREE_BUFFER;

	clnt_data->fd = clnt_fd;
	clnt_data->listener = listener;

	clnt_data->event->data = clnt_data;
	clnt_data->event->callback = handle_client;

	list_add(list_head, &clnt_data->list);

	return clnt_data;

FREE_BUFFER:	ring_buffer_destroy(clnt_data->buffer);
FREE_DATA:	free(clnt_data);
RETURN_NULL:	return NULL;
}

static void accept_client(void *arg)
{
	struct wserver *server = arg;

	EventListener listener = server->listener;
	int listen_fd = server->listen_fd;

	int clnt_fd = accept(listen_fd, NULL, NULL);
	if (clnt_fd == -1)
		return ;

	ClientData clnt_data = client_data_create(
		clnt_fd, server->listener, &server->client_list
	);

	if (event_listener_add(listener, clnt_fd, clnt_data->event) == -1)
		return ;

	msg("client accept (ID: %d)", clnt_fd);
}

static void event_handler(int fd, void *arg)
{
	((EventData) arg)->callback(((EventData) arg)->data);
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
	list_init_head(&server->client_list);

	return server;

FREE_SERVER:	free(server);
RETURN_NULL:	return NULL;
}

int wserver_start(WServer server, char *basedir)
{
	event_listener_set_handler(server->listener, event_handler);

	server->event = malloc(sizeof(struct event_data));
	if (server->event == NULL)
		return -1;

	server->event->callback = accept_client;
	server->event->data = server;

	if (event_listener_add(server->listener, server->listen_fd, server->event) == -1)
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
