#include "wserver.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <unistd.h>

#include <sys/socket.h>

#include "Cruzer-S/net-util/net-util.h"
#include "Cruzer-S/list/list.h"
#include "Cruzer-S/ring-buffer/ring_buffer.h"
#include "Cruzer-S/event-listener/event_listener.h"
#include "Cruzer-S/logger/logger.h"
#include "Cruzer-S/http/http.h"

#define BOUND(X) (((X) < 0) ? 0 : (X))

#include <sys/stat.h>

static long int file_size(char *filename)
{
	struct stat st;
	long int size;

	if (stat(filename, &st) == -1)
		return -1;

	return size = st.st_size;
}

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
	int fd;

	EventListener listener;
	EventData event;

	char header[HTTP_HEADER_MAX_SIZE + 1];
	size_t headerlen;

	RingBuffer body;

	bool is_get_header;

	struct list list;
} *ClientData;

void wserver_set_logger(Logger logg)
{
	logger = logg;
}

static void client_data_destroy(ClientData data)
{
	list_del(&data->list);

	ring_buffer_destroy(data->body);
	free(data->event);

	free(data);
}

static void disconnect_client(ClientData data)
{
	int fd = data->fd;

	event_listener_del(data->listener, data->fd);

	client_data_destroy(data);

	close(fd);
}

static int read_header(ClientData data)
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

			if (ring_buffer_enqueue(data->body,
			   			endptr, remain) == -1)
			{
				err("failed to enqueue to body");
				return -1;
			}

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

static int handle_request(ClientData data)
{
	struct http_request_header *request;

	request = http_request_header_create(data->header);
	if (request == NULL)
		return -1;

	switch (http_get_method(request))
	{
	case HTTP_REQUEST_GET:
		if (strstr(request->url, "/"))
			send_file(data->fd, "resources/index.html");
		break;

	case HTTP_REQUEST_UNKNOWN:
		err("invalid http method: %s (ID: %d)",
      		    request->method, data->fd);
		break;

	default:
		// Implemented Not Yet.
		return -1;
	}

	return 0;
}

static void handle_client(void *arg)
{
	ClientData data = arg;

	if ( !data->is_get_header ) {
		if (read_header(data) == -1)
			disconnect_client(data);	
	}
	
	if (handle_request(data) == -1)
		disconnect_client(data);
}

static ClientData client_data_create(
		int clnt_fd, EventListener listener, struct list *list_head
) {
	ClientData clnt_data = malloc(sizeof(struct client_data));
	if (clnt_data == NULL)
		goto RETURN_NULL;

	clnt_data->body = ring_buffer_create(BUFSIZ);
	if (clnt_data->body == NULL) 
		goto FREE_DATA;

	clnt_data->event = malloc(sizeof(struct event_data));
	if (clnt_data->event == NULL)
		goto FREE_BODY;

	clnt_data->fd = clnt_fd;
	clnt_data->listener = listener;

	clnt_data->event->data = clnt_data;
	clnt_data->event->callback = handle_client;

	list_add(list_head, &clnt_data->list);

	return clnt_data;

FREE_BODY:	ring_buffer_destroy(clnt_data->body);
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
		goto JUST_RETURN;

	if (fcntl_set_nonblocking(clnt_fd) == -1) {
		goto CLOSE_CLIENT;
	}

	ClientData clnt_data = client_data_create(
		clnt_fd, server->listener, &server->client_list
	);

	if (clnt_data == NULL)
		goto CLOSE_CLIENT;

	if (event_listener_add(listener, clnt_fd, clnt_data->event) == -1)
		goto DESTROY_DATA;

	msg("client accept (ID: %d)", clnt_fd);

	return ;

DESTROY_DATA:	client_data_destroy(clnt_data);
CLOSE_CLIENT:	close(clnt_fd);
JUST_RETURN:	return;
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
