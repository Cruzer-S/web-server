#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <netdb.h>
#include <net/if.h>

#include <unistd.h>

#include "Cruzer-S/net-util/net-util.h"

#include "web_server.h"
#include "web_server_util.h"

#define msg(...) log(logger, INFO, __VA_ARGS__)
#define crt(...) log(logger, PCRTC, __VA_ARGS__), exit(EXIT_FAILURE)
#define wrn(...) log(logger, WARN, __VA_ARGS__)

Logger logger;

static char *get_hostname(void)
{
	char *hostname;

	struct list *address = get_interface_address(
		AF_INET, IFF_UP, IFF_LOOPBACK
	);

	if (LIST_IS_EMPTY(address)) {
		wrn("failed to get interface address");
		return NULL;
	}

	LIST_FOREACH_ENTRY(address, addr, struct address_data_node, list) {
		hostname = get_host_from_address(
			&addr->address, NI_NUMERICHOST
		);

		if (hostname != NULL)
			break;
	}

	free_interface_address(address);

	return hostname;
}

static void request_handler(WebServer server, struct request_data *data)
{
	struct http_request_header *header = data->header;
	char *body = data->body;
	size_t bodylen = data->bodylen;
	int clnt_fd = data->fd;
	char *file;

	switch (http_get_method(header))
	{
	case HTTP_REQUEST_GET:
		msg("client request(%s): %s (ID: %d)",
      			"GET", header->url, clnt_fd);
		if ( !strcmp(header->url, "/") )
			file = "index.html";
		else
			file = header->url + 1;

		ws_send_file(server, clnt_fd, file);

		break;

	default:
		break;
	}
}

int main(int argc, char *argv[])
{
	char *hostname;
	const char *service = "443";
	const int backlog = 15;

	WebServer server;
	struct web_server_config config;
	int serv_fd;

	logger = logger_create();
	if (logger == NULL)
		exit(EXIT_FAILURE);

	logger_use_default_form(logger);
	net_util_set_logger(logger);
	web_server_set_logger(logger);

	hostname = get_hostname();
	if (hostname == NULL)
		crt("failed to get_hostname()");

	serv_fd = make_listener(hostname, (char *) service, backlog, true);
	if (serv_fd == -1)
		crt("failed to server_create()");

	config = (struct web_server_config) {
		.server_name = "mythos web server",
		.basedir = "resources"
	};

	server = web_server_create(serv_fd, &config);
	if (server == NULL)
		crt("failed to web_server_create()");

	web_server_register_handler(server, request_handler);

	if (web_server_start(server) == -1)
		crt("failed to web_server_start()");

	msg("server running at %s:%s (%d)\n", hostname, service, backlog);

	while (true)
		sleep(1);

	web_server_stop(server);
	web_server_destroy(server);

	close(serv_fd);

	logger_destroy(logger);

	return 0;
}
