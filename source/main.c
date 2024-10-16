#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <netdb.h>
#include <net/if.h>

#include <unistd.h>

#include "Cruzer-S/logger/logger.h"
#include "Cruzer-S/net-util/net-util.h"

#include "web_server.h"
#include "web_server_util.h"

#define info(...) log(INFO, __VA_ARGS__)
#define crtc(...) log(PCRTC, __VA_ARGS__), exit(EXIT_FAILURE)
#define warn(...) log(WARN, __VA_ARGS__)

static char *get_hostname(void)
{
	char *hostname;

	struct list *address = get_interface_address(
		AF_INET, IFF_UP, IFF_LOOPBACK
	);

	if (LIST_IS_EMPTY(address)) {
		warn("failed to get interface address");
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

static void request_handler(Session session)
{
	struct http_request_header *header = &session->header;
	char *body = session->body;
	size_t bodylen = session->bodylen;
	char *file;

	switch (http_get_method(header))
	{
	case HTTP_REQUEST_GET:
		info("client request(%s): %s (ID: %d)",
      		     "GET", header->url, session->id);
		if ( !strcmp(header->url, "/") )
			file = "index.html";
		else
			file = header->url + 1;

		ws_send_file(session, file);

		break;

	default:
		break;
	}
}

int main(int argc, char *argv[])
{
	char *hostname;
	char *service = "443";

	WebServer server;
	WebServerConfig config;

	if ( !logger_initialize() )
		perror("failed to logger_initialize(): ");

	hostname = get_hostname();
	if (hostname == NULL)
		crtc("failed to get_hostname()");
	
	config = &(struct web_server_config) {
		.hostname = hostname,
		.service = service,

		.server_name = "mythos web server",
		.basedir = "resources",
		.use_ssl = true,
		.cert_key = "certs/fullchain.pem",
		.priv_key = "certs/privkey.pem"
	};

	server = web_server_create(config);
	if (server == NULL)
		crtc("failed to web_server_create()");

	web_server_register_handler(server, request_handler);

	if (web_server_start(server) == -1)
		crtc("failed to web_server_start()");

	info("server running at %s:%s", hostname, service);

	while (true)
		sleep(1);

	web_server_stop(server);
	web_server_destroy(server);

	return 0;
}
