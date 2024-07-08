#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <netdb.h>
#include <net/if.h>

#include <unistd.h>

#include "Cruzer-S/net-util/net-util.h"

#include "web_server.h"

#define msg(...) log(logger, INFO, __VA_ARGS__)
#define crt(...) log(logger, PCRTC, __VA_ARGS__), exit(EXIT_FAILURE);
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

int main(int argc, char *argv[])
{
	char *hostname;
	const char *service = "443";
	const int backlog = 15;

	WebServer server;
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

	server = web_server_create(serv_fd);
	if (server == NULL)
		crt("failed to web_server_create()")

	msg("server running at %s:%s (%d)\n", hostname, service, backlog);

	if (web_server_start(server) == -1)
		crt("failed to web_server_start()");

	while (true) sleep(1);

	web_server_stop(server);
	web_server_destroy(server);

	close(serv_fd);

	logger_destroy(logger);

	return 0;
}
