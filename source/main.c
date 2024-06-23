#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <threads.h>

#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <net/if.h>
#include <ifaddrs.h>

#include "Cruzer-S/logger/logger.h"
#include "Cruzer-S/list/list.h"
#include "Cruzer-S/net-util/net-util.h"

#define SERVER_LISTEN_BACKLOG 15

#define LOGGER_LEVEL_INF 1
#define LOGGER_LEVEL_CRT 2
#define LOGGER_LEVEL_ERR 3

static Logger create_logger(void)
{
	Logger logger = logger_create();
	bool retval;

	retval = logger_define_level(
		logger, LOGGER_LEVEL_CRT, "critical", stderr
	);
	if ( !retval ) return NULL;

	retval = logger_set_format(
		logger, LOGGER_LEVEL_CRT, "[%d %t][%n:%f:%l] %s: %e\n"
	);
	if ( !retval) return NULL;

	retval = logger_define_level(
		logger, LOGGER_LEVEL_ERR, "error", stderr 
	);
	if ( !retval ) return NULL;

	retval = logger_set_format(
		logger, LOGGER_LEVEL_ERR, "[%d %t][%n:%f:%l] %s: %e\n"
	);

	retval = logger_define_level(
		logger, LOGGER_LEVEL_INF, "info", stdout
	);
	if ( !retval ) return NULL;

	retval = logger_set_format(
		logger, LOGGER_LEVEL_INF, "[%d %t][%n:%f:%l] %s\n"
	);

	return logger;
}

static char *get_ipv6_address_interface(Logger logg)
{
	char *host = NULL;

	struct list *address = get_interface_address(
		AF_INET6, IFF_UP, IFF_LOOPBACK
	);
	if (address == NULL) {
		log(logg, ERR, "%s", net_util_error());
		goto RETURN_HOST;
	}

	if (LIST_IS_EMPTY(address)) {
		log(logg, ERR, "failed to find address");
		goto FREE_INTERFACE_ADDRESS;
	}

	struct address_data_node *node = LIST_FIRST_ENTRY(
		address, struct address_data_node, list
	);

	host = get_host_from_address(
		&node->address, NI_NUMERICHOST
	);
	if (host == NULL)
		log(logg, ERR, "%s", net_util_error());

FREE_INTERFACE_ADDRESS:
	free_interface_address(address);
RETURN_HOST:
	return host;
}

int main(int argc, char *argv[])
{
	int server_fd;

	Logger logg = create_logger();
	if (logg == NULL) {
		fprintf(stderr, "failed to create logger: %s\n",
	  			strerror(errno));
		goto RETURN_ERROR;
	}	

	if (argc != 3) {
		log(logg, ERR, "usage: %s <host | null> <port>", argv[0]);
		goto RETURN_ERROR;
	}

	if ( !strcmp(argv[1], "null") ) {
		argv[1] = get_ipv6_address_interface(logg);

		if (argv[1] == NULL)
			goto RETURN_ERROR;
	}
		
	server_fd = server_create(argv[1], argv[2], SERVER_LISTEN_BACKLOG);
	if (server_fd == -1) {
		log(logg, ERR, "%s", net_util_error());
		goto DESTROY_LOGGER;
	}
	
	log(logg, INF, "server open at %s:%s", argv[1], argv[2]);

	// do something.

	log(logg, INF, "server closed.");

	close(server_fd);

	logger_destroy(logg);

	return 0;

SERVER_DESTROY: close(server_fd);
DESTROY_LOGGER:	logger_destroy(logg);
RETURN_ERROR:	return -1;
}
