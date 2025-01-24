#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

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

static bool run_server = false;

void signal_handler(int signo)
{
	run_server = false;
}

static void open_handler(Session session)
{
	info("client %d connected.", session->fd);
}

static void request_handler(Session session)
{
	struct http_request_header *header = &session->header;
	char *body = session->body;
	char *file;

	info("client %d request (%s): %s",
      	      session->fd, header->method, header->url);

	switch (http_get_method(header))
	{
	case HTTP_REQUEST_GET:
		if ( !strcmp(header->url, "/") )
			file = "index.html";
		else if ( !strcmp(header->url, "/favicon.ico") )
			file = "favicon.png";
		else
			file = header->url + 1;

		ws_render(session, HTTP_STATUS_CODE_OK, file);

		break;

	default:
		break;
	}
}

static void close_handler(Session session)
{
	info("client %d closed", session->fd);
}

static bool init_config(WebServerConfig config, int argc, char **argv)
{
	char *hostname;

	if (argc != 6)
		return false;

	if ( !strcmp(argv[1], "null") || !strcmp(argv[1], "NULL") ) {
		hostname = get_hostname(AF_INET);

		if (hostname == NULL)
			return false;
	} else {
		hostname = argv[1];
	}

	config->hostname = hostname;
	config->service = argv[2];
	config->basedir = argv[3];
	config->cert_key = argv[4];
	config->priv_key = argv[5];

	config->use_ssl = true;

	config->server_name = "mythos web server";

	config->nthread = 4;

	return true;
}

int main(int argc, char *argv[])
{
	struct web_server_config config;
	WebServer server;

	if ( !logger_initialize() )
		perror("failed to logger_initialize(): ");

	if (signal(SIGUSR1, signal_handler) == SIG_ERR)
		crtc("failed to signal()");

	if ( !init_config(&config, argc, argv) )
		crtc("failed to init_config()");
	
	server = web_server_create(&config);
	if (server == NULL)
		crtc("failed to web_server_create()");

	web_server_register_handler(
		server, open_handler, request_handler, close_handler
	);

	if (web_server_start(server) == -1)
		crtc("failed to web_server_start()");

	info("server running at %s:%s", config.hostname, config.service);

	for (run_server = true; run_server; )
		sleep(1);

	info("stop server");

	web_server_stop(server);
	web_server_destroy(server);

	info("cleanup done.");

	logger_destroy();

	return 0;
}
