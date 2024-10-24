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

static void request_handler(Session session)
{
	struct http_request_header *header = &session->header;
	char *body = session->body;
	size_t bodylen = session->bodylen;
	char *file;

	info("client %d request (%s): %s",
      	      session->id, header->method, header->url);

	switch (http_get_method(header))
	{
	case HTTP_REQUEST_GET:
		if ( !strcmp(header->url, "/") )
			file = "index.html";
		else if ( !strcmp(header->url, "/favicon.ico") )
			file = "favicon.png";
		else
			file = header->url + 1;

		if (ws_send_file(session, file) == -1)
			warn("failed to send file: %s (ID: %d)", 
			      file, session->id);

		break;

	default:
		break;
	}
}

static void close_handler(Session session)
{
	info("client %d closed", session->id);
}

int main(int argc, char *argv[])
{
	char *hostname;
	char *service = "443";

	WebServer server;
	WebServerConfig config;

	if ( !logger_initialize() )
		perror("failed to logger_initialize(): ");

	if (signal(SIGUSR1, signal_handler) == SIG_ERR)
		crtc("failed to signal()");

	hostname = get_hostname(AF_INET);
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

	web_server_register_handler(server, request_handler, close_handler);

	if (web_server_start(server) == -1)
		crtc("failed to web_server_start()");

	info("server running at %s:%s", hostname, service);

	for (run_server = true; run_server; )
		sleep(1);

	info("stop server", hostname, service);

	web_server_stop(server);
	web_server_destroy(server);

	info("cleanup done.", hostname, service);

	logger_destroy();

	return 0;
}
