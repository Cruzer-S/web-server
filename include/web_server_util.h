#ifndef WEB_SERVER_UTIL_H__
#define WEB_SERVER_UTIL_H__

#include "web_server.h"

int ws_send_file(WebServer server, int fd, char *filename);

#endif
