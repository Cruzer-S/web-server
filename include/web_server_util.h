#ifndef WEB_SERVER_UTIL_H__
#define WEB_SERVER_UTIL_H__

#include "web_server.h"

int ws_send_file(Session session, char *filename);

enum web_server_error ws_get_session_error(Session session);

#endif
