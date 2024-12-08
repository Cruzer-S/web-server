#ifndef WEB_SERVER_UTIL_H__
#define WEB_SERVER_UTIL_H__

#include "web_server.h"

int ws_render(Session , enum http_status_code , const char *filename);

enum web_server_error ws_get_session_error(Session session);

#endif
