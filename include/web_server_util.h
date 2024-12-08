#ifndef WEB_SERVER_UTIL_H__
#define WEB_SERVER_UTIL_H__

#include "web_server.h"

#include "Cruzer-S/http/http.h"
#include "Cruzer-S/cjson/cjson.h"

int ws_render(Session , enum http_status_code , const char *filename);
int ws_render_template(Session , enum http_status_code ,
		       const char *template, struct cjson_object *);

enum web_server_error ws_get_session_error(Session session);

#endif
