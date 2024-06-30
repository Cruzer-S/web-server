#ifndef WSERVER_H__
#define WSERVER_H__

#include "Cruzer-S/logger/logger.h"

typedef struct wserver *WServer;

WServer wserver_create(int serv_fd);
void wserver_destroy(WServer server);

int wserver_start(WServer server, char *basedir);
void wserver_stop(WServer server);

void wserver_set_logger(Logger logger);

#endif
