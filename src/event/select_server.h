#ifndef  _TCPCOPY_SELECT_SERVER_H_INC
#define  _TCPCOPY_SELECT_SERVER_H_INC

#include "net_event.h"

typedef void (*select_server_func)(int fd);

void select_server_set_callback(select_server_func func);
void select_server_add(int);
void select_server_del(int);
void select_server_run();
void select_server_run2(net_event_loop_t *loop);

#endif   /* ----- #ifndef _TCPCOPY_SELECT_SERVER_H_INC  ----- */

