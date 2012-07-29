#ifndef  _TCPCOPY_SELECT_SERVER_H_INC
#define  _TCPCOPY_SELECT_SERVER_H_INC

#include "../core/xcopy.h"

typedef void (*select_server_func)(int fd);
typedef void (*select_server_offline_func)(int first);

void select_server_set_callback(select_server_func func);
#if (TCPCOPY_OFFLINE)
void select_offline_set_callback(select_server_offline_func func);
#endif
void select_server_add(int);
void select_server_del(int);
void select_server_run();
void select_server_client_run(tc_event_loop_t *loop);

#endif   /* ----- #ifndef _TCPCOPY_SELECT_SERVER_H_INC  ----- */

