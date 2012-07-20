#ifndef __SELECT_SERVER_WRAPPER_H__
#define __SELECT_SERVER_WRAPPER_H__

#include "net_event.h"

int select_server_create_fake(net_event_loop_t *loop);
int select_server_destroy_fake(net_event_loop_t *loop); 
int select_server_add_wrapper(net_event_loop_t *loop, int fd, int events);
int select_server_del_wrapper(net_event_loop_t *loop, int fd, int events);
int select_server_run_wrapper(net_event_loop_t *loop);

#endif
