#ifndef __SELECT_SERVER_WRAPPER_H__
#define __SELECT_SERVER_WRAPPER_H__

#include "../core/xcopy.h"

int select_server_create_fake(cpy_event_loop_t *loop);
int select_server_destroy_fake(cpy_event_loop_t *loop); 
int select_server_add_wrapper(cpy_event_loop_t *loop, cpy_event_t *efd,
        int events);
int select_server_del_wrapper(cpy_event_loop_t *loop, cpy_event_t *efd,
        int events);
int select_server_run_wrapper(cpy_event_loop_t *loop);

#endif
