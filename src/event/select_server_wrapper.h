#ifndef __SELECT_SERVER_WRAPPER_H__
#define __SELECT_SERVER_WRAPPER_H__

#include <xcopy.h>

int select_server_create_fake(tc_event_loop_t *loop);
int select_server_destroy_fake(tc_event_loop_t *loop); 
int select_server_add_wrapper(tc_event_loop_t *loop, tc_event_t *efd,
        int events);
int select_server_del_wrapper(tc_event_loop_t *loop, tc_event_t *efd,
        int events);
int select_server_run_wrapper(tc_event_loop_t *loop, long timeout);

#endif
