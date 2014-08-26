#ifndef  TC_MANAGER_INCLUDED
#define  TC_MANAGER_INCLUDED

#include <xcopy.h>
#include <tcpcopy.h>

int  tcp_copy_init(tc_event_loop_t *event_loop);
void tcp_copy_over(const int sig);
void tcp_copy_release_resources(void);

#endif   /* ----- #ifndef TC_MANAGER_INCLUDED ----- */

