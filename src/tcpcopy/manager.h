#ifndef  _MANAGER_H_INC
#define  _MANAGER_H_INC

#include <xcopy.h>
#include <tcpcopy.h>

extern tc_event_loop_t event_loop;

int tcp_copy_init(tc_event_loop_t *event_loop);
void tcp_copy_over(const int sig);
void tcp_copy_exit();

#endif   /* ----- #ifndef _MANAGER_H_INC ----- */

