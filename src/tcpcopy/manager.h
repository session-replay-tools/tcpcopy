#ifndef  _MANAGER_H_INC
#define  _MANAGER_H_INC

#include "../core/xcopy.h"
#include "../event/net_event.h"

int tcp_copy_init(net_event_loop_t *event_loop);
void tcp_copy_over(const int sig);
void tcp_copy_exit();

#endif   /* ----- #ifndef _MANAGER_H_INC ----- */

