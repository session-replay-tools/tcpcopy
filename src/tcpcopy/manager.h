#ifndef  _MANAGER_H_INC
#define  _MANAGER_H_INC

#include "../core/xcopy.h"
#include "../event/cpy_event.h"

int tcp_copy_init(cpy_event_loop_t *event_loop);
void tcp_copy_over(const int sig);
void tcp_copy_exit();
void dispose_event(int fd);
void dispose_event_wrapper(cpy_event_t *efd);

#endif   /* ----- #ifndef _MANAGER_H_INC ----- */

