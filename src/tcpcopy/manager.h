#ifndef  _MANAGER_H_INC
#define  _MANAGER_H_INC

#include "../core/xcopy.h"
#include "tcpcopy.h"

int tcp_copy_init(tc_event_loop_t *event_loop);
void tcp_copy_over(const int sig);
void tcp_copy_exit();
void dispose_event(int fd);
void dispose_event_wrapper(tc_event_t *efd);
#if (TCPCOPY_OFFLINE)
void send_packets_from_pcap(int first);
#endif

#endif   /* ----- #ifndef _MANAGER_H_INC ----- */

