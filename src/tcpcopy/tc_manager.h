#ifndef  _MANAGER_H_INC
#define  _MANAGER_H_INC

#include <xcopy.h>
#include <tcpcopy.h>

int  address_find_sock(uint32_t local_ip, uint16_t local_port);
void address_release();

int  tcp_copy_init(tc_event_loop_t *event_loop);
void tcp_copy_over(const int sig);
void tcp_copy_release_resources();

#endif   /* ----- #ifndef _MANAGER_H_INC ----- */

