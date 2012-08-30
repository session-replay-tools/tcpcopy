#ifndef  _MANAGER_H_INC
#define  _MANAGER_H_INC

#include <xcopy.h>
#include <tcpcopy.h>

typedef struct {
    uint32_t ip;
    uint32_t port;
    int      sock;
} address_node_t;

int address_find_sock(uint16_t local_port);
int address_close_sock();

int tcp_copy_init(tc_event_loop_t *event_loop);
void tcp_copy_over(const int sig);
void tcp_copy_release_resources();

#endif   /* ----- #ifndef _MANAGER_H_INC ----- */

