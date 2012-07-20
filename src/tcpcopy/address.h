#ifndef  _ADDRESS_H_INC
#define  _ADDRESS_H_INC

#include "../core/xcopy.h"
#include "../event/net_event.h"

typedef struct address_node_s{
    uint32_t ip;
    uint32_t port;
    int      sock;
}address_node_t;

int address_add_msg_conn(net_event_loop_t *event_loop, uint16_t local_port,
        uint32_t dst_ip, uint16_t dst_port);
int address_find_sock(uint16_t local_port);
int address_close_sock();

#endif   /* ----- #ifndef _ADDRESS_H_INC ----- */

