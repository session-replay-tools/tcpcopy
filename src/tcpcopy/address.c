
#include "../core/xcopy.h"
#include "tcpcopy.h"

static address_node_t addr[65536];

/* This is for copying multiple ports */
int
address_add_msg_conn(cpy_event_loop_t *event_loop, uint16_t local_port,
        uint32_t dst_ip, uint16_t dst_port)
{
    cpy_event_t  *msg_socket_event;

    addr[local_port].ip   = dst_ip;
    addr[local_port].port = dst_port;
    addr[local_port].sock = msg_client_init(dst_ip, dst_port);

    msg_socket_event = cpy_event_create(addr[local_port].sock,
                                        dispose_event_wrapper, NULL);
    if (msg_socket_event == NULL) {
        return -1;
    }

    if (cpy_event_add(event_loop, msg_socket_event, CPY_EVENT_READ)
            == CPY_EVENT_ERROR)
    {
        return -1;     
    }

    return 0;
}

/* Find the message socket through local port */
int 
address_find_sock(uint16_t local_port)
{
    if (0 == addr[local_port].sock) {
        log_info(LOG_WARN, "it can't find address socket:%u",
                ntohs(local_port));
        return -1;
    }
    return addr[local_port].sock;
}

/* Close sockets */
int
address_close_sock()
{
    int i;

    for (i = 0; i< 65536; i++) {
        if (0 != addr[i].sock) {
            log_info(LOG_WARN, "it close socket:%d", addr[i].sock);
            close(addr[i].sock);
            addr[i].sock = 0;
        }
    }

    return 0;
}

