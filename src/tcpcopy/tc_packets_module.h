#ifndef __TC_PACKETS_MODULE_H__
#define __TC_PACKETS_MODULE_H__

#include <xcopy.h>
#include <tcpcopy.h>

typedef struct {
    uint64_t packets;
    uint64_t valid_packets;
} tc_packets_status_t;


void tc_process_raw_socket_packet(tc_event_t *efd);

#endif /* __TC_PACKETS_MODULE_H__ */
