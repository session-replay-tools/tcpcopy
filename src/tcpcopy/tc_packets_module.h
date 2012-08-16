#ifndef __TC_PACKETS_MODULE_H__
#define __TC_PACKETS_MODULE_H__

#include <xcopy.h>
#include <tcpcopy.h>

typedef struct {
    uint64_t packets;
    uint64_t valid_packets;
} tc_packets_status_t;


int tc_packets_init(tc_event_loop_t *event_loop);

#endif /* __TC_PACKETS_MODULE_H__ */
