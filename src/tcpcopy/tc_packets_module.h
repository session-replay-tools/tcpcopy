#ifndef __TC_PACKETS_MODULE_H__
#define __TC_PACKETS_MODULE_H__

#include <xcopy.h>
#include <tcpcopy.h>

int tc_packets_init(tc_event_loop_t *event_loop);
#if (TCPCOPY_OFFLINE)
int tc_offline_init(tc_event_loop_t *event_loop, char *pcap_file);
#endif

#endif /* __TC_PACKETS_MODULE_H__ */
