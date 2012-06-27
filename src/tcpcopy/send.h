#ifndef  _RAW_SOCKET_SEND_H_INC
#define  _RAW_SOCKET_SEND_H_INC

#include "../core/xcopy.h"

int send_init();
int send_close();
ssize_t send_ip_packet(struct iphdr *ip_header, uint16_t tot_len);

#endif   /* ----- #ifndef _RAW_SOCKET_SEND_H_INC  ----- */

