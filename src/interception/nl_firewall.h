#ifndef  _NL_FIREWALL_H_INC
#define  _NL_FIREWALL_H_INC

#include "../core/xcopy.h"

    int nl_firewall_init();
    struct iphdr *nl_firewall_recv(int sock, unsigned long *packet_id);

#endif   /* ----- #ifndef _NL_FIREWALL_H_INC  ----- */

