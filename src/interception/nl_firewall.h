#ifndef  _TCPCOPY_NL_FIREWALL_H_INC
#define  _TCPCOPY_NL_FIREWALL_H_INC

#ifdef __cplusplus
extern "C"
{
#endif

#include "nl.h"

#define FIREWALL_GROUP  0

	int nl_firewall_init();
	struct iphdr *nl_firewall_recv(int sock, unsigned long *packet_id);

#ifdef __cplusplus
}
#endif
#endif   /* ----- #ifndef _TCPCOPY_NL_FIREWALL_H_INC  ----- */

