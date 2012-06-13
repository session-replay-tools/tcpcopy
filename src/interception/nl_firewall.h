#ifndef  _NL_FIREWALL_H_INC
#define  _NL_FIREWALL_H_INC

#ifdef __cplusplus
extern "C"
{
#endif

#include "../core/xcopy.h"

	int nl_firewall_init();
	struct iphdr *nl_firewall_recv(int sock, unsigned long *packet_id);

#ifdef __cplusplus
}
#endif

#endif   /* ----- #ifndef _NL_FIREWALL_H_INC  ----- */

