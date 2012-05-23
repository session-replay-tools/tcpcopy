#ifndef  _TCPCOPY_NL_H_INC
#define  _TCPCOPY_NL_H_INC

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv4/ip_queue.h>

	int nl_init(int ,int);
	void nl_set_mode(int sock,uint8_t mode,size_t range);
	ssize_t nl_recv(int ,void *,size_t);
	void *nl_payload(void *);

#ifdef __cplusplus
}
#endif

#endif   /* ----- #ifndef _TCPCOPY_NL_H_INC----- */

