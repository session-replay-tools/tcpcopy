#ifndef  _ROUTER_H_INC
#define  _ROUTER_H_INC

#include "../core/xcopy.h" 

	void router_init();
	void router_update(struct iphdr *ip_header);
	void router_add(uint32_t ,uint16_t, int);
	void router_del(uint32_t ,uint16_t);
	void router_destroy();


#endif   /* ----- #ifndef _ROUTER_H_INC  ----- */

