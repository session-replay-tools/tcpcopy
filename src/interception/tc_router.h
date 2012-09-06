#ifndef  _ROUTER_H_INC
#define  _ROUTER_H_INC

#include <xcopy.h> 

void router_init(size_t size);
void route_delete_obsolete(time_t cur_time);

#if (MULTI_THREADS)
void router_update(tc_ip_header_t *ip_header, int len);
#else
void router_update(tc_ip_header_t *ip_header);
#endif

void router_add(uint32_t, uint16_t, int);
void router_del(uint32_t, uint16_t);
void router_destroy();

#endif /* _ROUTER_H_INC */

