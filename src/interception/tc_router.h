#ifndef  TC_ROUTER_INCLUDED
#define  TC_ROUTER_INCLUDED

#include <xcopy.h> 

#if (INTERCEPT_COMBINED)
typedef struct aggregation_s{
    time_t         access_time;
    unsigned char *cur_write;
    uint16_t       num;
    unsigned char  aggr_resp[COMB_LENGTH];
}aggregation_t;
#endif

void router_init(size_t size, int timeout);
void route_delete_obsolete(time_t cur_time);

#if (INTERCEPT_COMBINED)
void 
send_buffered_packets(time_t cur_time);
#endif

#if (INTERCEPT_THREAD)
void router_update(int main_router_fd, tc_ip_header_t *ip_header, int len);
#else
void router_update(int main_router_fd, tc_ip_header_t *ip_header);
#endif

void router_add(uint32_t, uint16_t, int);
void router_del(uint32_t, uint16_t);
void router_destroy();

#endif /* TC_ROUTER_INCLUDED */

