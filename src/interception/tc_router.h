#ifndef  TC_ROUTER_INCLUDED
#define  TC_ROUTER_INCLUDED

#include <xcopy.h> 

typedef struct route_item_s {
#if (INTERCEPT_MILLION_SUPPORT)
    uint64_t key;
#else
    uint16_t key;
#endif
    uint16_t fd;
    time_t   timestamp;
}route_item_t;

typedef struct route_slot_s {
    uint32_t     num:6;
    uint32_t     total_visit:26;
    route_item_t items[ROUTE_ARRAY_SIZE];
}route_slot_t;


typedef struct route_table_s {
    uint64_t     slot_full_cnt;
    uint64_t     hit;
    uint64_t     missed;
    uint64_t     lost;
    uint64_t     extra_compared;
    uint64_t     searched;
    uint64_t     total_sessions;
    route_item_t cache[ROUTE_SLOTS];
    route_slot_t slots[ROUTE_SLOTS];
}route_table_t;

int router_init();

void router_add(int, uint32_t, uint16_t, uint32_t, uint16_t, int);
void router_update(bool old, tc_ip_header_t *ip_header);
void router_stat();
void router_destroy();

#endif /* TC_ROUTER_INCLUDED */

