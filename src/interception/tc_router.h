#ifndef  TC_ROUTER_INCLUDED
#define  TC_ROUTER_INCLUDED

#include <xcopy.h> 

typedef struct route_item_s {
    uint16_t key;
    uint16_t fd;
}route_item_t;

typedef struct route_slot_s {
    uint32_t     write_index;
    route_item_t items[ROUTE_ARRAY_SIZE];
}route_slot_t;


typedef struct route_table_s {
    route_item_t cache[ROUTE_SLOTS];
    route_slot_t slots[ROUTE_SLOTS];
}route_table_t;

int router_init();

void router_update(int main_router_fd, tc_ip_header_t *ip_header);
void router_add(uint32_t, uint16_t, int);
void router_destroy();

#endif /* TC_ROUTER_INCLUDED */

