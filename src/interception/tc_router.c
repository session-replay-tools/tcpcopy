#include <xcopy.h>
#include <intercept.h>

static route_table_t  *table = NULL;

/* initiate router table */
int
router_init()
{
    table = (route_table_t *) malloc(sizeof(route_table_t));

    if (table == NULL) {
        tc_log_info(LOG_ERR, 0, "malloc route table error");
        return TC_ERROR;
    }

    memset(table, 0, sizeof(route_table_t));
    
    return TC_OK;
}

static uint32_t
get_route_key(int old, uint32_t clt_ip, uint16_t clt_port, 
        uint32_t target_ip, uint16_t target_port)
{
    uint32_t value = clt_port;

    value = (value << 16) + clt_ip + clt_port;
    if (!old) {
        value = value + target_ip + (target_port << 24) + 
            (target_port << 8) + target_port;
    }

    return value;
}

static void 
router_update_adjust(route_slot_t *slot, int child) 
{
    int          parent;
    route_item_t tmp;

    if (child < 1) {
        return;
    }

    parent = (child - 1) / 2;
    tmp = slot->items[parent];
    slot->items[parent] = slot->items[child];
    slot->items[child] = tmp;

    return;
}


static void router_add_adjust(route_slot_t *slot, int key, int fd) 
{
    int          i, tail_need_save;
    route_item_t item = {0, 0, 0}, tmp;

    tail_need_save = 0;

    if (slot->num > 0) {
        item = slot->items[0];
        if (slot->num == 1) {
            slot->items[1] = item;
        } else {
            tail_need_save = 1;
        }
    }

    slot->items[0].key = key;
    slot->items[0].fd = fd;
    slot->items[0].timestamp = tc_current_time_sec;

    for (i = 1; i < slot->num; i = (i << 1) + 1) {
        if (slot->items[i].timestamp > slot->items[i + 1].timestamp) {
            ++i;
        }

        /* TODO needs to be optimized */ 
        tmp = slot->items[i];
        slot->items[i] = item;
        item = tmp;
        if (item.timestamp == 0) {
            tail_need_save = 0;
        }
    }

    if (slot->num < ROUTE_ARRAY_SIZE) {
        if (tail_need_save) {
            slot->items[slot->num] = item;
        }

        slot->num++;
    }
}


/* add item to the router table */
void
router_add(int old, uint32_t clt_ip, uint16_t clt_port, uint32_t target_ip, 
        uint16_t target_port, int fd)
{
    int           i, max, existed, index, remainder;
    uint32_t      key;
    route_slot_t *slot;

    table->total_sessions++;

    key = get_route_key(old, clt_ip, clt_port, target_ip, target_port);

    index = (key & ROUTE_KEY_HIGH_MASK) >> ROUTE_KEY_SHIFT;
    remainder = key & ROUTE_KEY_LOW_MASK;

    table->cache[index].key = remainder; 
    table->cache[index].fd  = (uint16_t) fd; 

    slot = table->slots + index;

    existed = 0;
    max = ROUTE_ARRAY_SIZE;
    if (slot->num < ROUTE_ARRAY_SIZE) {
        max = slot->num;
    }

    for (i = 0; i < max; i++) {
        if (slot->items[i].key == remainder) {
            slot->items[i].fd = fd;
            slot->items[i].timestamp = tc_current_time_sec;
            existed = 1;
            break;
        }

#if 0
        if (slot->items[i].timestamp == 0) {
            tc_log_info(LOG_WARN, 0, "in add visit %d null timestamp,all:%d",
                    i + 1, max);
        }
#endif

    }

    if (!existed) {
        router_add_adjust(slot, remainder, fd);
    } else {
        router_update_adjust(slot, i);
    }

    delay_table_send(key, fd);

}

int
router_get(uint32_t key)
{
    int           i, fd = 0, index, remainder;
    route_slot_t *slot;

    table->searched++;
    index = (key & ROUTE_KEY_HIGH_MASK) >> ROUTE_KEY_SHIFT;
    remainder = key & ROUTE_KEY_LOW_MASK;

    if (table->cache[index].key == remainder) {
        table->hit++;
        return (int) table->cache[index].fd;
    }

    slot = table->slots + index;
    for (i = 0; i < slot->num; i++) {
        if (slot->items[i].key == remainder) {
            table->missed++;
            fd = (int) slot->items[i].fd;
            router_update_adjust(slot, i);
            break;
        }
        table->extra_compared++;
#if 1
        if (slot->items[i].timestamp == 0) {
            tc_log_info(LOG_WARN, 0, "in get, visit %d null timestamp, all:%d",
                    i + 1, slot->num);
        }
#endif
 
    }

    if (i < slot->num) {
        table->cache[index].key = remainder;
        table->cache[index].fd  = fd;
        return fd;
    }
    
    table->lost++;

    return -1;

}


void
router_update(int old, int main_router_fd, tc_ip_header_t *ip_header)
{
#if (!TCPCOPY_SINGLE)
    int                     fd;
    uint32_t                key;
#endif
    uint32_t                size_ip, size_tcp, tot_len;
    msg_server_t            msg;
    tc_tcp_header_t        *tcp_header;
#if (TCPCOPY_MYSQL_ADVANCED)
    uint32_t                cont_len;
    unsigned char          *payload, *p;
#endif
#if (TCPCOPY_SINGLE)
    if (main_router_fd == 0) {
        return;
    }
#endif
    if (ip_header->protocol != IPPROTO_TCP) {
        tc_log_info(LOG_INFO, 0, "this is not a tcp packet");
        return;
    }

    size_ip = ip_header->ihl << 2;
    tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);
    size_tcp = tcp_header->doff << 2;
    tot_len  = ntohs(ip_header->tot_len);

    memset(&msg, 0, sizeof(struct msg_server_s));
    memcpy((void *) &(msg.ip_header), ip_header, sizeof(tc_ip_header_t));
    memcpy((void *) &(msg.tcp_header), tcp_header, size_tcp);

#if (TCPCOPY_MYSQL_ADVANCED)
    cont_len = tot_len - size_ip - size_tcp;
    if (cont_len > 0) {
        payload = (unsigned char *) ((char *) tcp_header + size_tcp);
        if (cont_len <= MAX_PAYLOAD_LEN) {
            p = ((unsigned char *) &(msg.tcp_header)) + size_tcp;
            memcpy((void *) p, payload, cont_len);
        }
    }
#endif 
#if (!TCPCOPY_SINGLE)
    key = get_route_key(old, ip_header->daddr, tcp_header->dest, 
            ip_header->saddr, tcp_header->source);
    fd  = router_get(key);
    if (fd <= 0) {
        if (!tcp_header->syn) {
            tc_log_info(LOG_NOTICE, 0, "fd is null after session is created");
            tc_log_trace(LOG_NOTICE, 0,  BACKEND_FLAG, ip_header, tcp_header);
            return;
        }
        tc_log_debug0(LOG_DEBUG, 0, "fd is null");
        delay_table_add(key, &msg);
        return ;
    }
#endif

    tc_log_debug_trace(LOG_NOTICE, 0,  BACKEND_FLAG, ip_header, tcp_header);

#if (INTERCEPT_COMBINED)

#if (!TCPCOPY_SINGLE)
    buffer_and_send(main_router_fd, (int) (long) fd, &msg);
#else
    buffer_and_send(main_router_fd, main_router_fd, &msg);
#endif                       
#else

#if (!TCPCOPY_SINGLE)
    tc_socket_send((int) (long) fd, (char *) &msg, MSG_SERVER_SIZE);
#else
    tc_socket_send(main_router_fd, (char *) &msg, MSG_SERVER_SIZE);
#endif

#endif

}


void router_stat()
{
    tc_log_info(LOG_NOTICE, 0, "cache hit:%llu,missed:%llu,lost:%llu", 
            table->hit, table->missed, table->lost);
    tc_log_info(LOG_NOTICE, 0, 
            "search:%llu,extra compared:%llu,all sessions:%llu", 
            table->searched, table->extra_compared, table->total_sessions);

}

/* destroy router table */
void
router_destroy()
{
    int i, stat[ROUTE_ARRAY_ACTIVE_NUM_RANGE];

    if (table != NULL) {

        tc_log_info(LOG_NOTICE, 0, "cache hit:%llu,missed:%llu,lost:%llu", 
                table->hit, table->missed, table->lost);
        tc_log_info(LOG_NOTICE, 0, 
            "search:%llu,extra compared:%llu,all sessions:%llu", 
            table->searched, table->extra_compared, table->total_sessions);

        memset(stat, 0, sizeof(int) * ROUTE_ARRAY_ACTIVE_NUM_RANGE);
        for (i = 0; i <  ROUTE_SLOTS; i++) {
            stat[table->slots[i].num]++;
        }

        for (i = 0; i < ROUTE_ARRAY_ACTIVE_NUM_RANGE; i++) {
            tc_log_info(LOG_NOTICE, 0, "array has %d items and its stat:%d",
                    i, stat[i]);
        }

        tc_log_info(LOG_NOTICE, 0, "destroy router table");
        free(table);
        table = NULL;
    }
}

