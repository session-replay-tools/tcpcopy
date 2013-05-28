#include <xcopy.h>
#include <intercept.h>

static route_table_t  *table = NULL;
static uint64_t        fd_null_cnt = 0;


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

inline uint32_t
get_route_key(uint32_t ip, uint16_t port)
{
    uint32_t value = port;

    value = (value << 16) + ip + port;

    return value;
}


/* add item to the router table */
void
router_add(uint32_t ip, uint16_t port, int fd)
{
    int           index, remainder;
    uint32_t      key;
    route_slot_t *slot;

    key = get_route_key(ip, port);

    index = (key & 0xFFFF0000) >> 16;
    remainder = key & 0x0000FFFF;

    table->cache[index].key = remainder; 
    table->cache[index].fd  = (uint16_t) fd; 

    slot = table->slots + index;
    slot->items[slot->write_index] = table->cache[index];
    slot->write_index = (slot->write_index + 1) % ROUTE_ARRAY_SIZE;

    delay_table_send(get_key(ip, port), fd);

}

int
router_get(uint32_t key)
{
    int           i, fd = 0, index, remainder;
    route_slot_t *slot;

    index = (key & 0xFFFF0000) >> 16;
    remainder = key & 0x0000FFFF;

    if (table->cache[index].key == remainder) {
        return (int) table->cache[index].fd;
    }

    slot = table->slots + index;
    for (i = 0; i < ROUTE_ARRAY_SIZE; i++) {
        if (slot->items[i].key == remainder) {
            fd = (int) slot->items[i].fd;
            break;
        }
    }

    if (i < ROUTE_ARRAY_SIZE) {
        table->cache[index] = slot->items[i];
        return fd;
    }

    return -1;

}


void
router_update(int main_router_fd, tc_ip_header_t *ip_header)
{
#if (!TCPCOPY_SINGLE)
    int                     fd;
    uint32_t                key;
#endif
    uint32_t                size_ip, size_tcp, new_size_tcp;
    msg_server_t            msg;
    tc_tcp_header_t        *tcp_header;
#if (TCPCOPY_MYSQL_ADVANCED)
    uint32_t                cont_len, tot_len, new_tot_len;
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
#if (TCPCOPY_MYSQL_ADVANCED)
    tot_len  = ntohs(ip_header->tot_len);
#endif

    memset(&msg, 0, sizeof(struct msg_server_s));
    new_size_tcp = size_tcp;
    if (size_tcp > TCP_HEADER_MIN_LEN) {
        set_wscale(tcp_header);
        new_size_tcp = tcp_header->doff << 2;
#if (TCPCOPY_MYSQL_ADVANCED)
        new_tot_len = tot_len - (size_tcp - new_size_tcp);
        ip_header->tot_len = htons(new_tot_len);
#endif
    }
    memcpy((void *) &(msg.ip_header), ip_header, sizeof(tc_ip_header_t));
    memcpy((void *) &(msg.tcp_header), tcp_header, new_size_tcp);

#if (TCPCOPY_MYSQL_ADVANCED)
    cont_len = tot_len - size_ip - size_tcp;
    if (cont_len > 0) {
        payload = (unsigned char *) ((char *) tcp_header + size_tcp);
        if (cont_len <= MAX_PAYLOAD_LEN) {
            p = ((unsigned char *) &(msg.tcp_header)) + new_size_tcp;
            memcpy((void *) p, payload, cont_len);
        }
    }
#endif 
#if (!TCPCOPY_SINGLE)
    key = get_route_key(ip_header->daddr, tcp_header->dest);
    fd  = router_get(key);
    if (fd <= 0) {
        if (!tcp_header->syn) {
            tc_log_info(LOG_NOTICE, 0, "fd is null after session is created");
            tc_log_trace(LOG_NOTICE, 0,  BACKEND_FLAG, ip_header, tcp_header);
            return;
        }
        tc_log_debug0(LOG_DEBUG, 0, "fd is null");
        fd_null_cnt++;
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


/* destroy router table */
void
router_destroy()
{
    if (table != NULL) {
        tc_log_info(LOG_NOTICE, 0, "destroy router table");
        tc_log_info(LOG_NOTICE, 0, "fd null counter:%llu", fd_null_cnt);
        free(table);
        table = NULL;
    }
}

