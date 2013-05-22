#include <xcopy.h>
#if (INTERCEPT_THREAD)
#include <pthread.h>
#endif
#include <intercept.h>

static hash_table     *table;
static uint64_t        fd_null_cnt = 0;

#if (INTERCEPT_THREAD)
static pthread_mutex_t mutex; 
#endif

void 
route_delete_obsolete(time_t cur_time)
{   
    int          i, count = 0, timeout, cur_timeout;
    hash_node   *hn;
    link_list   *l;
    p_link_node  ln;

    cur_timeout = table->timeout;

#if (INTERCEPT_THREAD)
    pthread_mutex_lock(&mutex);
#endif

    if (table->total < TIMEOUT_CHANGE_THRESHOLD) {
        cur_timeout = cur_timeout << 3;
    }

    tc_log_info(LOG_NOTICE, 0, "router size:%u, timeout:%d",
            table->total, cur_timeout);

    for (i = 0; i < table->size; i++) {

        l  = table->lists[i];
        if (l->size > 0) {
            while (true) {
                ln = link_list_tail(l); 
                if (ln == NULL) {
                    break;
                }       
                hn = (hash_node *) ln->data;
                timeout = cur_timeout;
                if (0 == hn->visit_cnt) {
                    /* 
                     * If we have not received the second handshake packet 
                     * for more than 3 seconds, we clear out router info 
                     */
                    timeout = 3;
                }
                if ((hn->access_time + timeout) < cur_time) {
                    link_list_pop_tail(l);
                    free(hn);
                    ln->data = NULL;
                    free(ln);
                    table->total--;
                    count++;
                } else {
                    break;
                }   
            }
        }
    } 


    delay_table_delete_obsolete(cur_time);

#if (INTERCEPT_THREAD)
    pthread_mutex_unlock(&mutex);
#endif

    tc_log_info(LOG_NOTICE, 0, "router delete obsolete:%d", count);

}


/* initiate router table */
void
router_init(size_t size, int timeout)
{
#if (INTERCEPT_THREAD)
    pthread_mutex_init(&mutex, NULL);
#endif
    delay_table_init(size);
    table = hash_create(size << 1);
    hash_set_timeout(table, timeout);
    strcpy(table->name, "router-table");
    tc_log_info(LOG_NOTICE, 0, "create %s, size:%u", table->name, table->size);
}

/* delete item in router table */
void
router_del(uint32_t ip, uint16_t port)
{
    uint64_t key = get_key(ip, port);

#if (INTERCEPT_THREAD)
    pthread_mutex_lock(&mutex);
#endif

    hash_del(table, key);
    delay_table_del(key);

#if (INTERCEPT_THREAD)
    pthread_mutex_unlock(&mutex);
#endif

}

/* add item to the router table */
void
router_add(uint32_t ip, uint16_t port, int fd)
{
    uint64_t key = get_key(ip, port);

#if (INTERCEPT_THREAD)
    pthread_mutex_lock(&mutex);
#endif

    hash_add(table, key, (void *) (long) fd);
    delay_table_send(key, fd);

#if (INTERCEPT_THREAD)
    pthread_mutex_unlock(&mutex);
#endif
}

#if (INTERCEPT_THREAD)
/* update router table */
void
router_update(int main_router_fd, tc_ip_header_t *ip_header, int len)
{
#if (!TCPCOPY_SINGLE)
    void                   *fd;
    uint64_t                key;
#endif
    uint32_t                size_ip;
    msg_server_t            msg;
    tc_tcp_header_t        *tcp_header;

#if (TCPCOPY_SINGLE)
    if (main_router_fd == 0) {
        return;
    }
#endif
    if (ip_header->protocol != IPPROTO_TCP) {
        tc_log_info(LOG_INFO, 0, "this is not a tcp packet");
        return;
    }

    size_ip    = ip_header->ihl << 2;
    tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);

    tc_log_debug1(LOG_DEBUG, 0, "router update:%u", ntohs(tcp_header->source));
    memcpy(&msg, ip_header, len);

#if (!TCPCOPY_SINGLE)
    key = get_key(ip_header->daddr, tcp_header->dest);
    pthread_mutex_lock(&mutex);

    fd  = hash_find(table, key);
    if (fd == NULL) {
        if (!tcp_header->syn) {
            tc_log_info(LOG_NOTICE, 0, "fd is null after session is created");
            tc_log_trace(LOG_NOTICE, 0,  BACKEND_FLAG, ip_header, tcp_header); 
        }
        tc_log_debug0(LOG_DEBUG, 0, "fd is null");
        fd_null_cnt++;
        delay_table_add(key, &msg);

        pthread_mutex_unlock(&mutex);

        return ;
    }

    pthread_mutex_unlock(&mutex);
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

#else 

void
router_update(int main_router_fd, tc_ip_header_t *ip_header)
{
#if (!TCPCOPY_SINGLE)
    void                   *fd;
    uint64_t                key;
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
            /*
             * only transfer payload if content length is less
             * than MAX_PAYLOAD_LEN
             */
            memcpy((void *) p, payload, cont_len);
        }
    }
#endif
#if (!TCPCOPY_SINGLE)
    key = get_key(ip_header->daddr, tcp_header->dest);
    fd  = hash_find(table, key);
    if (fd == NULL) {
        if (!tcp_header->syn) {
            tc_log_info(LOG_NOTICE, 0, "fd is null after session is created");
            tc_log_trace(LOG_NOTICE, 0,  BACKEND_FLAG, ip_header, tcp_header);
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

#endif

/* destroy router table */
void
router_destroy()
{

#if (INTERCEPT_THREAD)
    pthread_mutex_lock(&mutex);
#endif
    if (table != NULL) {
        tc_log_info(LOG_NOTICE, 0, "destroy router table");
        tc_log_info(LOG_NOTICE, 0, "fd null counter:%llu", fd_null_cnt);
        hash_destroy(table);
        free(table);
        table = NULL;
        delay_table_destroy();
    }
#if (INTERCEPT_THREAD)
    pthread_mutex_unlock(&mutex);
#endif
}

