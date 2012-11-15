#include <xcopy.h>
#if (INTERCEPT_THREAD)
#include <pthread.h>
#endif
#include <intercept.h>

static hash_table *table;
static uint64_t    fd_null_cnt = 0;

#if (INTERCEPT_THREAD)
static pthread_mutex_t mutex; 
#endif

void 
route_delete_obsolete(time_t cur_time)
{   
    int          i, count = 0, timeout;
    hash_node   *hn;
    link_list   *l;
    p_link_node  ln;

    tc_log_info(LOG_NOTICE, 0, "router size:%u", table->total);
#if (INTERCEPT_THREAD)
    pthread_mutex_lock(&mutex);
#endif

    for (i = 0; i < table->size; i++) {

        l  = table->lists[i];
        if (l->size > 0) {
            while (true) {
                ln = link_list_tail(l); 
                if (ln == NULL) {
                    break;
                }       
                hn = (hash_node *)ln->data;
                timeout = table->timeout;
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

    tc_log_info(LOG_NOTICE, 0, "router delete obsolete:%d", count);

    delay_table_delete_obsolete(cur_time);

#if (INTERCEPT_THREAD)
    pthread_mutex_unlock(&mutex);
#endif

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
router_update(tc_ip_header_t *ip_header, int len)
{
    void                   *fd;
    uint32_t                size_ip;
    uint64_t                key;
    msg_server_t            msg;
    tc_tcp_header_t        *tcp_header;

    size_ip    = ip_header->ihl << 2;
    tcp_header = (tc_tcp_header_t *) ((char *)ip_header + size_ip);

    tc_log_debug1(LOG_DEBUG, 0, "router update:%u", ntohs(tcp_header->source));
    memcpy(&msg, ip_header, len);

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

    tc_log_debug_trace(LOG_NOTICE, 0,  BACKEND_FLAG, ip_header, tcp_header);

    tc_socket_send((int) (long) fd, (char *) &msg, MSG_SERVER_SIZE);
}

#else 

void
router_update(tc_ip_header_t *ip_header)
{
    void                   *fd;
    uint32_t                size_ip;
    uint64_t                key;
    msg_server_t            msg;
    tc_tcp_header_t        *tcp_header;
#if (TCPCOPY_MYSQL_ADVANCED)
    uint32_t                size_tcp, cont_len, tot_len;
    unsigned char          *payload;
#endif

    if (ip_header->protocol != IPPROTO_TCP) {
        tc_log_info(LOG_INFO, 0, "this is not a tcp packet");
        return;
    }

    size_ip = ip_header->ihl << 2;
    tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);

    memset(&msg, 0, sizeof(struct msg_server_s));
    memcpy((void *) &(msg.ip_header), ip_header, sizeof(tc_ip_header_t));
    memcpy((void *) &(msg.tcp_header), tcp_header, sizeof(tc_tcp_header_t));

#if (TCPCOPY_MYSQL_ADVANCED)
    tot_len  = ntohs(ip_header->tot_len);
    size_tcp = tcp_header->doff << 2;
    cont_len = tot_len - size_ip - size_tcp;
    if (cont_len > 0) {
        payload = (unsigned char *) ((char *) tcp_header + size_tcp);
        if (cont_len <= MAX_PAYLOAD_LEN) {
            /*
             * only transfer payload if content length is less
             * than MAX_PAYLOAD_LEN
             */
            memcpy((void *) &(msg.payload), payload, cont_len);
        }
    }
#endif
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

    tc_log_debug_trace(LOG_NOTICE, 0,  BACKEND_FLAG, ip_header, tcp_header);
    tc_socket_send((int) (long) fd, (char *) &msg, MSG_SERVER_SIZE);
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

