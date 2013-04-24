#include <xcopy.h>
#if (INTERCEPT_THREAD)
#include <pthread.h>
#endif
#include <intercept.h>

static hash_table     *table;
static uint64_t        fd_null_cnt = 0;
#if (INTERCEPT_COMBINED)
static aggregation_t  *combined[MAX_FD_NUM];
static int             max_fd = 0;
#endif

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

#if (INTERCEPT_COMBINED)
static void 
buffer_and_send(int mfd, int fd, msg_server_t *msg)
{
    int                  is_send = 0, bytes;
    unsigned char       *p;
    aggregation_t       *aggr;

    if (fd > max_fd) {
        max_fd = fd;
    }

    if (max_fd > MAX_FD_VALUE) {
        tc_log_info(LOG_WARN, 0, "fd is too large:%d", max_fd);
        max_fd = MAX_FD_VALUE;
        return;
    }

    aggr = combined[fd];
    if (!aggr) {
        aggr = (aggregation_t *) malloc(sizeof(aggregation_t));
        if (aggr == NULL) {
            tc_log_info(LOG_ERR, errno, "can't malloc memory");
        } else {
            tc_log_info(LOG_ERR, 0, "malloc memory for fd:%d", fd);
            memset(aggr, 0, sizeof(aggregation_t));
            aggr->cur_write = aggr->aggr_resp;
            combined[fd] = aggr;
        }
    }

    if (aggr) {
        if (msg != NULL) {
            p = aggr->cur_write;
            memcpy((char *) p, (char *) msg, MSG_SERVER_SIZE); 
            aggr->cur_write = p + MSG_SERVER_SIZE;
            aggr->num = aggr->num + 1;
        }

        if (aggr->num == COMB_MAX_NUM) {
            is_send = 1;
        } else if (aggr->access_time < tc_current_time_sec) {
            is_send = 1;
        } else if (aggr->access_time == tc_current_time_sec) {
            if (aggr->access_msec != tc_current_time_msec) {
                is_send = 1;
            }
        }

        if (is_send) {
            tc_log_debug1(LOG_DEBUG, 0, "combined send:%d", aggr->num);
            aggr->num = htons(aggr->num);
            p = (unsigned char *) (&(aggr->num));
            bytes = aggr->cur_write - aggr->aggr_resp + sizeof(aggr->num);
            tc_log_debug1(LOG_DEBUG, 0, "send bytes:%d", bytes);
#if (!TCPCOPY_SINGLE)
            tc_socket_send(fd, (char *) p, bytes);
#else
            tc_socket_send(mfd, (char *) p, bytes);
#endif
            aggr->num = 0;
            aggr->cur_write = aggr->aggr_resp;
        } 
    }

    aggr->access_time = tc_current_time_sec;
    aggr->access_msec = tc_current_time_msec;

}

void
send_buffered_packets(time_t cur_time)
{
    int i;

    for (i = 0; i <= max_fd; i++) {
        if (combined[i] != NULL) {
            buffer_and_send(srv_settings.router_fd, i, NULL);
        }
    }
}

#endif

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
    buffer_and_send(main_router_fd, (int) (long) fd, &msg);
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
    uint32_t                size_ip, size_tcp;
    msg_server_t            msg;
    tc_tcp_header_t        *tcp_header;
#if (TCPCOPY_MYSQL_ADVANCED)
    uint32_t                cont_len, tot_len;
    unsigned char          *payload, *p;
#endif

    if (ip_header->protocol != IPPROTO_TCP) {
        tc_log_info(LOG_INFO, 0, "this is not a tcp packet");
        return;
    }

    size_ip = ip_header->ihl << 2;
    tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);
    size_tcp = tcp_header->doff << 2;

    memset(&msg, 0, sizeof(struct msg_server_s));
    memcpy((void *) &(msg.ip_header), ip_header, sizeof(tc_ip_header_t));

    if (size_tcp > MAX_OPTION_LEN) {
        set_wscale(tcp_header);
        size_tcp = tcp_header->doff << 2;
    }
    memcpy((void *) &(msg.tcp_header), tcp_header, size_tcp);

#if (TCPCOPY_MYSQL_ADVANCED)
    tot_len  = ntohs(ip_header->tot_len);
    cont_len = tot_len - size_ip - size_tcp;
    if (cont_len > 0) {
        payload = (unsigned char *) ((char *) tcp_header + size_tcp);
        if (cont_len <= MAX_PAYLOAD_LEN) {
            p = ((unsigned char *) msg.tcp_header) + size_tcp;
            /*
             * only transfer payload if content length is less
             * than MAX_PAYLOAD_LEN
             */
            memcpy((void *) &(p), payload, cont_len);
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
    buffer_and_send(main_router_fd, (int) (long) fd, &msg);
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
#if (INTERCEPT_COMBINED)
    int i;

    for (i = 0; i <= max_fd; i++) {
        if (combined[i] != NULL) {
            free(combined[i]);
            combined[i] = NULL;
            tc_log_info(LOG_NOTICE, 0, "release resources for fd %d", i);
        }
    }
#endif

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

