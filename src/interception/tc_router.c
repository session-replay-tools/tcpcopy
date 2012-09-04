#include <xcopy.h>
#include <pthread.h>
#include <intercept.h>

static hash_table *table;
static pthread_mutex_t mutex; 

void 
route_delete_obsolete(time_t cur_time)
{   
    int          i, count = 0, timeout;
    hash_node   *hn;
    link_list   *l;
    p_link_node  ln;

    tc_log_info(LOG_NOTICE, 0, "router size:%u", table->total);

    pthread_mutex_lock(&mutex);

    for (i = 0; i < table->size; i++) {

        l  = table->lists[i];
        if (l->size > 0) {
            while (true) {
                ln = link_list_tail(l); 
                if (NULL == ln) {
                    break;
                }       
                hn = (hash_node *)ln->data;
                timeout = table->timeout;
                if (0 == hn->visit_cnt) {
                    /* 
                     * If we have not received the second handshake packet 
                     * for more than 3 seconds,then we clear out router info 
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

    pthread_mutex_unlock(&mutex);

}


/* Initiate router table */
void
router_init(size_t size)
{
    pthread_mutex_init(&mutex, NULL);
    delay_table_init(size);
    table = hash_create(size << 1);
    strcpy(table->name, "router-table");
    tc_log_info(LOG_NOTICE, 0, "create %s, size:%u", table->name, table->size);
}

/* Delete item in router table */
void
router_del(uint32_t ip, uint16_t port)
{
    uint64_t key = get_key(ip, port);

    pthread_mutex_lock(&mutex);
    hash_del(table, key);
    delay_table_del(key);
    pthread_mutex_unlock(&mutex);

}

/* Add item to the router table */
void
router_add(uint32_t ip, uint16_t port, int fd)
{
    uint64_t key = get_key(ip, port);

    pthread_mutex_unlock(&mutex);
    hash_add(table, key, (void *)(long)fd);
    delay_table_send(key, fd);
    pthread_mutex_unlock(&mutex);
}

/* Update router table */
void
router_update(tc_ip_header_t *ip_header, int len)
{
    void                   *fd;
    uint32_t                size_ip;
    uint64_t                key;
    msg_server_t            msg;
    struct tcphdr          *tcp_header;

    size_ip    = ip_header->ihl << 2;
    tcp_header = (struct tcphdr*)((char *)ip_header + size_ip);

    memcpy(&msg, ip_header, len);

    key = get_key(ip_header->daddr, tcp_header->dest);
    pthread_mutex_lock(&mutex);
    fd  = hash_find(table, key);
    if ( NULL == fd ) {
        tc_log_debug0(LOG_DEBUG, 0, "fd is null");
        delay_table_add(key, &msg);
        return ;
    }
    pthread_mutex_unlock(&mutex);

    tc_socket_send((int) (long) fd, (char *) &msg, MSG_SERVER_SIZE);
}

/* Destroy router table */
void
router_destroy()
{
    pthread_mutex_lock(&mutex);
    if (table != NULL) {
        tc_log_info(LOG_NOTICE, 0, "destroy router table");
        hash_destroy(table);
        free(table);
        table = NULL;
        delay_table_destroy();
    }
    pthread_mutex_unlock(&mutex);
}

