#include "router.h"
#include "delay.h"
#include "../communication/msg.h"
#include "../core/hash.h"
#include "../util/util.h"

static hash_table *table;

void route_delete_obsolete(time_t cur_time)
{   
    hash_node   *hn;
    p_link_node ln;
    link_list   *l;
    int         i, count = 0, timeout;

    log_info(LOG_NOTICE, "router size:%u", table->total);
    for(i = 0; i < table->size; i++){
        l  = table->lists[i];
        if(l->size > 0){
            while(true){
                ln = link_list_tail(l); 
                if(NULL == ln){
                    break;
                }       
                hn = (hash_node *)ln->data;
                timeout = table->timeout;
                if(0 == hn->visit_cnt){
                    /* 
                     * If we have not received the second handshake packet 
                     * for more than 3 seconds,then we clear out router info 
                     */
                    timeout = 3;
                }
                if((hn->access_time + timeout) < cur_time){
                    link_list_pop_tail(l);
                    free(hn);
                    ln->data = NULL;
                    free(ln);
                    table->total--;
                    count++;
                }else{
                    break;
                }   
            }
        }
    } 
    log_info(LOG_NOTICE, "router delete obsolete:%d", count);
}


/* Initiate router table */
void router_init(size_t size)
{
    table = hash_create(size);
    strcpy(table->name, "router-table");
    log_info(LOG_NOTICE, "create %s, size:%u", table->name, table->size);
}

/* Delete item in router table */
void router_del(uint32_t ip, uint16_t port)
{
    uint64_t key = get_key(ip, port);
    hash_del(table, key);
    delay_table_del(key);
}

/* Add item to the router table */
void router_add(uint32_t ip, uint16_t port, int fd)
{
    uint64_t key = get_key(ip, port);
    hash_add(table, key, (void *)(long)fd);
    delay_table_send(key, fd);
}

/* Update router table */
void router_update(struct iphdr *ip_header)
{
    uint32_t               size_ip;
    struct tcphdr          *tcp_header;
    uint64_t               key;
    void                   *fd;
    struct msg_server_s    msg;
#if (TCPCOPY_MYSQL_ADVANCED) 
    unsigned char          *payload;
    uint32_t               size_tcp, cont_len, tot_len;
#endif

    if(ip_header->protocol != IPPROTO_TCP){
        log_info(LOG_INFO, "this is not a tcp packet");
        return;
    }
    size_ip = ip_header->ihl << 2;
    tcp_header = (struct tcphdr*)((char *)ip_header + size_ip);

    memset(&msg, 0, sizeof(struct msg_server_s));
    memcpy((void *) &(msg.ip_header),  ip_header,  sizeof(struct iphdr));
    memcpy((void *) &(msg.tcp_header), tcp_header, sizeof(struct tcphdr));

#if (TCPCOPY_MYSQL_ADVANCED) 
    tot_len  = ntohs(ip_header->tot_len);
    size_tcp = tcp_header->doff << 2;
    cont_len = tot_len - size_ip - size_tcp;
    if(cont_len > 0){
        payload =(unsigned char*)((char*)tcp_header + size_tcp);
        if(cont_len <= MAX_PAYLOAD_LEN){
            /*
             * Only transfer payload if content length is less
             * than MAX_PAYLOAD_LEN
             */
            memcpy((void *)&(msg.payload), payload, cont_len);
        }
    }
#endif
    key = get_key(ip_header->daddr, tcp_header->dest);
    fd  = hash_find(table, key);
    if( NULL == fd ){
#if (DEBUG_TCPCOPY)
        log_info(LOG_INFO, "fd is null");
#endif
        delay_table_add(key, &msg);
        return ;
    }
    msg_server_send((int)(long)fd, &msg);
}

/* Destroy router table */
void router_destroy()
{
    if(table != NULL){
        log_info(LOG_NOTICE, "destroy router table");
        hash_destory(table);
        free(table);
        table = NULL;
    }
}

