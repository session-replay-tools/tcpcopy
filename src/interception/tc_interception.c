#include <xcopy.h>
#if (INTERCEPT_THREAD)
#include <pthread.h>
#endif
#include <intercept.h>

static pid_t           pid;
static time_t          last_clean_time;
static uint64_t        tot_copy_resp_packs = 0; 
static uint64_t        tot_resp_packs = 0; 

#if (!INTERCEPT_NFQUEUE)
static uint32_t        seq = 1;
static unsigned char   buffer[128];
#endif

#if (INTERCEPT_THREAD)
/* for pool */
static char            pool[POOL_SIZE];
static uint64_t        read_counter  = 0;
static uint64_t        write_counter = 0; 
static pthread_mutex_t mutex;
static pthread_cond_t  empty;
static pthread_cond_t  full;


typedef struct tc_verdict_s{
    int fd;
    int verdict;
    unsigned long packet_id;
}tc_verdict_t;


/* for netlink sending */
static tc_verdict_t    nl_pool[NL_POOL_SIZE];
static uint64_t        nl_read_counter  = 0;
static uint64_t        nl_write_counter = 0; 
static pthread_mutex_t nl_mutex;
static pthread_cond_t  nl_empty;
static pthread_cond_t  nl_full;

#endif

static int tc_msg_event_process(tc_event_t *rev);

static int
tc_msg_event_accept(tc_event_t *rev)
{
    int         fd;
    tc_event_t *ev;

    if ((fd = tc_socket_accept(rev->fd)) == TC_INVALID_SOCKET) {
        tc_log_info(LOG_ERR, 0, "msg accept failed, from listen:%d", rev->fd);
        return TC_ERROR;
    }

    if (tc_socket_set_nodelay(fd) == TC_ERROR) {
        tc_log_info(LOG_ERR, 0, "Set no delay to socket(%d) failed.", rev->fd);
        return TC_ERROR;
    }

    ev = tc_event_create(fd, tc_msg_event_process, NULL);
    if (ev == NULL) {
        tc_log_info(LOG_ERR, 0, "Msg event create failed.");
        return TC_ERROR;
    }

    if (tc_event_add(rev->loop, ev, TC_EVENT_READ) == TC_EVENT_ERROR) {
        return TC_ERROR;
    }
#if (TCPCOPY_SINGLE)  
    if (srv_settings.router_fd > 0) {
        tc_log_info(LOG_WARN, 0, "it does not support distributed tcpcopy");
    }
    srv_settings.router_fd = fd;
#endif

    return TC_OK;
}

static int 
tc_msg_event_process(tc_event_t *rev)
{
    msg_client_t msg;

    if (tc_socket_recv(rev->fd, (char *) &msg, MSG_CLIENT_SIZE) == TC_ERROR) {
        tc_socket_close(rev->fd);
        tc_log_info(LOG_NOTICE, 0, "close sock:%d", rev->fd);
        tc_event_del(rev->loop, rev, TC_EVENT_READ);
        return TC_ERROR;
    }

    switch (msg.type) {
        case CLIENT_ADD:
            tc_log_debug1(LOG_DEBUG, 0, "add client router:%u",
                          ntohs(msg.client_port));
            router_add(msg.client_ip, msg.client_port, rev->fd);
            break;
        case CLIENT_DEL:
            tc_log_debug1(LOG_DEBUG, 0, "del client router:%u",
                          ntohs(msg.client_port));
            router_del(msg.client_ip, msg.client_port);
            break;
    }

    return TC_OK;
}

static void
tc_check_cleaning()
{
    int      diff;
    time_t   now;

    now  = tc_time();
    diff = now - last_clean_time;
    if (diff > CHECK_INTERVAL) {
        tc_log_info(LOG_NOTICE, 0, "total resp packets:%llu, all:%llu",
                tot_copy_resp_packs, tot_resp_packs);
        route_delete_obsolete(now);
        last_clean_time = now;
    }
}


#if (INTERCEPT_THREAD)
static
void put_resp_header_to_pool(tc_ip_header_t *ip_header)
{
    int                    *p_len, cur_w_pos, diff, next_w_pos;
    char                   *p_content;
    uint16_t                size_ip, save_len, record_len;
#if (TCPCOPY_MYSQL_ADVANCED) 
    uint16_t                size_tcp, cont_len, tot_len;
    unsigned char          *payload; 
#endif
    uint64_t                next_w_cnt; 
    tc_tcp_header_t        *tcp_header;

    if (ip_header->protocol != IPPROTO_TCP) {
        tc_log_info(LOG_WARN, 0, "this is not a tcp packet");
        return;
    }

    save_len = RESP_MAX_USEFUL_SIZE;

    size_ip = ip_header->ihl << 2;
    tcp_header = (tc_tcp_header_t *) ((char *)ip_header + size_ip);

#if (TCPCOPY_MYSQL_ADVANCED) 
    size_tcp = tcp_header->doff << 2;
    tot_len  = ntohs(ip_header->tot_len);
    cont_len = tot_len - size_ip - size_tcp;
    if (cont_len > 0 && cont_len <= MAX_PAYLOAD_LEN) {
            save_len += cont_len;
    }
#endif

    record_len = save_len;
    pthread_mutex_lock(&mutex);
    next_w_cnt = write_counter + save_len + sizeof(int); 
    next_w_pos = next_w_cnt & POOL_MASK;

    if (next_w_pos > POOL_MAX_ADDR) {
        next_w_cnt  = (next_w_cnt / POOL_SIZE + 1) << POOL_SHIFT;
        record_len += (POOL_SIZE - next_w_pos);
    }

    diff = next_w_cnt - read_counter;
    
    for (;;) {
        if (diff > POOL_SIZE) {
            tc_log_info(LOG_WARN, 0, "pool is full");
            pthread_cond_wait(&empty, &mutex);
        } else {
            break;
        }
        diff = next_w_cnt - read_counter;
    }

    cur_w_pos = write_counter & POOL_MASK;
    p_len     = (int *) (pool + cur_w_pos);
    p_content = (char *) ((unsigned char *) p_len + sizeof(int));
    
    write_counter = next_w_cnt;
    
    *p_len = record_len;
    ip_header->ihl = (sizeof(tc_ip_header_t)) >> 2;
    memcpy(p_content, ip_header, sizeof(tc_ip_header_t));
    p_content = p_content + sizeof(tc_ip_header_t);
    memcpy(p_content, tcp_header, sizeof(tc_tcp_header_t));

#if (TCPCOPY_MYSQL_ADVANCED) 
    if (cont_len > 0 && cont_len <= MAX_PAYLOAD_LEN) {
        p_content = p_content + sizeof(tc_tcp_header_t);
        payload = (unsigned char*) ((char*) tcp_header + size_tcp);
        memcpy(p_content, payload, cont_len);
    }
#endif

    pthread_cond_signal(&full);
    pthread_mutex_unlock(&mutex);
}

static tc_ip_header_t *
get_resp_ip_hdr_from_pool(char *resp, int *len)
{
    int       read_pos;
    char     *pos;

    pthread_mutex_lock(&mutex);

    if (read_counter >= write_counter) {
        pthread_cond_wait(&full, &mutex);
    }

    read_pos = read_counter & POOL_MASK;

    pos = pool + read_pos;
    *len = *(int *) (pos);

    pos = pos + sizeof(int);

    memcpy(resp, pos, *len);

    read_counter += (*len + sizeof(int));

    pthread_cond_signal(&empty);
    pthread_mutex_unlock(&mutex);

    return (tc_ip_header_t *)resp;
}

static
void put_nl_verdict_to_pool(int fd, int verdict, unsigned long packet_id)
{
    int  index, diff;

    pthread_mutex_lock(&nl_mutex);

    index = nl_write_counter & NL_POOL_MASK;

    diff = nl_write_counter - nl_read_counter + 1;
    
    for (;;) {
        if (diff > NL_POOL_SIZE) {
            tc_log_info(LOG_WARN, 0, "nl pool is full");
            pthread_cond_wait(&nl_empty, &nl_mutex);
        } else {
            break;
        }

        diff = nl_write_counter - nl_read_counter + 1;
    }

    
    nl_pool[index].fd = fd;
    nl_pool[index].verdict = verdict;
    nl_pool[index].packet_id = packet_id;

    nl_write_counter++;
    
    pthread_cond_signal(&nl_full);
    pthread_mutex_unlock(&nl_mutex);
}

static tc_verdict_t*
get_nl_verdict_from_pool(tc_verdict_t* verdict)
{
    int   index;

    pthread_mutex_lock(&nl_mutex);

    if (nl_read_counter >= nl_write_counter) {
        pthread_cond_wait(&nl_full, &nl_mutex);
    }

    index = nl_read_counter & NL_POOL_MASK;

    verdict->fd = nl_pool[index].fd;
    verdict->verdict = nl_pool[index].verdict;
    verdict->packet_id = nl_pool[index].packet_id;


    nl_read_counter++;

    pthread_cond_signal(&nl_empty);
    pthread_mutex_unlock(&nl_mutex);

    return verdict;
}

#endif


#if (INTERCEPT_NFQUEUE)
static int tc_nfq_process_packet(struct nfq_q_handle *qh, 
        struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    int                          i, id = 0, payload_len = 0, ret,
                                 pass_through_flag = 0;
    unsigned char               *payload;
    tc_ip_header_t              *ip_hdr;
    struct nfqnl_msg_packet_hdr *ph;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    payload_len = nfq_get_payload(nfa, &payload);
    if (payload_len < 40) {
        tc_log_info(LOG_WARN, 0, "payload len wrong:%d", payload_len);
        return TC_ERROR;
    }

    ip_hdr = (tc_ip_header_t *)payload;

    if (ip_hdr != NULL) {
        /* check if it is the valid user to pass through firewall */
        for (i = 0; i < srv_settings.passed_ips.num; i++) {
            if (srv_settings.passed_ips.ips[i] == ip_hdr->daddr) {
                pass_through_flag = 1;
                break;
            }
        }

        tot_resp_packs++;

        if (pass_through_flag) {

            /* pass through the firewall */
            ret = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        } else {

            tot_copy_resp_packs++;
            router_update(srv_settings.router_fd, ip_hdr);

            tc_check_cleaning();

            /* drop the packet */
            ret = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        }
    } else {
        ret = TC_ERROR;
    }


    return ret;
}


static int
tc_nfq_event_process(tc_event_t *rev)
{
    int             rv = 0;
    char            buffer[65535];
    unsigned long   packet_id;

    packet_id = 0;

    if (tc_nfq_socket_recv(rev->fd, buffer, 65535, &rv) == TC_ERROR) {
        return TC_ERROR;
    }

    nfq_handle_packet(srv_settings.nfq_handler, buffer, rv);

    return TC_OK;
}

#else

static int
dispose_netlink_packet(int fd, int verdict, unsigned long packet_id)
{
    struct nlmsghdr        *nl_header = (struct nlmsghdr*)buffer;
    struct ipq_verdict_msg *ver_data;
    struct sockaddr_nl      addr;

    /*
     * The IPQM_VERDICT message is used to communicate with
     * the kernel ip queue module.
     */
    nl_header->nlmsg_type  = IPQM_VERDICT;
    nl_header->nlmsg_len   = NLMSG_LENGTH(sizeof(struct ipq_verdict_msg));
    nl_header->nlmsg_flags = (NLM_F_REQUEST);
    nl_header->nlmsg_pid   = pid;
    nl_header->nlmsg_seq   = seq++;
    ver_data = (struct ipq_verdict_msg *)NLMSG_DATA(nl_header);
    ver_data->value = verdict;
    ver_data->id    = packet_id;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family  = AF_NETLINK;
    addr.nl_pid     = 0;
    addr.nl_groups  = 0;

    /*
     * In an effort to keep packets properly ordered,
     * the impelmentation of the protocol requires that
     * the user space application send an IPQM_VERDICT message
     * after every IPQM PACKET message is received.
     *
     */
    if (sendto(fd, (void *)nl_header, nl_header->nlmsg_len, 0,
                (struct sockaddr *)&addr, sizeof(struct sockaddr_nl)) < 0)
    {
        tc_log_info(LOG_ERR, errno, "unable to send mode message");
        return 0;
    }

    return 1;
}


static int
tc_nl_event_process(tc_event_t *rev)
{
    int             i, pass_through_flag = 0;
    char            buffer[65535];
    unsigned long   packet_id;
    tc_ip_header_t *ip_hdr;

    packet_id = 0;

    if (tc_nl_socket_recv(rev->fd, buffer, 65535) == TC_ERROR) {
        return TC_ERROR;
    }

    ip_hdr = tc_nl_ip_header(buffer);
    packet_id = tc_nl_packet_id(buffer);

    if (ip_hdr != NULL) {
        /* check if it is the valid user to pass through firewall */
        for (i = 0; i < srv_settings.passed_ips.num; i++) {
            if (srv_settings.passed_ips.ips[i] == ip_hdr->daddr) {
                pass_through_flag = 1;
                break;
            }
        }

        tot_resp_packs++;

        if (pass_through_flag) {

#if (INTERCEPT_THREAD)
            put_nl_verdict_to_pool(rev->fd, NF_ACCEPT, packet_id);
#else
            /* pass through the firewall */
            dispose_netlink_packet(rev->fd, NF_ACCEPT, packet_id);
#endif
        } else {

            tot_copy_resp_packs++;
#if (INTERCEPT_THREAD)
            /* put response packet header to pool */
            put_resp_header_to_pool(ip_hdr);
            /* drop the packet */
            put_nl_verdict_to_pool(rev->fd, NF_DROP, packet_id);
#else
            router_update(srv_settings.router_fd, ip_hdr);

            tc_check_cleaning();

            /* drop the packet */
            dispose_netlink_packet(rev->fd, NF_DROP, packet_id);
#endif
        }
    }

    return TC_OK;
}

#endif


#if (INTERCEPT_THREAD)
static void *
interception_dispose_nl_verdict(void *tid)
{

    tc_verdict_t verdict;

    for (;;) {
        get_nl_verdict_from_pool(&verdict); 
        dispose_netlink_packet(verdict.fd, verdict.verdict, verdict.packet_id);
    }

    return NULL;
}


static void *
interception_process_msg(void *tid)
{
    int             len;
    char            resp[65536];
    tc_ip_header_t *ip_hdr;

    for (;;) {

        ip_hdr = get_resp_ip_hdr_from_pool(resp, &len); 
        if (ip_hdr == NULL) {
            tc_log_info(LOG_WARN, 0, "ip header is null");
        }

        router_update(srv_settings.router_fd, ip_hdr, len);

        tc_check_cleaning();

    }

    return NULL;
}
#endif

/* initiate for tcpcopy server */
int
interception_init(tc_event_loop_t *event_loop, char *ip, uint16_t port)
{
    int         fd;
#if (INTERCEPT_THREAD)
    pthread_t   thread;
#endif
    tc_event_t *ev;

    router_init(srv_settings.hash_size, srv_settings.timeout);

    pid = getpid();

    /* init the listening socket */
    if ((fd = tc_socket_init()) == TC_INVALID_SOCKET) {
        return TC_ERROR;

    } else {
        if (tc_socket_listen(fd, ip, port) == TC_ERROR) {
            return TC_ERROR;
        }

        tc_log_info(LOG_NOTICE, 0, "msg listen socket:%d", fd);

        ev = tc_event_create(fd, tc_msg_event_accept, NULL);
        if (ev == NULL) {
            return TC_ERROR;
        }

        if (tc_event_add(event_loop, ev, TC_EVENT_READ) == TC_EVENT_ERROR) {
            return TC_ERROR;
        }
    }

#if (INTERCEPT_NFQUEUE)   
    /*
     * not support multi-threading for nfqueue
     */

    /* init the nfq socket */
    if ((fd = tc_nfq_socket_init(&srv_settings.nfq_handler, 
                    &srv_settings.nfq_q_handler, tc_nfq_process_packet)) 
            == TC_INVALID_SOCKET)
    {
        return TC_ERROR;

    } else {
        tc_log_info(LOG_NOTICE, 0, "nfq socket:%d", fd);

        ev = tc_event_create(fd, tc_nfq_event_process, NULL);
        if (ev == NULL) {
            return TC_ERROR;
        }

        if (tc_event_add(event_loop, ev, TC_EVENT_READ) == TC_EVENT_ERROR) {
            return TC_ERROR;
        }
    }
#else
    /* init the netlink socket */
    if ((fd = tc_nl_socket_init()) == TC_INVALID_SOCKET) {
        return TC_ERROR;

    } else {
        tc_log_info(LOG_NOTICE, 0, "firewall socket:%d", fd);

        ev = tc_event_create(fd, tc_nl_event_process, NULL);
        if (ev == NULL) {
            return TC_ERROR;
        }

        if (tc_event_add(event_loop, ev, TC_EVENT_READ) == TC_EVENT_ERROR) {
            return TC_ERROR;
        }
    }


#if (INTERCEPT_THREAD)
    pthread_mutex_init(&mutex, NULL);
    pthread_cond_init(&full, NULL);
    pthread_cond_init(&empty, NULL);
    pthread_create(&thread, NULL, interception_process_msg, NULL);

    pthread_mutex_init(&nl_mutex, NULL);
    pthread_cond_init(&nl_full, NULL);
    pthread_cond_init(&nl_empty, NULL);
    pthread_create(&thread, NULL, interception_dispose_nl_verdict, NULL);
#endif

#endif

    return TC_OK;
}

/* clear resources for interception */
void
interception_over()
{
#if (INTERCEPT_NFQUEUE)   
    tc_log_info(LOG_NOTICE, 0, "unbinding from queue");
    nfq_destroy_queue(srv_settings.nfq_q_handler);
    srv_settings.nfq_q_handler = NULL;
    tc_log_info(LOG_NOTICE, 0, "closing nfq library handle");
    nfq_close(srv_settings.nfq_handler);
    srv_settings.nfq_handler = NULL;
#endif

    router_destroy();
}

