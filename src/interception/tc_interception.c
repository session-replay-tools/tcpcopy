#include <xcopy.h>
#include <intercept.h>

static pid_t           pid;
static uint64_t        tot_copy_resp_packs = 0; 
static uint64_t        tot_resp_packs = 0; 
static uint64_t        tot_router_items = 0; 

#if (!INTERCEPT_NFQUEUE)
static uint32_t        seq = 1;
static unsigned char   buffer[128];
#endif

static int tc_msg_event_process(tc_event_t *rev);

static int
tc_msg_event_accept(tc_event_t *rev)
{
    tc_event_t     *ev;
    register int    fd;
    tunnel_basic_t *tunnel;

    if ((fd = tc_socket_accept(rev->fd)) == TC_INVALID_SOCKET) {
        tc_log_info(LOG_ERR, 0, "msg accept failed, from listen:%d", rev->fd);
        return TC_ERROR;
    }

    tc_log_info(LOG_NOTICE, 0, "it adds fd:%d", fd);

    if (tc_socket_set_nodelay(fd) == TC_ERROR) {
        tc_log_info(LOG_ERR, 0, "Set no delay to socket(%d) failed.", rev->fd);
        tc_log_info(LOG_NOTICE, 0, "it close socket:%d", fd);
        tc_socket_close(fd);
        return TC_ERROR;
    }

#if (TCPCOPY_SINGLE)  
    if (!tc_intercept_check_tunnel_for_single(fd)) {
        tc_log_info(LOG_WARN, 0, "sth tries to connect to server.");
        tc_log_info(LOG_NOTICE, 0, "it close socket:%d", fd);
        tc_socket_close(fd);
        return TC_ERROR;
    }
#endif   

    ev = tc_event_create(fd, tc_msg_event_process, NULL);
    if (ev == NULL) {
        tc_log_info(LOG_ERR, 0, "msg event create failed.");
        return TC_ERROR;
    }

    if (tc_event_add(rev->loop, ev, TC_EVENT_READ) == TC_EVENT_ERROR) {
        return TC_ERROR;
    }
 
    tunnel = srv_settings.tunnel;
    tunnel[fd].ev = ev; 
    tunnel[fd].first_in = 1;
    tunnel[fd].fd_valid = 1;

    return TC_OK;
}

static int 
tc_msg_event_process(tc_event_t *rev)
{
    register int    fd, version;
    msg_client_t    msg;
    tunnel_basic_t *tunnel;

    fd = rev->fd;

    memset(&msg, 0, sizeof(msg_client_t));

    tunnel = srv_settings.tunnel;
    if (tunnel[fd].first_in) {
        if (tc_socket_recv(fd, (char *) &msg, MSG_CLIENT_MIN_SIZE) == 
                TC_ERROR) 
        {
            tc_intercept_release_tunnel(fd, rev);
            return TC_ERROR;
        }

       version = ntohs(msg.type);

        tunnel[fd].first_in = 0;
        if (msg.client_ip != 0 || msg.client_port != 0) {
            tunnel[fd].clt_msg_size = MSG_CLIENT_MIN_SIZE;
            tc_log_info(LOG_WARN, 0, "too old tcpcopy for intercept");
            srv_settings.old = 1;
        } else {
            if (version != INTERNAL_VERSION) {
                tc_log_info(LOG_WARN, 0, 
                        "not compatible,tcpcopy:%d,intercept:%d",
                        msg.type, INTERNAL_VERSION);
            }
            tunnel[fd].clt_msg_size = MSG_CLIENT_SIZE;
            if (tc_socket_recv(fd, ((char *) &msg + MSG_CLIENT_MIN_SIZE), 
                        MSG_CLIENT_SIZE - MSG_CLIENT_MIN_SIZE) == TC_ERROR) 
            {
                tc_intercept_release_tunnel(fd, rev);
                return TC_ERROR;
            }
            return TC_OK;
        }

    } else {
        if (tc_socket_recv(fd, (char *) &msg, tunnel[fd].clt_msg_size) == 
                TC_ERROR) 
        {
            tc_intercept_release_tunnel(fd, rev);
            return TC_ERROR;
        }
    }

    msg.client_ip = msg.client_ip;
    msg.client_port = msg.client_port;
    msg.type = ntohs(msg.type);
    msg.target_ip = msg.target_ip;
    msg.target_port = msg.target_port;

    switch (msg.type) {
        case CLIENT_ADD:
#if (!TCPCOPY_SINGLE)
            tot_router_items++;
            tc_log_debug1(LOG_DEBUG, 0, "add client router:%u",
                          ntohs(msg.client_port));
            router_add(srv_settings.old, msg.client_ip, msg.client_port, 
                    msg.target_ip, msg.target_port, fd);
#endif
            break;
        case CLIENT_DEL:
            tc_log_debug1(LOG_DEBUG, 0, "del client router:%u",
                          ntohs(msg.client_port));
            break;
        default:
            tc_log_info(LOG_WARN, 0, "unknown msg type:%u", msg.type);
    }

    return TC_OK;
}

void
interception_output_stat(tc_event_timer_t *evt)
{
    tc_log_info(LOG_NOTICE, 0, 
            "total resp packs:%llu, all:%llu, route:%llu",
            tot_copy_resp_packs, tot_resp_packs, tot_router_items);
#if (!TCPCOPY_SINGLE)
    router_stat();
    delay_table_delete_obsolete(tc_time());
#endif
    evt->msec = tc_current_time_msec + OUTPUT_INTERVAL;
}

#if (INTERCEPT_COMBINED)
void
interception_push(tc_event_timer_t *evt)
{
    send_buffered_packets();
    evt->msec = tc_current_time_msec + CHECK_INTERVAL;
}
#endif


#if (INTERCEPT_NFQUEUE)
static int tc_nfq_process_packet(struct nfq_q_handle *qh, 
        struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    int                          id = 0, payload_len = 0, ret,
                                 pass_through_flag = 0;
    register int                 i;
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

    ip_hdr = (tc_ip_header_t *) payload;

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
            router_update(srv_settings.old, ip_hdr);

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
    char            buffer[65536];

    if (tc_nfq_socket_recv(rev->fd, buffer, 65536, &rv) == TC_ERROR) {
        return TC_ERROR;
    }

    nfq_handle_packet(srv_settings.nfq_handler, buffer, rv);

    return TC_OK;
}

#else

static int
dispose_netlink_packet(int fd, int verdict, unsigned long packet_id)
{
    struct nlmsghdr        *nl_header = (struct nlmsghdr *) buffer;
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
    ver_data = (struct ipq_verdict_msg *) NLMSG_DATA(nl_header);
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
    if (sendto(fd, (void *) nl_header, nl_header->nlmsg_len, 0,
                (struct sockaddr *) &addr, sizeof(struct sockaddr_nl)) < 0)
    {
        tc_log_info(LOG_ERR, errno, "unable to send mode message");
        return 0;
    }

    return 1;
}


static int
tc_nl_event_process(tc_event_t *rev)
{
    char            buffer[65536];
    register int    i, pass_through_flag = 0;
    unsigned long   packet_id;
    tc_ip_header_t *ip_hdr;

    if (tc_nl_socket_recv(rev->fd, buffer, 65536) == TC_ERROR) 
    {
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

            /* pass through the firewall */
            dispose_netlink_packet(rev->fd, NF_ACCEPT, packet_id);
            
        } else {

            tot_copy_resp_packs++;
            router_update(srv_settings.old, ip_hdr);
            /* drop the packet */
            dispose_netlink_packet(rev->fd, NF_DROP, packet_id);
        }
    }

    return TC_OK;
}

#endif

/* initiate for tcpcopy server */
int
interception_init(tc_event_loop_t *event_loop, char *ip, uint16_t port)
{
    int         fd;
    tc_event_t *ev;

#if (!TCPCOPY_SINGLE)
    delay_table_init(srv_settings.hash_size);
    if (router_init() != TC_OK) {
        return TC_ERROR;
    }
#endif

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
    /* init the nfq socket */
    if ((fd = tc_nfq_socket_init(&srv_settings.nfq_handler, 
                    &srv_settings.nfq_q_handler, tc_nfq_process_packet, 
                    srv_settings.max_queue_len)) 
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

#endif

    return TC_OK;
}

/* clear resources for interception */
void
interception_over()
{
#if (INTERCEPT_NFQUEUE)   

    if (srv_settings.nfq_q_handler != NULL) {
        tc_log_info(LOG_NOTICE, 0, "unbinding from queue");
        nfq_destroy_queue(srv_settings.nfq_q_handler);
        srv_settings.nfq_q_handler = NULL;
    }

    if (srv_settings.nfq_handler != NULL) {
        tc_log_info(LOG_NOTICE, 0, "closing nfq library handle");
        nfq_close(srv_settings.nfq_handler);
        srv_settings.nfq_handler = NULL;
    }
#endif

#if (!TCPCOPY_SINGLE)
    router_destroy();
    delay_table_destroy();
#endif
}

