#include <xcopy.h>
#include <intercept.h>


static uint64_t        tot_copy_resp_packs = 0; 
static uint64_t        tot_resp_packs = 0; 
static uint64_t        tot_router_items = 0; 
#if (TCPCOPY_PCAP)
static  pcap_t        *pcap_map[MAX_FD_NUM];
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
        tc_log_info(LOG_ERR, 0, "Msg event create failed.");
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
    tunnel = srv_settings.tunnel;

    if (tunnel[fd].first_in) {
        if (tc_socket_recv(fd, (char *) &msg, MSG_CLIENT_MIN_SIZE) == 
                TC_ERROR) 
        {
            tc_intercept_release_tunnel(fd, rev);
            return TC_ERROR;
        }

        tunnel[fd].first_in = 0;

        version = ntohs(msg.type);
        if (msg.client_ip != 0 || msg.client_port != 0) {
            tunnel[fd].clt_msg_size = MSG_CLIENT_MIN_SIZE;
            srv_settings.old = 1;
            tc_log_info(LOG_WARN, 0, "client too old for intercept");
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
                    msg.target_ip,  msg.target_port, rev->fd);
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

static int resp_dispose(tc_ip_header_t *ip_header)
{
    uint16_t             port, size_ip, size_tcp, tot_len;
    uint32_t             ip_addr;
    register int         i, passed;
    ip_port_pair_t      *pair;
    tc_tcp_header_t     *tcp_header;

    if (ip_header->protocol != IPPROTO_TCP) {
        return TC_OK;
    }

    tot_resp_packs++;

    size_ip   = ip_header->ihl << 2;
    if (size_ip < 20) {
        tc_log_info(LOG_WARN, 0, "Invalid IP header length: %d", size_ip);
        return TC_OK;
    }

    tot_len   = ntohs(ip_header->tot_len);

    tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);
    size_tcp   = tcp_header->doff << 2;
    if (size_tcp < 20) {
        tc_log_info(LOG_WARN, 0, "Invalid TCP header len: %d bytes,pack len:%d",
                size_tcp, tot_len);
        return TC_OK;
    }

#if (TCPCOPY_PCAP)
    if (srv_settings.user_filter != NULL) {
        passed = 1;
    } else {
        passed = 0;
    }
#else
    passed = 0;
#endif

    ip_addr = ip_header->saddr;
    port    = tcp_header->source;

    if (!passed) {
        /* filter the packets we do care about */
        for (i = 0; i < srv_settings.targets.num; i++) {
            pair = srv_settings.targets.mappings[i];
            if (ip_addr == pair->ip && port == pair->port) {
                passed = 1;
                break;
            } else if (0 == pair->ip && port == pair->port) {
                passed = 1;
                break;
            }
        }

        if (passed == 0) {
            return TC_OK;
        }
    }

    tot_copy_resp_packs++;

    router_update(srv_settings.old, ip_header);
    return TC_OK;

}

#if (TCPCOPY_PCAP)
static void 
pcap_packet_callback(unsigned char *args, const struct pcap_pkthdr *pkt_hdr,
        unsigned char *frame)
{
    pcap_t        *pcap;
    unsigned char *ip_data; 
    int            l2_len;
    
    if (pkt_hdr->len < ETHERNET_HDR_LEN) {
        tc_log_info(LOG_ERR, 0, "recv len is less than:%d", ETHERNET_HDR_LEN);
        return;
    }
    pcap = (pcap_t *) args;
    ip_data = get_ip_data(pcap, frame, pkt_hdr->len, &l2_len);
    resp_dispose((tc_ip_header_t *) ip_data);
}
#endif

static int
tc_process_resp_packet(tc_event_t *rev)
{
#if (TCPCOPY_PCAP)
    pcap_t              *pcap;
#else
    char                 recv_buf[RESP_RECV_BUF_SIZE];
    register int         recv_len;
    tc_ip_header_t      *ip_header;
#endif

#if (TCPCOPY_PCAP)
    pcap = pcap_map[rev->fd];
    pcap_dispatch(pcap, 10, (pcap_handler) pcap_packet_callback, 
            (u_char *) pcap);
#else
    recv_len = recvfrom(rev->fd, recv_buf, 
            RESP_RECV_BUF_SIZE, 0, NULL, NULL);
    if (recv_len == -1) {
        if (errno == EAGAIN) {
            return TC_OK;
        }

        tc_log_info(LOG_ERR, errno, "recvfrom");
        return TC_ERROR;
    }


    if (recv_len < 40) {
        tc_log_info(LOG_ERR, 0, "recv len is less than 40:%d", recv_len);
        return TC_ERROR;
    }

    ip_header = (tc_ip_header_t *) (char *) (recv_buf);
    resp_dispose(ip_header);

#endif
    return TC_OK;
}


#if (TCPCOPY_PCAP)
static int 
tc_device_set(tc_event_loop_t *event_loop, device_t *device) 
{
    int         fd;
    tc_event_t *ev;

    fd = tc_pcap_socket_in_init(&(device->pcap), device->name,
            RESP_RECV_BUF_SIZE, INTERCEPT_PCAP_BUF_SIZE, srv_settings.filter);
    if (fd == TC_INVALID_SOCKET) {
        return TC_ERROR;
    }

    pcap_map[fd] = device->pcap;

    ev = tc_event_create(fd, tc_process_resp_packet, NULL);
    if (ev == NULL) {
        return TC_ERROR;
    }

    if (tc_event_add(event_loop, ev, TC_EVENT_READ) == TC_EVENT_ERROR) {
        tc_log_info(LOG_ERR, 0, "add socket(%d) to event loop failed.", fd);
        return TC_ERROR;
    }

    return TC_OK;
}
#endif

/* sniff response packets in the second test machine */
static int
sniff_init(tc_event_loop_t *event_loop)
{
#if (TCPCOPY_PCAP)
    int         i = 0;
    bool        work = false;
    char        ebuf[PCAP_ERRBUF_SIZE];
    devices_t  *devices;
    pcap_if_t  *alldevs, *d;
#else
   
    int fd;
    tc_event_t *ev;
#endif


#if (TCPCOPY_PCAP)
    devices = &(srv_settings.devices);
    if (srv_settings.raw_device == NULL) {
        if (pcap_findalldevs(&alldevs, ebuf) == -1) {
            tc_log_info(LOG_ERR, 0, "error in pcap_findalldevs:%s", ebuf);
            return TC_ERROR;
        }
        for (d = alldevs; d; d = d->next)
        {
            if (strcmp(d->name, DEFAULT_DEVICE) == 0) {
                continue;
            }

            if (i >= MAX_DEVICE_NUM) {
                pcap_freealldevs(alldevs);
                tc_log_info(LOG_ERR, 0, "It has too many devices");
                return TC_ERROR;
            }

            strcpy(devices->device[i++].name, d->name);
        }
        devices->device_num = i;

        pcap_freealldevs(alldevs);
    }

    for (i = 0; i < devices->device_num; i++) {
        if (tc_device_set(event_loop, &(devices->device[i]))
                == TC_ERROR) 
        {
            tc_log_info(LOG_WARN, 0, "device could not work:%s", 
                    devices->device[i].name);
        } else {
            work = true;
        }
    }

    if (!work) {
        tc_log_info(LOG_ERR, 0, "no device available for snooping packets");
        return TC_ERROR;
    }
#else
    if ((fd = tc_raw_socket_in_init(COPY_FROM_LINK_LAYER)) 
            == TC_INVALID_SOCKET) 
    {
        return TC_ERROR;
    }
    tc_socket_set_nonblocking(fd);

    ev = tc_event_create(fd, tc_process_resp_packet, NULL);
    if (ev == NULL) {
        return TC_ERROR;
    }

    if (tc_event_add(event_loop, ev, TC_EVENT_READ) == TC_EVENT_ERROR) {
        tc_log_info(LOG_ERR, 0, "add socket(%d) to event loop failed.", fd);
        return TC_ERROR;
    }
#endif

    return TC_OK;

}

/* initiate for tcpcopy server */
int
interception_init(tc_event_loop_t *event_loop, char *ip, uint16_t port)
{
    int         fd;
    tc_event_t *ev;

    delay_table_init(srv_settings.hash_size);
    if (router_init() != TC_OK) {
        return TC_ERROR;
    }

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

    
    if (sniff_init(event_loop) != TC_OK) {
        return TC_ERROR;
    }

    return TC_OK;
}

/* clear resources for interception */
void
interception_over()
{
    int i;

    router_destroy();
    delay_table_destroy();

    if (srv_settings.targets.mappings != NULL) {
        for (i = 0; i < srv_settings.targets.num; i++) {
            if (srv_settings.targets.mappings[i] != NULL) {
                free(srv_settings.targets.mappings[i]);
                srv_settings.targets.mappings[i] = NULL;
            }
        }
        free(srv_settings.targets.mappings);
        srv_settings.targets.mappings = NULL;
    }

#if (TCPCOPY_PCAP)
    for (i = 0; i < MAX_FD_NUM; i++) {
        if (pcap_map[i] != NULL) {
            pcap_close(pcap_map[i]);
            pcap_map[i] = NULL;
        }
    }
#endif

}

