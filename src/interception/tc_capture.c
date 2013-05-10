#include <xcopy.h>
#if (INTERCEPT_THREAD)
#include <pthread.h>
#endif
#include <intercept.h>

static uint64_t        tot_copy_resp_packs = 0; 
static uint64_t        tot_resp_packs = 0; 

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
    
    tc_log_info(LOG_NOTICE, 0, "it adds fd:%d", fd);

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

    msg.client_ip = ntohl(msg.client_ip);
    msg.client_port = ntohs(msg.client_port);
    msg.type = ntohs(msg.type);

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

void
interception_output_stat(tc_event_timer_t *evt)
{
    tc_log_info(LOG_NOTICE, 0, "total resp packets:%llu, all:%llu",
            tot_copy_resp_packs, tot_resp_packs);
#if (!TCPCOPY_SINGLE)  
    route_delete_obsolete(tc_time());
#endif
    evt->msec = tc_current_time_msec + OUTPUT_INTERVAL;
}

#if (INTERCEPT_COMBINED)
void
interception_push(tc_event_timer_t *evt)
{
    send_buffered_packets(tc_time());
    evt->msec = tc_current_time_msec + CHECK_INTERVAL;
}
#endif

#if (INTERCEPT_THREAD)
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

    }

    return NULL;
}
#endif

static int
tc_process_resp_packet(tc_event_t *rev)
{
    int                  i, recv_len, threshold, passed;
    char                 recv_buf[RESP_RECV_BUF_SIZE];
    uint16_t             port, size_ip, size_tcp, tot_len;
    uint32_t             ip_addr;
    ip_port_pair_t      *pair;
    tc_ip_header_t      *ip_header;
    tc_tcp_header_t     *tcp_header;
#if (TCPCOPY_PCAP)
    struct ethernet_hdr *ether;
#endif

#if (TCPCOPY_PCAP)
    threshold = ETHERNET_HDR_LEN;
#else
    threshold = 40;
#endif

    for ( ;; ) {

        recv_len = recvfrom(rev->fd, recv_buf, 
                RESP_RECV_BUF_SIZE, 0, NULL, NULL);

        if (recv_len == -1) {
            if (errno == EAGAIN) {
                return TC_OK;
            }

            tc_log_info(LOG_ERR, errno, "recvfrom");
            return TC_ERROR;
        }


        if (recv_len == 0 ||recv_len < threshold) {
            tc_log_info(LOG_ERR, 0, "recv len is 0 or less than threshold");
            return TC_ERROR;
        }

#if (TCPCOPY_PCAP)
        ether = (struct ethernet_hdr *) recv_buf;
        if (ntohs(ether->ether_type) != ETH_P_IP) {
            return TC_OK;
        }

        ip_header = (tc_ip_header_t *) (char *) (recv_buf + ETHERNET_HDR_LEN);
#else
        ip_header = (tc_ip_header_t *) (char *) (recv_buf);
#endif

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

        /* filter the packets we do care about */
        ip_addr = ip_header->saddr;
        port    = tcp_header->source;

        passed = 0;
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

        tot_copy_resp_packs++;

#if (INTERCEPT_THREAD)
        put_resp_header_to_pool(ip_header);
#else
        router_update(srv_settings.router_fd, ip_header);
#endif

    }

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
    bool        work;
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
                tc_log_info(LOG_ERR, 0, "It has too many devices");
                return TC_ERROR;
            }

            strcpy(devices->device[i++].name, d->name);
        }
        devices->device_num = i;
    }

    for (i = 0; i < devices->device_num; i++) {
        if (tc_device_set(event_loop, &(devices->device[i]))
                == TC_ERROR) 
        {
            tc_log_info(LOG_WARN, 0, "device could not work:%s", d->name);
        } else {
            work = true;
        }
    }

    if (work == false) {
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
#if (INTERCEPT_THREAD)
    pthread_t   thread;
#endif
    tc_event_t *ev;

    router_init(srv_settings.hash_size, srv_settings.timeout);

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

    
    sniff_init(event_loop);

#if (INTERCEPT_THREAD)
    tc_pool_init();
    pthread_create(&thread, NULL, interception_process_msg, NULL);

#endif

    return TC_OK;
}

/* clear resources for interception */
void
interception_over()
{
    int i;
#if (INTERCEPT_COMBINED)
    release_combined_resouces();
#endif
    router_destroy();

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

}

