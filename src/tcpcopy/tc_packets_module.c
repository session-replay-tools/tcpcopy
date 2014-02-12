
#include <xcopy.h>
#include <tcpcopy.h>

uint32_t              ip_tf[65536];
uint16_t              ip_tf_cnt = 0;
#if (TCPCOPY_OFFLINE)
static bool           read_pcap_over = false;
static time_t         read_pcap_over_time;
static uint64_t       accumulated_diff = 0, adj_v_pack_diff = 0;
static struct timeval first_pack_time, last_v_pack_time,
                      last_pack_time, base_time, cur_time;
#endif

#if (TCPCOPY_PCAP)
static  pcap_t       *pcap_map[MAX_FD_NUM];
#endif

#if (TCPCOPY_PCAP)
static int tc_process_pcap_socket_packet(tc_event_t *rev);
#else
static int tc_process_raw_socket_packet(tc_event_t *rev);
#endif
static bool process_packet(bool backup, unsigned char *frame, int frame_len);
static void replicate_packs(unsigned char *frame, int frame_len, 
        int replica_num);
static int dispose_packet(unsigned char *frame, int frame_len, int ip_recv_len, 
        int *p_valid_flag);

#if (TCPCOPY_OFFLINE)
static void tc_process_offline_packet(tc_event_timer_t *evt);
static uint64_t timeval_diff(struct timeval *start, struct timeval *cur);
static bool check_read_stop();
static void send_packets_from_pcap(int first);
#endif


static uint16_t
get_ip_key(uint32_t ip)
{
    uint32_t value = (ip >> 16) + ip;
    return (uint16_t) value;
}

static uint32_t 
get_tf_ip(uint16_t key) {

    if (ip_tf[key] == 0) {
        ip_tf[key] = clt_settings.clt_tf_ip[ip_tf_cnt++];
        if (ip_tf_cnt >= clt_settings.clt_tf_ip_num) {
            ip_tf_cnt = 0;
        }
    }

    return ip_tf[key];
}

#if (TCPCOPY_PCAP)
static int 
tc_device_set(tc_event_loop_t *event_loop, device_t *device) 
{
    int         fd;
    tc_event_t *ev;

    fd = tc_pcap_socket_in_init(&(device->pcap), device->name,
            PCAP_RECV_BUF_SIZE, clt_settings.buffer_size, clt_settings.filter);
    if (fd == TC_INVALID_SOCKET) {
        return TC_ERROR;
    }

    pcap_map[fd] = device->pcap;

    ev = tc_event_create(fd, tc_process_pcap_socket_packet, NULL);
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

int
tc_packets_init(tc_event_loop_t *event_loop)
{
#if (!TCPCOPY_PCAP_SEND || !TCPCOPY_PCAP)
    int         fd;
#endif
#if (TCPCOPY_PCAP)
    int         i = 0;
    bool        work = false;
    char        ebuf[PCAP_ERRBUF_SIZE];
    devices_t  *devices;
    pcap_if_t  *alldevs, *d;
#else
    tc_event_t *ev;
#endif

#if (!TCPCOPY_PCAP_SEND)
    /* init the raw socket to send packets */
    if ((fd = tc_raw_socket_out_init()) == TC_INVALID_SOCKET) {
        return TC_ERROR;
    } else {
        tc_raw_socket_out = fd;
    }
#else
    tc_pcap_send_init(clt_settings.output_if_name, clt_settings.mtu);
#endif

#if (TCPCOPY_PCAP)
    devices = &(clt_settings.devices);
    if (clt_settings.raw_device == NULL) {
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
    /* init the raw socket to recv packets */
#if (TCPCOPY_CAPTURE_FROM_LINK)
    if ((fd = tc_raw_socket_in_init(COPY_FROM_LINK_LAYER)) 
            == TC_INVALID_SOCKET) 
#else
    if ((fd = tc_raw_socket_in_init(COPY_FROM_IP_LAYER)) 
            == TC_INVALID_SOCKET) 
#endif
    {
        return TC_ERROR;
    }
    tc_socket_set_nonblocking(fd);

    ev = tc_event_create(fd, tc_process_raw_socket_packet, NULL);
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


#if (TCPCOPY_PCAP)
static void 
pcap_tunnel_retrieve(pcap_t *pcap, const struct pcap_pkthdr *pkt_hdr,
        unsigned char *frame)
{
    int            l2_len = 0, ip_pack_len, frame_len;
    unsigned char *ip_data, tunnel_frame[ETHERNET_HDR_LEN + IP_RECV_BUF_SIZE];

    ip_data = get_ip_data(pcap, frame, pkt_hdr->len, &l2_len); 
    ip_pack_len = pkt_hdr->len - l2_len;

    memcpy(tunnel_frame + ETHERNET_HDR_LEN, ip_data, ip_pack_len);
    frame_len = ip_pack_len + ETHERNET_HDR_LEN;

    dispose_packet(tunnel_frame, frame_len, ip_pack_len, NULL);
}

static void
pcap_retrieve(unsigned char *args, const struct pcap_pkthdr *pkt_hdr,
        unsigned char *frame)
{
    int                  l2_len, ip_pack_len, frame_len;
    pcap_t              *pcap;
    unsigned char       *ip_data; 
    struct ethernet_hdr *ether;

    if (pkt_hdr->len < ETHERNET_HDR_LEN) {
        tc_log_info(LOG_ERR, 0, "recv len is less than:%d", ETHERNET_HDR_LEN);
        return;
    }

    pcap = (pcap_t *) args;
    
    frame_len = pkt_hdr->len;
    l2_len    = get_l2_len(frame, frame_len, pcap_datalink(pcap));

    if (l2_len != ETHERNET_HDR_LEN) {
        if (l2_len > ETHERNET_HDR_LEN) {
           ip_data = get_ip_data(pcap, frame, pkt_hdr->len, &l2_len); 
           frame = ip_data - ETHERNET_HDR_LEN;
           frame_len = frame_len - l2_len + ETHERNET_HDR_LEN;
        } else if (l2_len == 0) {
            /* tunnel frames without ethernet header */
            pcap_tunnel_retrieve(pcap, pkt_hdr, frame);
            return;
        } else {
            tc_log_info(LOG_WARN, 0, "l2 len is %d", l2_len);
            return;
        }
    } else {
        ether = (struct ethernet_hdr *) frame;
        if (ntohs(ether->ether_type) != ETH_P_IP) {
            return;
        }
    }

    ip_pack_len = pkt_hdr->len - l2_len;

    dispose_packet(frame, frame_len, ip_pack_len, NULL);
}

static int
tc_process_pcap_socket_packet(tc_event_t *rev)
{
    pcap_t *pcap;

    pcap = pcap_map[rev->fd];
    pcap_dispatch(pcap, 1, (pcap_handler) pcap_retrieve, (u_char *) pcap);

    return TC_OK;
}

#else
static int
tc_process_raw_socket_packet(tc_event_t *rev)
{
    int  recv_len, frame_len;
    unsigned char frame[ETHERNET_HDR_LEN + IP_RECV_BUF_SIZE];

    for ( ;; ) {

        recv_len = recvfrom(rev->fd, frame + ETHERNET_HDR_LEN, 
                IP_RECV_BUF_SIZE, 0, NULL, NULL);

        if (recv_len == -1) {
            if (errno == EAGAIN) {
                return TC_OK;
            }

            tc_log_info(LOG_ERR, errno, "recvfrom");
            return TC_ERROR;
        }

        if (recv_len == 0) {
            tc_log_info(LOG_ERR, 0, "recv len is 0");
            return TC_ERROR;
        }

        frame_len = ETHERNET_HDR_LEN + recv_len;
        if (dispose_packet(frame, frame_len, recv_len, NULL) == TC_ERROR) {
            return TC_ERROR;
        }
    }

    return TC_OK;
}
#endif

static bool
process_packet(bool backup, unsigned char *frame, int frame_len)
{
    unsigned char tmp[IP_RECV_BUF_SIZE + ETHERNET_HDR_LEN];

    if (!backup) {

        return process_in(frame);
    } else {
        memcpy(tmp, frame, frame_len);

        return process_in(tmp);
    }
}



#if (TCPCOPY_UDP)
static void
replicate_packs(unsigned char *frame, int frame_len, int replica_num)
{
    int              i;
    uint32_t         size_ip;
    uint16_t         orig_port, addition, dest_port, rand_port;
    unsigned char   *packet;
    tc_ip_header_t  *ip_header;
    tc_udp_header_t *udp_header;

    packet     = frame + ETHERNET_HDR_LEN;
    ip_header  = (tc_ip_header_t *) packet;
    size_ip    = ip_header->ihl << 2;
    udp_header = (tc_udp_header_t *) ((char *) ip_header + size_ip);
    orig_port  = ntohs(udp_header->source);

    tc_log_debug1(LOG_DEBUG, 0, "orig port:%u", orig_port);

    rand_port = clt_settings.rand_port_shifted;
    for (i = 1; i < replica_num; i++) {
        addition   = (((i << 1) - 1) << 5) + rand_port;
        dest_port  = get_appropriate_port(orig_port, addition);

        tc_log_debug2(LOG_DEBUG, 0, "new port:%u,add:%u", dest_port, addition);

        udp_header->source = htons(dest_port);
        process_packet(true, frame, frame_len);
    }
}

static int
dispose_packet(unsigned char *frame, int frame_len, int ip_recv_len, 
        int *p_valid_flag)
{
    int             replica_num;
    bool            packet_valid = false;
    unsigned char  *packet;
    tc_ip_header_t *ip_header;

    packet = frame + ETHERNET_HDR_LEN;

    if (is_packet_needed(packet)) {

        replica_num = clt_settings.replica_num;
        ip_header   = (tc_ip_header_t *) packet;

        if (clt_settings.clt_tf_ip_num > 0) {
            ip_header->saddr = get_tf_ip(get_ip_key(ip_header->saddr));
        }

        if (replica_num > 1) {
            packet_valid = process_packet(true, frame, frame_len);
            replicate_packs(frame, frame_len, replica_num);
        } else {
            packet_valid = process_packet(false, frame, frame_len);
        }
    }

    if (p_valid_flag) {
        *p_valid_flag = (packet_valid == true ? 1 : 0);
    }

    return TC_OK;  
}

#else

/* replicate packets for multiple-copying */
static void
replicate_packs(unsigned char *frame, int frame_len, int replica_num)
{
    int               i;
    uint16_t          orig_port, addition, dest_port, rand_port;
    uint32_t          size_ip;
    unsigned char    *packet;
    tc_tcp_header_t  *tcp_header;
    tc_ip_header_t   *ip_header;
    
    packet     = frame + ETHERNET_HDR_LEN;
    ip_header  = (tc_ip_header_t *) packet;
    size_ip    = ip_header->ihl << 2;
    tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);
    rand_port  = clt_settings.rand_port_shifted;
    orig_port  = ntohs(tcp_header->source);

    tc_log_debug1(LOG_DEBUG, 0, "orig port:%u", orig_port);

    for (i = 1; i < replica_num; i++) {

        addition   = (((i << 1) - 1) << 5) + rand_port;
        dest_port  = get_appropriate_port(orig_port, addition);
        tcp_header->source = htons(dest_port);
        process_packet(true, frame, frame_len);

        tc_log_debug2(LOG_DEBUG, 0, "new port:%u,add:%u", dest_port, addition);
    }
}

static int
dispose_packet(unsigned char *frame, int frame_len, int ip_recv_len,
        int *p_valid_flag)
{
    int              replica_num, i, last, packet_num, max_payload,
                     index, payload_len;
    char             *p, buf[ETHERNET_HDR_LEN + IP_RECV_BUF_SIZE];
    bool             packet_valid = false;
    uint16_t         id, size_ip, size_tcp, tot_len, cont_len, 
                     pack_len = 0, head_len;
    uint32_t         seq;
    unsigned char   *packet;
    tc_ip_header_t  *ip_header;
    tc_tcp_header_t *tcp_header;

    packet = frame + ETHERNET_HDR_LEN;

    if (is_packet_needed(packet)) {

        replica_num = clt_settings.replica_num;
        ip_header   = (tc_ip_header_t *) packet;

        if (clt_settings.clt_tf_ip_num > 0) {
            ip_header->saddr = get_tf_ip(get_ip_key(ip_header->saddr));
        }

        /* 
         * If the packet length is larger than MTU, we split it. 
         */
        if (ip_recv_len > clt_settings.mtu) {

            /* calculate number of packets */
            size_ip     = ip_header->ihl << 2;
            tot_len     = ntohs(ip_header -> tot_len);
            if (tot_len != ip_recv_len) {
                tc_log_info(LOG_WARN, 0, "packet len:%u, recv len:%u",
                            tot_len, ip_recv_len);
                return TC_ERROR;
            }

            tcp_header  = (tc_tcp_header_t *) ((char *) ip_header + size_ip);
            size_tcp    = tcp_header->doff << 2;
            cont_len    = tot_len - size_tcp - size_ip;
            head_len    = size_ip + size_tcp;
            max_payload = clt_settings.mtu - head_len;
            packet_num  = (cont_len + max_payload - 1)/max_payload;
            seq         = ntohl(tcp_header->seq);
            last        = packet_num - 1;
            id          = ip_header->id;

#if (TCPCOPY_DEBUG)
            tc_log_trace(LOG_NOTICE, 0, CLIENT_FLAG, ip_header, tcp_header);
#endif
            tc_log_debug1(LOG_DEBUG, 0, "recv:%d, more than MTU", ip_recv_len);
            index = head_len;

            for (i = 0 ; i < packet_num; i++) {
                tcp_header->seq = htonl(seq + i * max_payload);
                if (i != last) {
                    pack_len  = clt_settings.mtu;
                } else {
                    pack_len += (cont_len - packet_num * max_payload);
                }
                payload_len = pack_len - head_len;
                ip_header->tot_len = htons(pack_len);
                ip_header->id = id++;
                p = buf + ETHERNET_HDR_LEN;
                /* copy header here */
                memcpy(p, (char *) packet, head_len);
                p +=  head_len;
                /* copy payload here */
                memcpy(p, (char *) (packet + index), payload_len);
                index = index + payload_len;
                if (replica_num > 1) {
                    packet_valid = process_packet(true, (unsigned char *) buf,
                            ETHERNET_HDR_LEN + pack_len);
                    replicate_packs((unsigned char *) buf, 
                            ETHERNET_HDR_LEN + pack_len, replica_num);
                } else {
                    packet_valid = process_packet(false, (unsigned char *) buf,
                            ETHERNET_HDR_LEN + pack_len);
                }
            }
        } else {

            if (replica_num > 1) {

                packet_valid = process_packet(true, frame, frame_len);
                replicate_packs(frame, frame_len, replica_num);
            } else {

                packet_valid = process_packet(false, frame, frame_len);
            }
        }
    }

    if (p_valid_flag) {
        *p_valid_flag = (packet_valid == true ? 1 : 0);
    }

    return TC_OK;
}
#endif

#if (TCPCOPY_OFFLINE)
int
tc_offline_init(tc_event_loop_t *event_loop, char *pcap_file)
{
#if (!TCPCOPY_PCAP_SEND)
    int  fd;
#endif
    char ebuf[PCAP_ERRBUF_SIZE];

#if (!TCPCOPY_PCAP_SEND)
    /* init the raw socket to send */
    if ((fd = tc_raw_socket_out_init()) == TC_INVALID_SOCKET) {
        return TC_ERROR;
    } else {
        tc_raw_socket_out = fd;
    }
#else
    tc_pcap_send_init(clt_settings.output_if_name, clt_settings.mtu);
#endif

    if (pcap_file == NULL) {
        return TC_ERROR;
    }

    if ((clt_settings.pcap = pcap_open_offline(pcap_file, ebuf)) == NULL) {
        tc_log_info(LOG_ERR, 0, "open %s" , ebuf);
        fprintf(stderr, "open %s\n", ebuf);
        return TC_ERROR;
    }

    gettimeofday(&base_time, NULL);
    tc_log_info(LOG_NOTICE, 0, "open pcap success:%s", pcap_file);
    tc_log_info(LOG_NOTICE, 0, "send the first packets here");
    send_packets_from_pcap(1);

    /* register a timer for offline */
    tc_event_timer_add(event_loop, 0, tc_process_offline_packet);

    return TC_OK;
}

static void
tc_process_offline_packet(tc_event_timer_t *evt)
{
    int diff = 0;  

    if (!read_pcap_over) {
        send_packets_from_pcap(0);
    } else {
        diff = tc_time() - read_pcap_over_time;
        if (diff > OFFLINE_TAIL_TIMEOUT) {
            tc_over = SIGRTMAX;
            tc_log_info(LOG_NOTICE, 0, "offline replay is complete");
        }
    }

    evt->msec = tc_current_time_msec;
}

static uint64_t
timeval_diff(struct timeval *start, struct timeval *cur)
{
    int64_t usec;

    usec  = cur->tv_sec - start->tv_sec;
    usec  = usec * 1000000;
    usec += cur->tv_usec - start->tv_usec;

    if (usec < 0) {
        tc_log_info(LOG_NOTICE, 0, "usec is less than 0:%lld", usec);
        return 0;
    }

    return (uint64_t) usec;
}

static bool
check_read_stop()
{
    uint64_t diff, history_diff, cur_diff;

    history_diff = timeval_diff(&first_pack_time, &last_pack_time);
    cur_diff     = timeval_diff(&base_time, &cur_time);

    if (clt_settings.accelerated_times > 1) {
        cur_diff = cur_diff * clt_settings.accelerated_times;
    }

    if (clt_settings.interval > 0) {
        if (adj_v_pack_diff > 0 && adj_v_pack_diff > clt_settings.interval) {
            accumulated_diff += adj_v_pack_diff;
            tc_log_info(LOG_NOTICE, 0, "accumulated time saved:%llu",
                    accumulated_diff);
        }
        cur_diff = cur_diff + accumulated_diff;
    }


    if (history_diff <= cur_diff) {
        return false;
    }

    diff = history_diff - cur_diff;
    if (diff > 0) {
        return true;
    }

    return false;
}

static void 
send_packets_from_pcap(int first)
{
    int                 l2_len, ip_pack_len, p_valid_flag = 0;
    bool                stop;
    pcap_t             *pcap;
    unsigned char      *pkt_data, *frame, *ip_data;
    struct pcap_pkthdr  pkt_hdr;  

    pcap = clt_settings.pcap;

    if (pcap == NULL) {
        return;
    }

    gettimeofday(&cur_time, NULL);

    stop = check_read_stop();

    while (!stop) {

        pkt_data = (u_char *) pcap_next(pcap, &pkt_hdr);
        if (pkt_data != NULL) {

            if (pkt_hdr.caplen < pkt_hdr.len) {

                tc_log_info(LOG_WARN, 0, "truncated packets,drop");
            } else {

                ip_data = get_ip_data(pcap, pkt_data, pkt_hdr.len, &l2_len);
                if (l2_len < ETHERNET_HDR_LEN) {
                    tc_log_info(LOG_WARN, 0, "l2 len is %d", l2_len);
                    continue;
                }

                last_pack_time = pkt_hdr.ts;
                if (ip_data != NULL) {
                    clt_settings.pcap_time = last_pack_time.tv_sec * 1000 + 
                        last_pack_time.tv_usec / 1000; 

                    ip_pack_len = pkt_hdr.len - l2_len;
                    tc_log_debug2(LOG_DEBUG, 0, "frame len:%d, ip len:%d",
                            pkt_hdr.len, ip_pack_len);
                    frame = ip_data - ETHERNET_HDR_LEN;
                    dispose_packet(frame, ip_pack_len + ETHERNET_HDR_LEN,
                            ip_pack_len, &p_valid_flag);
                    if (p_valid_flag) {

                        tc_log_debug0(LOG_DEBUG, 0, "valid flag for packet");

                        if (first) {
                            first_pack_time = pkt_hdr.ts;
                            first = 0;
                        } else {
                            adj_v_pack_diff = timeval_diff(&last_v_pack_time,
                                    &last_pack_time);
                        }

                        /* set last valid packet time in pcap file */
                        last_v_pack_time = last_pack_time;

                        stop = check_read_stop();

                    } else {
                        tc_log_debug0(LOG_DEBUG, 0, "invalid flag");
                    }
                }
            }
        } else {

            tc_log_info(LOG_NOTICE, 0, "stop, null from pcap_next");
            stop = true;
            read_pcap_over = true;
            read_pcap_over_time = tc_time();
        }
    }
}
#endif /* TCPCOPY_OFFLINE */

