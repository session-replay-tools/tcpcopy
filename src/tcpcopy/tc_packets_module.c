
#include <xcopy.h>
#include <tcpcopy.h>

#if (TC_OFFLINE)
static bool           read_pcap_over = false;
static time_t         read_pcap_over_time;
static uint64_t       accumulated_diff = 0, adj_v_pack_df = 0;
static struct timeval first_pack_time, last_v_pack_time,
                      last_pack_time, base_time, cur_time;

static void proc_offline_pack(tc_event_timer_t *);
static bool check_read_stop();
static void send_packets_from_pcap(int);
static uint64_t timeval_diff(struct timeval *, struct timeval *);
#endif

#if (TC_PCAP)
static  pcap_t  *pcap_map[MAX_FD_NUM];
static int proc_pcap_pack(tc_event_t *);
#else
static int proc_raw_pack(tc_event_t *);
#endif
static int dispose_packet(unsigned char *, int, int *);


#if (TC_PCAP)
static int 
device_set(tc_event_loop_t *event_loop, device_t *device) 
{
    int         fd;
    tc_event_t *ev;

    fd = tc_pcap_socket_in_init(&(device->pcap), device->name,
            clt_settings.snaplen, clt_settings.buffer_size, 
            clt_settings.filter);
    if (fd == TC_INVALID_SOCK) {
        return TC_ERR;
    }

    pcap_map[fd] = device->pcap;

    ev = tc_event_create(event_loop->pool, fd, proc_pcap_pack, NULL);
    if (ev == NULL) {
        return TC_ERR;
    }

    if (tc_event_add(event_loop, ev, TC_EVENT_READ) == TC_EVENT_ERROR) {
        tc_log_info(LOG_ERR, 0, "add socket(%d) to event loop failed.", fd);
        return TC_ERR;
    }

    return TC_OK;
}
#endif


int
tc_packets_init(tc_event_loop_t *event_loop)
{
#if (!TC_PCAP_SND || !TC_PCAP)
    int         fd;
#endif
#if (TC_PCAP)
    int         i;
    bool        work;
    char        ebuf[PCAP_ERRBUF_SIZE];
    devices_t  *devices;
    pcap_if_t  *alldevs, *d;
#else
    tc_event_t *ev;
#endif

#if (!TC_PCAP_SND)
    /* init the raw socket to send packets */
    if ((fd = tc_raw_socket_out_init()) == TC_INVALID_SOCK) {
        return TC_ERR;
    } else {
        tc_raw_socket_out = fd;
    }
#else
    if (tc_pcap_snd_init(clt_settings.output_if_name, clt_settings.mtu) !=
            TC_OK) 
    {
        return TC_ERR;
    }
#endif

#if (TC_PCAP)
    devices = &(clt_settings.devices);
    if (clt_settings.raw_device == NULL) {
        if (pcap_findalldevs(&alldevs, ebuf) == -1) {
            tc_log_info(LOG_ERR, 0, "error in pcap_findalldevs:%s", ebuf);
            return TC_ERR;
        }
        
        i = 0;
        for (d = alldevs; d; d = d->next)
        {
            if (strcmp(d->name, DEFAULT_DEVICE) == 0) {
                continue;
            }

            if (i >= MAX_DEVICE_NUM) {
                pcap_freealldevs(alldevs);
                tc_log_info(LOG_ERR, 0, "too many devices");
                return TC_ERR;
            }

            strcpy(devices->device[i++].name, d->name);
        }
        devices->device_num = i;
        pcap_freealldevs(alldevs);
    }

    work = false;
    for (i = 0; i < devices->device_num; i++) {
        if (device_set(event_loop, &(devices->device[i]))
                == TC_ERR) 
        {
            tc_log_info(LOG_WARN, 0, "device could not work:%s", 
                    devices->device[i].name);
        } else {
            work = true;
        }
    }

    if (!work) {
        tc_log_info(LOG_ERR, 0, "no device available for snooping packets");
        return TC_ERR;
    }

#else
    /* init the raw socket to recv packets */
    if ((fd = tc_raw_socket_in_init(COPY_FROM_IP_LAYER)) == TC_INVALID_SOCK) {
        return TC_ERR;
    }
    tc_socket_set_nonblocking(fd);

    ev = tc_event_create(event_loop->pool, fd, proc_raw_pack, NULL);
    if (ev == NULL) {
        return TC_ERR;
    }

    if (tc_event_add(event_loop, ev, TC_EVENT_READ) == TC_EVENT_ERROR) {
        tc_log_info(LOG_ERR, 0, "add socket(%d) to event loop failed.", fd);
        return TC_ERR;
    }
#endif

    return TC_OK;
}


#if (TC_PCAP)

static void
pcap_retrieve(unsigned char *args, const struct pcap_pkthdr *pkt_hdr,
        unsigned char *frame)
{
    int                  l2_len, ip_pack_len;
    pcap_t              *pcap;
    unsigned char       *ip_data; 
    struct ethernet_hdr *ether;

    if (pkt_hdr->len < ETHERNET_HDR_LEN) {
        tc_log_info(LOG_ERR, 0, "recv len is less than:%d", ETHERNET_HDR_LEN);
        return;
    }

    ip_data = NULL;
    pcap = (pcap_t *) args;
    
    l2_len    = get_l2_len(frame, pcap_datalink(pcap));

    if (l2_len != ETHERNET_HDR_LEN) {
        if ((size_t) l2_len > ETHERNET_HDR_LEN) {
            ip_data = get_ip_data(pcap, frame, pkt_hdr->len, &l2_len); 
        } else if (l2_len == 0) {
            /* tunnel frames without ethernet header */
            ip_data = get_ip_data(pcap, frame, pkt_hdr->len, &l2_len); 
        } else {
            tc_log_info(LOG_WARN, 0, "l2 len is %d", l2_len);
            return;
        }
    } else {
        ether = (struct ethernet_hdr *) frame;
        if (ntohs(ether->ether_type) != ETH_P_IP) {
            return;
        }
        ip_data = get_ip_data(pcap, frame, pkt_hdr->len, &l2_len); 
    }

    ip_pack_len = pkt_hdr->len - l2_len;

    dispose_packet(ip_data, ip_pack_len, NULL);
}


static int
proc_pcap_pack(tc_event_t *rev)
{
    pcap_t *pcap;

    pcap = pcap_map[rev->fd];
    pcap_dispatch(pcap, 10, (pcap_handler) pcap_retrieve, (u_char *) pcap);

    return TC_OK;
}

#else

static unsigned char pack_buffer1[IP_RCV_BUF_SIZE];

static int 
proc_raw_pack(tc_event_t *rev)
{
    int            recv_len;
    unsigned char *packet;

    packet = pack_buffer1;

    for ( ;; ) {

        recv_len = recvfrom(rev->fd, packet, IP_RCV_BUF_SIZE, 0, NULL, NULL);

        if (recv_len == -1) {
            if (errno == EAGAIN) {
                return TC_OK;
            }

            tc_log_info(LOG_ERR, errno, "recvfrom");
            return TC_ERR;
        }

        if (recv_len == 0) {
            tc_log_info(LOG_ERR, 0, "recv len is 0");
            return TC_ERR;
        }

        if (dispose_packet(packet, recv_len, NULL) == TC_ERR) {
            return TC_ERR;
        }
    }

    return TC_OK;
}
#endif


#if (TC_UDP)
static void
replicate_packs(tc_iph_t *ip, tc_udpt_t *udp_header, int replica_num)
{
    int       i;
    uint16_t  orig_port, addition, dest_port, rand_port;

    orig_port  = ntohs(udp_header->source);

    tc_log_debug1(LOG_DEBUG, 0, "orig port:%u", orig_port);

    rand_port = clt_settings.rand_port_shifted;
    for (i = 1; i < replica_num; i++) {
        addition   = (((i << 1) - 1) << 5) + rand_port;
        dest_port  = get_appropriate_port(orig_port, addition);

        tc_log_debug2(LOG_DEBUG, 0, "new port:%u,add:%u", dest_port, addition);

        udp_header->source = htons(dest_port);
        tc_proc_ingress(ip, udp_header);
    }
}


static int
dispose_packet(unsigned char *packet, int ip_rcv_len, int *p_valid_flag)
{
    int        replica_num;
    bool       packet_valid;
    uint16_t   size_ip;
    tc_iph_t  *ip;
    tc_udpt_t *udp_header;

    if (p_valid_flag) {
        packet_valid = false;
    }

    ip = (tc_iph_t *) packet;

    if (tc_check_ingress_pack_needed(ip)) {

        replica_num = clt_settings.replica_num;
        ip   = (tc_iph_t *) packet;

        size_ip     = ip->ihl << 2;
        udp_header  = (tc_udpt_t *) ((char *) ip + size_ip);

        packet_valid = tc_proc_ingress(ip, udp_header);
          
        if (replica_num > 1) {
            replicate_packs(ip, udp_header, replica_num);
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
replicate_packs(tc_iph_t *ip, tc_tcph_t *tcp, int replica_num)
{
    int       i;
    uint16_t  tf_key, orig_port, addition, dest_port, rand_port;
    
    rand_port  = clt_settings.rand_port_shifted;
    orig_port  = ntohs(tcp->source);

    for (i = 1; i < replica_num; i++) {

        addition   = (((i << 1) - 1) << 5) + rand_port;
        dest_port  = get_appropriate_port(orig_port, addition);
        tcp->source = htons(dest_port);
        if (clt_settings.clt_tf_ip_num > 0) {
            tf_key = get_ip_key((ip->saddr << 1) + addition);
            ip->saddr = get_tf_ip(tf_key);
        }
        tc_proc_ingress(ip, tcp);
    }
}


static unsigned char pack_buffer2[IP_RCV_BUF_SIZE];

static int
dispose_packet(unsigned char *packet, int ip_rcv_len, int *p_valid_flag)
{
    int        replica_num, i, last, packet_num, max_payload,
               index, payload_len;
    char      *p;
    bool       packet_valid;
    uint16_t   id, size_ip, size_tcp, tot_len, cont_len, 
               pack_len, head_len;
    uint32_t   seq;
    tc_iph_t  *ip;
    tc_tcph_t *tcp;

    if (p_valid_flag) {
        packet_valid = false;
    }

    ip   = (tc_iph_t *) packet;
    if (tc_check_ingress_pack_needed(ip)) {

        replica_num = clt_settings.replica_num;
        size_ip     = ip->ihl << 2;
        tcp  = (tc_tcph_t *) ((char *) ip + size_ip);

        if (ip_rcv_len <= clt_settings.mtu) {
            packet_valid = tc_proc_ingress(ip, tcp);
            if (replica_num > 1) {
                replicate_packs(ip, tcp, replica_num);
            }

        } else {

            tot_len     = ntohs(ip -> tot_len);
            if (tot_len != ip_rcv_len) {
                tc_log_info(LOG_WARN, 0, "packet len:%u, recv len:%u",
                            tot_len, ip_rcv_len);
                return TC_ERR;
            }

            size_tcp    = tcp->doff << 2;
            cont_len    = tot_len - size_tcp - size_ip;
            head_len    = size_ip + size_tcp;
            max_payload = clt_settings.mtu - head_len;
            packet_num  = (cont_len + max_payload - 1)/max_payload;
            seq         = ntohl(tcp->seq);
            last        = packet_num - 1;
            id          = ip->id;

#if (TC_DEBUG)
            tc_log_trace(LOG_NOTICE, 0, TC_CLT, ip, tcp);
#endif
            tc_log_debug1(LOG_DEBUG, 0, "recv:%d, more than MTU", ip_rcv_len);
            index = head_len;

            pack_len = 0;
            for (i = 0 ; i < packet_num; i++) {
                tcp->seq = htonl(seq + i * max_payload);
                if (i != last) {
                    pack_len  = clt_settings.mtu;
                } else {
                    pack_len += (cont_len - packet_num * max_payload);
                }
                payload_len = pack_len - head_len;
                ip->tot_len = htons(pack_len);
                ip->id = id++;
                p = (char *) pack_buffer2;
                /* copy header here */
                memcpy(p, (char *) packet, head_len);
                p +=  head_len;
                /* copy payload here */
                memcpy(p, (char *) (packet + index), payload_len);
                index = index + payload_len;
                packet_valid = tc_proc_ingress(ip, tcp);
                if (replica_num > 1) {
                    replicate_packs(ip, tcp, replica_num);
                }
            }
        }
    }

    if (p_valid_flag) {
        *p_valid_flag = (packet_valid == true ? 1 : 0);
    }

    return TC_OK;
}
#endif


#if (TC_OFFLINE)
int
tc_offline_init(tc_event_loop_t *event_loop, char *pcap_file)
{
#if (!TC_PCAP_SND)
    int  fd;
#endif
    char ebuf[PCAP_ERRBUF_SIZE];

#if (!TC_PCAP_SND)
    /* init the raw socket to send */
    if ((fd = tc_raw_socket_out_init()) == TC_INVALID_SOCK) {
        return TC_ERR;
    } else {
        tc_raw_socket_out = fd;
    }
#else
    tc_pcap_snd_init(clt_settings.output_if_name, clt_settings.mtu);
#endif

    if (pcap_file == NULL) {
        return TC_ERR;
    }

    if ((clt_settings.pcap = pcap_open_offline(pcap_file, ebuf)) == NULL) {
        tc_log_info(LOG_ERR, 0, "open %s" , ebuf);
        fprintf(stderr, "open %s\n", ebuf);
        return TC_ERR;
    }

    gettimeofday(&base_time, NULL);
    tc_log_info(LOG_NOTICE, 0, "open pcap success:%s", pcap_file);
    tc_log_info(LOG_NOTICE, 0, "send the first packets here");
    send_packets_from_pcap(1);

    /* register a timer for offline */
    tc_event_add_timer(event_loop->pool, OFFLINE_ACTIVATE_INTERVAL, 
            NULL, proc_offline_pack);

    return TC_OK;
}


static void
proc_offline_pack(tc_event_timer_t *evt)
{
    int diff;  

    if (!read_pcap_over) {
        send_packets_from_pcap(0);
    } else {
        diff = tc_time() - read_pcap_over_time;
        if (diff > OFFLINE_TAIL_TIMEOUT) {
            tc_over = SIGRTMAX;
            tc_log_info(LOG_NOTICE, 0, "offline replay is complete");
        }
    }

    tc_event_update_timer(evt, OFFLINE_ACTIVATE_INTERVAL);
}


static uint64_t
timeval_diff(struct timeval *start, struct timeval *cur)
{
    int64_t usec;

    usec  = cur->tv_sec - start->tv_sec;
    usec  = usec * 1000000;
    usec += cur->tv_usec - start->tv_usec;

    if (usec > 0) {
        return (uint64_t) usec;
    } else {
        return 0;
    }
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
        if (adj_v_pack_df > 0 && adj_v_pack_df > clt_settings.interval) {
            accumulated_diff += adj_v_pack_df;
            tc_log_debug1(LOG_INFO, 0, "accumulated time saved:%llu",
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
    unsigned char      *pkt_data, *ip_data;
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

            if (pkt_hdr.caplen >= pkt_hdr.len) {

                ip_data = get_ip_data(pcap, pkt_data, pkt_hdr.len, &l2_len);
                if ((size_t) l2_len >= ETHERNET_HDR_LEN) {
                    last_pack_time = pkt_hdr.ts;
                    if (ip_data != NULL) {
                        clt_settings.pcap_time = last_pack_time.tv_sec * 1000 +
                            last_pack_time.tv_usec / 1000; 

                        ip_pack_len = pkt_hdr.len - l2_len;
                        dispose_packet(ip_data, ip_pack_len, &p_valid_flag);
                        if (p_valid_flag) {

                            if (!first) {
                                adj_v_pack_df = timeval_diff(&last_v_pack_time,
                                        &last_pack_time);
                            } else {
                                first_pack_time = pkt_hdr.ts;
                                first = 0;
                            }

                            /* set last valid packet time in pcap file */
                            last_v_pack_time = last_pack_time;

                            stop = check_read_stop();
                        }
                    }

                } else {
                    tc_log_info(LOG_WARN, 0, "l2 len is %d", l2_len);
                }

            } else {

                tc_log_info(LOG_WARN, 0, "truncated packets,drop");
            }
        } else {

            tc_log_info(LOG_NOTICE, 0, "stop, null from pcap_next");
            stop = true;
            read_pcap_over = true;
            read_pcap_over_time = tc_time();
        }
    }
}
#endif /* TC_OFFLINE */

