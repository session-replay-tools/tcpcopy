
#include <xcopy.h>
#include <tcpcopy.h>

#if (TCPCOPY_OFFLINE)
static bool           read_pcap_over= false;
static pcap_t        *pcap = NULL;
static struct timeval first_pack_time, last_pack_time, base_time, cur_time;
#endif

static int tc_process_raw_socket_packet(tc_event_t *rev);
static bool process_packet(bool backup, char *packet, int length);
static void replicate_packs(char *packet, int length, int replica_num);
static int dispose_packet(char *recv_buf, int recv_len, int *p_valid_flag);

#if (TCPCOPY_OFFLINE)
static void tc_process_offline_packet(tc_event_timer_t *evt);
static uint64_t timeval_diff(struct timeval *start, struct timeval *cur);
static bool check_read_stop();
static int get_l2_len(const unsigned char *packet, const int pkt_len,
        const int datalink);
static unsigned char * get_ip_data(unsigned char *packet, const int pkt_len,
        int *p_l2_len);
static void send_packets_from_pcap(int first);
#endif

int
tc_packets_init(tc_event_loop_t *event_loop)
{
    int         fd;
    tc_event_t *ev;

    /* Init the raw socket to send packets */
    if ((fd = tc_raw_socket_out_init()) == TC_INVALID_SOCKET) {
        return TC_ERROR;
    } else {
        tc_raw_socket_out = fd;
    }

    /* Init the raw socket to recv packets */
    if ((fd = tc_raw_socket_in_init()) == TC_INVALID_SOCKET) {
        return TC_ERROR;
    }

    tc_socket_set_nonblocking(fd);

    ev = tc_event_create(fd, tc_process_raw_socket_packet, NULL);
    if (ev == NULL) {
        return TC_ERROR;
    }

    if (tc_event_add(event_loop, ev, TC_EVENT_READ) == TC_EVENT_ERROR) {
        tc_log_info(LOG_ERR, 0, "add raw socket(%d) to event loop failed.", fd);
        return TC_ERROR;
    }

    return TC_OK;
}

static int
tc_process_raw_socket_packet(tc_event_t *rev)
{
    int  recv_len;
    char recv_buf[RECV_BUF_SIZE];

    for ( ;; ) {

        recv_len = recvfrom(rev->fd, recv_buf, RECV_BUF_SIZE, 0, NULL, NULL);

        if (recv_len == -1) {
            tc_log_info(LOG_ERR, errno, "recvfrom");
            return TC_ERROR;
        }

        if (recv_len == 0) {
            tc_log_info(LOG_ERR, 0, "recv len is 0");
            return TC_ERROR;
        }

        if (dispose_packet(recv_buf, recv_len, NULL) == TC_ERROR) {
            return TC_ERROR;
        }
    }

    return TC_OK;
}

static bool
process_packet(bool backup, char *packet, int length)
{
    char tmp_packet[RECV_BUF_SIZE];

    if (!backup) {
        return process(packet, LOCAL);

    } else {
        memcpy(tmp_packet, packet, length);

        return process(tmp_packet, LOCAL);
    }
}

/* Replicate packets for multiple-copying */
static void
replicate_packs(char *packet, int length, int replica_num)
{
    int             i;
    uint16_t        orig_port, addition, dest_port, rand_port;
    uint32_t        size_ip;
    struct tcphdr  *tcp_header;
    struct iphdr   *ip_header;
    
    ip_header  = (struct iphdr*)packet;
    size_ip    = ip_header->ihl << 2;
    tcp_header = (struct tcphdr*)((char *)ip_header + size_ip);
    rand_port  = clt_settings.rand_port_shifted;
    orig_port  = ntohs(tcp_header->source);

    tc_log_debug1(LOG_DEBUG, 0, "orig port:%u", orig_port);

    for (i = 1; i < replica_num; i++) {

        addition   = (((i << 1) - 1) << 5) + rand_port;
        dest_port  = get_appropriate_port(orig_port, addition);
        tcp_header->source = htons(dest_port);
        process_packet(true, packet, length);

        tc_log_debug2(LOG_DEBUG, 0, "new port:%u,add:%u", dest_port, addition);
    }
}

static int
dispose_packet(char *recv_buf, int recv_len, int *p_valid_flag)
{
    int             replica_num, i, last, packet_num, max_payload,
                    index, payload_len;
    char           *packet, tmp_buf[RECV_BUF_SIZE];
    bool            packet_valid = false;
    uint16_t        id, size_ip, size_tcp, tot_len, cont_len, 
                    pack_len = 0, head_len;
    uint32_t        seq;
    struct tcphdr  *tcp_header;
    struct iphdr   *ip_header;

    packet = recv_buf;

    if (is_packet_needed((const char *)packet)) {

        replica_num = clt_settings.replica_num;
        packet_num = 1;
        ip_header   = (struct iphdr*)packet;

        if (localhost == ip_header->saddr) {
            if (0 != clt_settings.lo_tf_ip) {
                ip_header->saddr = clt_settings.lo_tf_ip;
            }
        }

        /* 
         * If packet length larger than MTU, then we split it. 
         * This is to solve the ip fragmentation problem
         */
        if (recv_len > clt_settings.mtu) {

            /* Calculate number of packets */
            size_ip     = ip_header->ihl << 2;
            tot_len     = ntohs(ip_header -> tot_len);
            if (tot_len != recv_len) {
                tc_log_info(LOG_WARN, 0, "packet len:%u, recv len:%u",
                            tot_len, recv_len);
                return TC_ERROR;
            }

            tcp_header  = (struct tcphdr*)((char *)ip_header + size_ip);
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
            tc_log_debug1(LOG_DEBUG, 0, "recv:%d, more than MTU", recv_len);
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
                /* Copy header here */
                memcpy(tmp_buf, recv_buf, head_len);
                /* Copy payload here */
                memcpy(tmp_buf + head_len, recv_buf + index, payload_len);
                index = index + payload_len;
                if (replica_num > 1) {
                    packet_valid = process_packet(true, tmp_buf, pack_len);
                    replicate_packs(tmp_buf, pack_len, replica_num);
                } else {
                    packet_valid = process_packet(false, tmp_buf, pack_len);
                }
            }
        } else {

            if (replica_num > 1) {

                packet_valid = process_packet(true, packet, recv_len);
                replicate_packs(packet, recv_len, replica_num);
            } else {

                packet_valid = process_packet(false, packet, recv_len);
            }
        }
    }

    if (p_valid_flag) {
        *p_valid_flag = (packet_valid == true ? 1 : 0);
    }

    return TC_OK;
}

#if (TCPCOPY_OFFLINE)
int
tc_offline_init(tc_event_loop_t *event_loop, char *pcap_file)
{
    int  fd;
    char ebuf[PCAP_ERRBUF_SIZE];

    /* Init the raw socket to send */
    if ((fd = tc_raw_socket_out_init()) == TC_INVALID_SOCKET) {
        return TC_ERROR;
    } else {
        tc_raw_socket_out = fd;
    }

    if (pcap_file == NULL) {
        return TC_ERROR;
    }

    if ((pcap = pcap_open_offline(pcap_file, ebuf)) == NULL) {
        tc_log_info(LOG_ERR, 0, "open %s" , ebuf);
        fprintf(stderr, "open %s\n", ebuf);
        return TC_ERROR;
    }

    gettimeofday(&base_time, NULL);
    tc_log_info(LOG_NOTICE, 0, "open pcap success:%s", pcap_file);
    tc_log_info(LOG_NOTICE, 0, "send the first packets here");
    send_packets_from_pcap(1);

    /* register a timer to perform offline */
    tc_event_timer_add(event_loop, 100, tc_process_offline_packet);

    return TC_OK;
}

static void
tc_process_offline_packet(tc_event_timer_t *evt)
{
    send_packets_from_pcap(0);
    evt->msec = tc_current_time_msec + 100;
}

static uint64_t
timeval_diff(struct timeval *start, struct timeval *cur)
{
    uint64_t msec;

    msec  = (cur->tv_sec - start->tv_sec)*1000;
    msec += (cur->tv_usec - start->tv_usec)/1000;

    return msec;
}

static bool
check_read_stop()
{
    uint64_t diff, history_diff, cur_diff;

    history_diff = timeval_diff(&first_pack_time, &last_pack_time);
    cur_diff     = timeval_diff(&base_time, &cur_time);

    tc_log_debug2(LOG_DEBUG, 0, "diff,old:%llu,new:%llu", 
            history_diff, cur_diff);
    if (history_diff <= cur_diff) {
        return false;
    }

    diff = history_diff - cur_diff;
    if (diff > 0) {
        return true;
    }

    return false;
}

static int
get_l2_len(const unsigned char *packet, const int pkt_len, const int datalink)
{
    struct ethernet_hdr *eth_hdr;

    switch (datalink) {
        case DLT_RAW:
            return 0;
            break;
        case DLT_EN10MB:
            eth_hdr = (struct ethernet_hdr *)packet;
            switch (ntohs(eth_hdr->ether_type)) {
                case ETHERTYPE_VLAN:
                    return 18;
                    break;
                default:
                    return 14;
                    break;
            }
            break;
        case DLT_C_HDLC:
            return CISCO_HDLC_LEN;
            break;
        case DLT_LINUX_SLL:
            return SLL_HDR_LEN;
            break;
        default:
            tc_log_info(LOG_ERR, 0, "unsupported DLT type: %s (0x%x)", 
                    pcap_datalink_val_to_description(datalink), datalink);
            break;
    }

    return -1;
}

#ifdef FORCE_ALIGN
static unsigned char pcap_ip_buf[65536];
#endif

static unsigned char *
get_ip_data(unsigned char *packet, const int pkt_len, int *p_l2_len)
{
    int      l2_len;
    u_char  *ptr;

    l2_len    = get_l2_len(packet, pkt_len, pcap_datalink(pcap));
    *p_l2_len = l2_len;

    if (pkt_len <= l2_len) {
        return NULL;
    }
#ifdef FORCE_ALIGN
    if (l2_len % 4 == 0) {
        ptr = (&(packet)[l2_len]);
    } else {
        ptr = pcap_ip_buf;
        memcpy(ptr, (&(packet)[l2_len]), pkt_len - l2_len);
    }
#else
    ptr = (&(packet)[l2_len]);
#endif

    return ptr;

}

static void 
send_packets_from_pcap(int first)
{
    int                 l2_len, ip_pack_len, p_valid_flag = 0;
    bool                stop;
    unsigned char      *pkt_data, *ip_data;
    struct pcap_pkthdr  pkt_hdr;  

    if (NULL == pcap || read_pcap_over) {
        return;
    }

    gettimeofday(&cur_time, NULL);

    stop = check_read_stop();
    while (!stop) {

        pkt_data = (u_char *)pcap_next(pcap, &pkt_hdr);
        if (pkt_data != NULL) {

            if (pkt_hdr.caplen < pkt_hdr.len) {

                tc_log_info(LOG_WARN, 0, "truncated packets,drop");
            } else {

                ip_data = get_ip_data(pkt_data, pkt_hdr.len, &l2_len);
                if (ip_data != NULL) {

                    ip_pack_len = pkt_hdr.len - l2_len;
                    dispose_packet((char*)ip_data, ip_pack_len, &p_valid_flag);
                    if (p_valid_flag) {

                        tc_log_debug0(LOG_DEBUG, 0, "valid flag for packet");

                        if (first) {

                            first_pack_time = pkt_hdr.ts;
                            first = 0;
                        }
                        last_pack_time = pkt_hdr.ts;
                    } else {

                        stop = false;
                        tc_log_debug0(LOG_DEBUG, 0, "stop,invalid flag");
                    }
                }
            }
            stop = check_read_stop();
        } else {

            tc_log_info(LOG_WARN, 0, "stop,null from pcap_next");
            stop = true;
            read_pcap_over = true;
        }
    }
}
#endif /* TCPCOPY_OFFLINE */
