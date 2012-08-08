
#include <xcopy.h>
#include <tcpcopy.h>

static int            raw_sock  = -1;
static uint32_t       localhost;
static uint64_t       raw_packs = 0, valid_raw_packs = 0;

#if (TCPCOPY_OFFLINE)
static bool           read_pcap_over= false;
static pcap_t        *pcap = NULL;
static struct timeval first_pack_time, last_pack_time, base_time, cur_time;
#endif

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

#if (!TCPCOPY_OFFLINE)
static void
set_nonblock(int socket)
{
    int flags;

    flags = fcntl(socket, F_GETFL, 0);
    fcntl(socket, F_SETFL, flags | O_NONBLOCK);
}

/* Initiate input raw socket */
static int
init_input_raw_socket()
{
    int        sock, recv_buf_opt, ret;
    socklen_t  opt_len;

#if (COPY_LINK_PACKETS)
    /* 
     * AF_PACKET
     * Packet sockets are used to receive or send raw packets 
     * at the device driver level.They allow the user to 
     * implement protocol modules in user space on top of 
     * the physical layer. 
     * ETH_P_IP
     * Internet Protocol packet that is related to the Ethernet 
     */
    sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
#else 
    /* copy ip datagram from IP layer*/
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
#endif

    if (-1 == sock) {
        tc_log_info(LOG_ERR, errno, "socket");   
    }

    set_nonblock(sock);

    recv_buf_opt   = 67108864;
    opt_len = sizeof(int);
    ret = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &recv_buf_opt, opt_len);
    if (-1 == ret) {
        tc_log_info(LOG_ERR, errno, "setsockopt");    
    }

    return sock;
}
#endif

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
                return FAILURE;
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
            strace_pack(LOG_NOTICE, CLIENT_FLAG, ip_header, tcp_header);
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

    if (packet_valid) {
        *p_valid_flag = 1;
    }

    return SUCCESS;
}

/*
 * Retrieve raw packets
 */
static int
retrieve_raw_sockets(int sock)
{
    int      err, recv_len, p_valid_flag = 0;
    char     recv_buf[RECV_BUF_SIZE];

    while (true) {

        recv_len = recvfrom(sock, recv_buf, RECV_BUF_SIZE, 0, NULL, NULL);
        if (recv_len < 0) {
            err = errno;
            if (EAGAIN == err) {
                break;
            }
            tc_log_info(LOG_ERR, errno, "recvfrom");
        }
        if (0 == recv_len) {
            tc_log_info(LOG_ERR, 0, "recv len is 0");
            break;
        }

        raw_packs++;
        if (recv_len > RECV_BUF_SIZE) {
            tc_log_info(LOG_ERR, 0, "recv_len:%d ,it is too long", recv_len);
            break;
        }

        if (FAILURE == dispose_packet(recv_buf, recv_len, &p_valid_flag)) {
            break;
        }

        if (p_valid_flag) {
            valid_raw_packs++;
        }

        if (raw_packs % 100000 == 0) {
            tc_log_info(LOG_NOTICE, 0, "raw packets:%llu, valid :%llu",
                    raw_packs, valid_raw_packs);
        }
    }

    return 0;
}

/* Check resource usage, such as memory usage and cpu usage */
static void
check_resource_usage(tc_event_timer_t *evt)
{
    int           ret, who;
    struct rusage usage;

    who = RUSAGE_SELF;

    ret = getrusage(who, &usage);
    if (ret == -1) {
        tc_log_info(LOG_ERR, errno, "getrusage"); 
    }

    /* Total amount of user time used */
    tc_log_info(LOG_NOTICE, 0, "user time used:%ld", usage.ru_utime.tv_sec);

    /* Total amount of system time used */
    tc_log_info(LOG_NOTICE, 0, "sys  time used:%ld", usage.ru_stime.tv_sec);

    /* Maximum resident set size (in kilobytes) */
    /* This is only valid since Linux 2.6.32 */
    tc_log_info(LOG_NOTICE, 0, "max memory size:%ld", usage.ru_maxrss);

    if (usage.ru_maxrss > clt_settings.max_rss) {
        tc_log_info(LOG_WARN, 0, "occupies too much memory,limit:%ld",
                 clt_settings.max_rss);
    }

    evt->msec = tc_current_time_msec + 60000;
}

#if (TCPCOPY_OFFLINE)
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

void 
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
                        valid_raw_packs++;
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

#endif

/* Dispose one event*/
void
dispose_event(int fd)
{
    struct msg_server_s *msg;

    if (fd == raw_sock) {
        retrieve_raw_sockets(fd);
    } else {

        msg = msg_client_recv(fd);
        if (NULL == msg ) {
            fprintf(stderr, "NULL msg :\n");
            tc_log_info(LOG_ERR, 0, "NULL msg from msg_client_recv");
            exit(EXIT_FAILURE);
        }   
        process((char*)msg, REMOTE);
    }   
#if (TCPCOPY_OFFLINE)
    if (!read_pcap_over) {
        tc_log_debug0(LOG_DEBUG, 0, "send_packets_from_pcap");
        send_packets_from_pcap(0);
    }
#endif
}

void 
tcp_copy_exit()
{
    int i;

    tc_event_loop_finish(&event_loop);
    destroy_for_sessions();

    if (-1 != raw_sock) {
        close(raw_sock);
        raw_sock = -1;
    }

    send_close();
    address_close_sock();
    tc_log_end();

#ifdef TCPCOPY_MYSQL_ADVANCED
    release_mysql_user_pwd_info();
#endif

    if (clt_settings.transfer.mappings != NULL) {

        for (i = 0; i < clt_settings.transfer.num; i++) {
            free(clt_settings.transfer.mappings[i]);
        }

        free(clt_settings.transfer.mappings);
        clt_settings.transfer.mappings = NULL;
    }
    exit(EXIT_SUCCESS);

}

void
tcp_copy_over(const int sig)
{
    long int pid   = (long int)syscall(SYS_gettid);

    tc_log_info(LOG_WARN, 0, "sig %d received, pid=%ld", sig, pid);
    exit(EXIT_SUCCESS);
}


/* Initiate tcpcopy client */
int
tcp_copy_init(tc_event_loop_t *event_loop)
{
    int                      i;
#if (TCPCOPY_OFFLINE)
    char                    *pcap_file, ebuf[PCAP_ERRBUF_SIZE];
#endif
    uint16_t                 online_port, target_port;
    uint32_t                 target_ip;
    tc_event_t              *raw_socket_event;
    ip_port_pair_mapping_t  *pair, **mappings;

    /* keep it temporarily */
    select_server_set_callback(dispose_event);

    /* Register a timer to check resource every minute */
    tc_event_timer_add(event_loop, 60000, check_resource_usage);

    /* Init session table*/
    init_for_sessions();
    localhost = inet_addr("127.0.0.1"); 

    /* Init output raw socket info */
    send_init();

    /* Add connections to the tested server for exchanging info */
    mappings = clt_settings.transfer.mappings;
    for (i = 0; i < clt_settings.transfer.num; i++) {

        pair = mappings[i];
        online_port = pair->online_port;
        target_ip   = pair->target_ip;
        target_port = pair->target_port;
        if (address_add_msg_conn(event_loop, online_port, target_ip, 
                clt_settings.srv_port))
        {
            return FAILURE;
        }
        tc_log_info(LOG_NOTICE, 0, "add a tunnel for exchanging info:%u",
                ntohs(target_port));
    }
    
#if (!TCPCOPY_OFFLINE)
    /* Init input raw socket info */
    raw_sock = init_input_raw_socket();
#endif
    if (raw_sock != -1) {

        /* Add the input raw socket to select */
        raw_socket_event = tc_event_create(raw_sock, dispose_event_wrapper,
                                           NULL);
        if (raw_socket_event == NULL) {
            return FAILURE;
        }

        if (tc_event_add(event_loop, raw_socket_event, TC_EVENT_READ)
                == TC_EVENT_ERROR)
        {
            tc_log_info(LOG_ERR, 0, "add raw socket(%d) to event loop failed.",
                     raw_socket_event->fd);
            return FAILURE;
        }

        /* Init output raw socket info */
        send_init();

        /* Add connections to the tested server for exchanging info */
        mappings = clt_settings.transfer.mappings;
        for (i = 0; i < clt_settings.transfer.num; i++) {

            pair = mappings[i];
            online_port = pair->online_port;
            target_ip   = pair->target_ip;
            target_port = pair->target_port;

            if (address_add_msg_conn(event_loop, online_port, target_ip, 
                                     clt_settings.srv_port) == -1)
            {
                return FAILURE;
            }

            tc_log_info(LOG_NOTICE, 0, "add a tunnel for exchanging info:%u",
                    ntohs(target_port));
        }

        return SUCCESS;
    } else {

#if (TCPCOPY_OFFLINE)
        select_offline_set_callback(send_packets_from_pcap);

        pcap_file = clt_settings.pcap_file;
        if (pcap_file != NULL) {

            if ((pcap = pcap_open_offline(pcap_file, ebuf)) == NULL) {
                tc_log_info(LOG_ERR, 0, "open %s" , ebuf);
                fprintf(stderr, "open %s\n", ebuf);
                return FAILURE;

            } else {

                gettimeofday(&base_time, NULL);
                tc_log_info(LOG_NOTICE, 0, "open pcap success:%s", pcap_file);
                tc_log_info(LOG_NOTICE, 0, "send the first packets here");
                send_packets_from_pcap(1);
            }
        } else {
            return FAILURE;
        }
#else
        return FAILURE;
#endif
    }

    return SUCCESS;
}

/* keep it temporarily */
void 
dispose_event_wrapper(tc_event_t *efd)
{
    dispose_event(efd->fd);
}

