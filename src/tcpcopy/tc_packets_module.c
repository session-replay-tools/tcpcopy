
#include <xcopy.h>
#include <tcpcopy.h>

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

    if (packet_valid) {
        *p_valid_flag = 1;
    } else {
        *p_valid_flag = 0;
    }

    return TC_OK;
}

static void
tc_process_raw_socket_packet(tc_event_t *rev)
{
    int  recv_len, p_valid_flag = 0;
    char recv_buf[RECV_BUF_SIZE];

    for ( ;; ) {

        recv_len = recvfrom(rev->fd, recv_buf, RECV_BUF_SIZE, 0, NULL, NULL);

        if (recv_len == -1) {
            if (errno == EAGAIN) {
                return;
            }
            tc_log_info(LOG_ERR, errno, "recvfrom");
            return;
        }

        if (recv_len == 0) {
            tc_log_info(LOG_ERR, 0, "recv len is 0");
            return;
        }
#if 0
        raw_packs++;
#endif
        if (dispose_packet(recv_buf, recv_len, &p_valid_flag) == TC_ERROR) {
            return;
        }
#if 0
        if (p_valid_flag) {
            valid_raw_packs++;
        }

        if (raw_packs % 100000 == 0) {
            tc_log_info(LOG_NOTICE, 0, "raw packets:%llu, valid :%llu",
                    raw_packs, valid_raw_packs);
        }
#endif
    }
}

int
tc_packets_init(tc_event_loop_t *event_loop)
{
    int         fd;
    tc_event_t *ev;

    /* Init the raw socket to send */
    if ((fd = tc_raw_socket_out_init()) == TC_INVALID_SOCKET) {
        return TC_ERROR;
    } else {
        tc_raw_socket_out = fd;
    }

    /* Init the raw socket to recv */
    if ((fd = tc_raw_socket_in_init()) == TC_INVALID_SOCKET) {
        return TC_ERROR;
    }

    tc_socket_set_nonblocking(fd);

    ev = tc_event_create(fd, tc_process_raw_socket_packet, NULL);
    if (ev == NULL) {
        return TC_ERROR;
    }

    if (tc_event_add(event_loop, ev, TC_EVENT_READ)
            == TC_EVENT_ERROR)
    {
        tc_log_info(LOG_ERR, 0, "add raw socket(%d) to event loop failed.",
                    fd);
        return TC_ERROR;
    }

    return TC_OK;
}

