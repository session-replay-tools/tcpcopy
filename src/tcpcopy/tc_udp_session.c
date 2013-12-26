
#include <xcopy.h>
#include <tcpcopy.h>


static uint64_t clt_udp_cnt      = 0;
static uint64_t clt_udp_send_cnt = 0;


void
init_for_sessions()
{
}

void 
destroy_for_sessions()
{
}

/*
 * filter udp packets 
 */
bool
is_packet_needed(unsigned char *packet)
{
    bool             is_needed = false;
    uint16_t         size_ip, size_udp, tot_len;
    tc_ip_header_t  *ip_header;
    tc_udp_header_t *udp_header;

    ip_header = (tc_ip_header_t *) packet;

    /* check if it is a udp packet */
    if (ip_header->protocol != IPPROTO_UDP) {
        return is_needed;
    }

    size_ip   = ip_header->ihl << 2;
    tot_len   = ntohs(ip_header->tot_len);
    if (size_ip < 20) {
        tc_log_info(LOG_WARN, 0, "Invalid IP header length: %d", size_ip);
        return is_needed;
    }

    udp_header = (tc_udp_header_t *) ((char *) ip_header + size_ip);
    size_udp   = ntohs(udp_header->len);
    if (size_udp < sizeof(tc_udp_header_t)) {
        tc_log_info(LOG_WARN, 0, "Invalid udp header len: %d,pack len:%d",
                size_udp, tot_len);
        return is_needed;
    }

    /* filter the packets we do care about */
    if (LOCAL == check_pack_src(&(clt_settings.transfer), 
                ip_header->daddr, udp_header->dest, CHECK_DEST))
    {
        is_needed = true;
        clt_udp_cnt++;
    }

    return is_needed;

}


void
output_stat()
{
    tc_log_info(LOG_INFO, 0, 
            "udp packets captured:%llu,packets sent:%llu",
            clt_udp_cnt, clt_udp_send_cnt);
}


void
tc_interval_dispose(tc_event_timer_t *evt)
{
    output_stat();

    evt->msec = tc_current_time_msec + OUTPUT_INTERVAL;
}


void
ip_fragmentation(unsigned char *frame, tc_ip_header_t *ip_header, 
        tc_udp_header_t *udp_header)
{
    int             ret, max_pack_no, index, i;
    unsigned char  *p, buf[IP_RECV_BUF_SIZE + ETHERNET_HDR_LEN];
    uint16_t        offset, size_ip, tot_len,
                    remainder, payload_len;
    tc_ip_header_t *tmp_ip_header;

    size_ip    = ip_header->ihl << 2;
    tot_len    = ntohs(ip_header->tot_len);

    p = buf;
    /* dispose the first packet here */
    memcpy(p, frame, ETHERNET_HDR_LEN + size_ip);
    p = p + ETHERNET_HDR_LEN;
    offset = clt_settings.mtu - size_ip;
    if (offset % 8 != 0) {
        offset = offset / 8;
        offset = offset * 8;
    }
    payload_len = offset;

    tmp_ip_header = (tc_ip_header_t *) p;
    tmp_ip_header->frag_off = htons(IP_MF);

    index  = size_ip;
    p += size_ip;
    memcpy(p, ((unsigned char *) ip_header) + index, payload_len);
    index      = index + payload_len;
    remainder  = tot_len - size_ip - payload_len;
#if (!TCPCOPY_PCAP_SEND)
    ret = tc_raw_socket_send(tc_raw_socket_out, tmp_ip_header, 
            size_ip + payload_len, tmp_ip_header->daddr);
#else
    ret = tc_pcap_send(buf, ETHERNET_HDR_LEN + size_ip + payload_len);
#endif
 
    if (ret == TC_ERROR) {
        tc_log_info(LOG_ERR, 0, "send to back error,packet size:%d",
                size_ip + payload_len);
        return;
    }

    clt_udp_send_cnt++;

    max_pack_no = (offset + remainder - 1) / offset - 1;

    for (i = 0; i <= max_pack_no; i++) {

        p = buf + ETHERNET_HDR_LEN;
        memcpy(p, (char *) ip_header, size_ip);

        tmp_ip_header = (tc_ip_header_t *) p;
        tmp_ip_header->frag_off = htons(offset >> 3);

        if (i == max_pack_no) {
            payload_len = remainder;
        } else {
            tmp_ip_header->frag_off |= htons(IP_MF);
            remainder = remainder - payload_len;
        }

        p += size_ip;
        memcpy(p, ((char *) ip_header) + index, payload_len);
        index     = index + payload_len;
        offset    = offset + payload_len;
#if (!TCPCOPY_PCAP_SEND)
        ret = tc_raw_socket_send(tc_raw_socket_out, tmp_ip_header, 
                size_ip + payload_len, tmp_ip_header->daddr);
#else
        ret = tc_pcap_send(buf, ETHERNET_HDR_LEN + size_ip + payload_len);
#endif
        if (ret == TC_ERROR) {
            tc_log_info(LOG_ERR, 0, "send to back error,packet size:%d",
                    size_ip + payload_len);
            return;
        }
        clt_udp_send_cnt++;
    }
}

bool process_out(unsigned char *packet)
{
    return true;
}

/*
 * the main procedure for processing udp packets
 */
bool process_in(unsigned char *frame)
{
    int                      ret;
    uint16_t                 size_ip, tot_len;
    unsigned char           *packet;
    tc_ip_header_t          *ip_header;
    tc_udp_header_t         *udp_header;
    ip_port_pair_mapping_t  *test;

    packet     = frame + ETHERNET_HDR_LEN;
    ip_header  = (tc_ip_header_t *) packet;
    size_ip    = ip_header->ihl << 2;
    tot_len    = ntohs(ip_header->tot_len);
    udp_header = (tc_udp_header_t *) ((char *) ip_header + size_ip);

    test = get_test_pair(&(clt_settings.transfer),
            ip_header->daddr, udp_header->dest);
    ip_header->daddr = test->target_ip;
    udp_header->dest = test->target_port;
#if (TCPCOPY_PCAP_SEND)
    fill_frame((struct ethernet_hdr *) frame, test->src_mac, test->dst_mac);
#endif
    udpcsum(ip_header, udp_header);

    /* check if it needs fragmentation */
    if (tot_len > clt_settings.mtu) {

        ip_fragmentation(frame, ip_header, udp_header);
    } else {

#if (!TCPCOPY_PCAP_SEND)
        ret = tc_raw_socket_send(tc_raw_socket_out, ip_header, 
                tot_len, ip_header->daddr);
#else
        ret = tc_pcap_send(frame, tot_len + ETHERNET_HDR_LEN);
#endif
        if (ret == TC_ERROR) {
            tc_log_info(LOG_ERR, 0, "send to back error,tot_len:%d", tot_len);
        }
        clt_udp_send_cnt++;
    }

    return true;
}

