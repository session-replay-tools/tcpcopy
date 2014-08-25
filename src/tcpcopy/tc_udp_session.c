
#include <xcopy.h>
#include <tcpcopy.h>


static uint64_t clt_udp_cnt      = 0;
static uint64_t clt_udp_send_cnt = 0;


int
tc_init_sess_table(void)
{
    return TC_OK;
}

void 
tc_dest_sess_table(void)
{
}

/*
 * filter udp packets 
 */
bool
tc_check_ingress_pack_needed(tc_iph_t *ip)
{
    bool          is_needed = false;
    uint16_t      size_ip, size_udp, tot_len;
    tc_udpt_t    *udp;

    /* check if it is a udp packet */
    if (ip->protocol != IPPROTO_UDP) {
        return is_needed;
    }

    size_ip   = ip->ihl << 2;
    tot_len   = ntohs(ip->tot_len);
    if (size_ip < IPH_MIN_LEN) {
        tc_log_info(LOG_WARN, 0, "Invalid IP header length: %d", size_ip);
        return is_needed;
    }

    udp = (tc_udpt_t *) ((char *) ip + size_ip);
    size_udp   = ntohs(udp->len);
    if (size_udp < sizeof(tc_udpt_t)) {
        tc_log_info(LOG_WARN, 0, "Invalid udp header len: %d,pack len:%d",
                size_udp, tot_len);
        return is_needed;
    }

    /* filter the packets we do care about */
    if (TC_CLT == check_pack_src(&(clt_settings.transfer), 
                ip->daddr, udp->dest, CHECK_DEST))
    {
        is_needed = true;
        clt_udp_cnt++;
    }

    return is_needed;

}


void
tc_output_stat()
{
    tc_log_info(LOG_INFO, 0, 
            "udp packets captured:%llu,packets sent:%llu",
            clt_udp_cnt, clt_udp_send_cnt);
}


void
tc_interval_disp(tc_event_timer_t *evt)
{
    tc_output_stat();
    tc_event_update_timer(evt, OUTPUT_INTERVAL);
}


static unsigned char buf[IP_RCV_BUF_SIZE];
void
ip_fragmentation(tc_iph_t *ip)
{
    int             ret, max_pack_no, index, i;
    tc_iph_t       *tmp_ip;
    uint16_t        offset, size_ip, tot_len,
                    remainder, payload_len;
    unsigned char  *p;

    size_ip    = ip->ihl << 2;
    tot_len    = ntohs(ip->tot_len);

    p = buf;
    /* dispose the first packet here */
    memcpy(p, ip, size_ip);
    p = p + ETHERNET_HDR_LEN;
    offset = clt_settings.mtu - size_ip;
    if (offset % 8 != 0) {
        offset = offset / 8;
        offset = offset * 8;
    }
    payload_len = offset;

    tmp_ip = (tc_iph_t *) p;
    tmp_ip->frag_off = htons(IP_MF);

    index  = size_ip;
    p += size_ip;
    memcpy(p, ((unsigned char *) ip) + index, payload_len);
    index      = index + payload_len;
    remainder  = tot_len - size_ip - payload_len;
    ret = tc_raw_socket_snd(tc_raw_socket_out, tmp_ip, 
            size_ip + payload_len, tmp_ip->daddr);
 
    if (ret == TC_ERR) {
        tc_log_info(LOG_ERR, 0, "send to back error,packet size:%d",
                size_ip + payload_len);
        return;
    }

    clt_udp_send_cnt++;

    max_pack_no = (offset + remainder - 1) / offset - 1;

    for (i = 0; i <= max_pack_no; i++) {

        p = buf;
        memcpy(p, (char *) ip, size_ip);

        tmp_ip = (tc_iph_t *) p;
        tmp_ip->frag_off = htons(offset >> 3);

        if (i == max_pack_no) {
            payload_len = remainder;
        } else {
            tmp_ip->frag_off |= htons(IP_MF);
            remainder = remainder - payload_len;
        }

        p += size_ip;
        memcpy(p, ((char *) ip) + index, payload_len);
        index     = index + payload_len;
        offset    = offset + payload_len;
        ret = tc_raw_socket_snd(tc_raw_socket_out, tmp_ip, 
                size_ip + payload_len, tmp_ip->daddr);
        if (ret == TC_ERR) {
            tc_log_info(LOG_ERR, 0, "send to back error,packet size:%d",
                    size_ip + payload_len);
            return;
        }
        clt_udp_send_cnt++;
    }
}

bool tc_proc_outgress(unsigned char *packet)
{
    return true;
}

/*
 * the main procedure for processing udp packets
 */
bool tc_proc_ingress(tc_iph_t *ip, tc_udpt_t *udp)
{
    int              ret;
    uint16_t         tot_len;
    transfer_map_t  *test;

    tot_len    = ntohs(ip->tot_len);

    test = get_test_pair(&(clt_settings.transfer), ip->daddr, udp->dest);
    ip->daddr = test->target_ip;
    udp->dest = test->target_port;
    udpcsum(ip, udp);

    /* check if it needs fragmentation */
    if (tot_len > clt_settings.mtu) {

        ip_fragmentation(ip);
    } else {

        ret = tc_raw_socket_snd(tc_raw_socket_out, ip, 
                tot_len, ip->daddr);
        if (ret == TC_ERR) {
            tc_log_info(LOG_ERR, 0, "send to back error,tot_len:%d", tot_len);
        }
        clt_udp_send_cnt++;
    }

    return true;
}

