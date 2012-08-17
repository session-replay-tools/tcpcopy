
static bool           read_pcap_over= false;
static pcap_t        *pcap = NULL;
static struct timeval first_pack_time, last_pack_time, base_time, cur_time;

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

int tc_offline_init()
{
    select_offline_set_callback(send_packets_from_pcap);

    pcap_file = clt_settings.pcap_file;
    if (pcap_file != NULL) {

        if ((pcap = pcap_open_offline(pcap_file, ebuf)) == NULL) {
            tc_log_info(LOG_ERR, 0, "open %s" , ebuf);
            fprintf(stderr, "open %s\n", ebuf);
            return TC_ERROR;

        } else {

            gettimeofday(&base_time, NULL);
            tc_log_info(LOG_NOTICE, 0, "open pcap success:%s", pcap_file);
            tc_log_info(LOG_NOTICE, 0, "send the first packets here");
            send_packets_from_pcap(1);
        }
    } else {
        return TC_ERROR;
    }

}
