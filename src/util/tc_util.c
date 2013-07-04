
#include <xcopy.h>
#include <tcpcopy.h>


inline uint64_t
get_key(uint32_t ip, uint16_t port)
{
    uint64_t value = ((uint64_t) ip ) << 16;

    value += port;

    return value;
}

inline uint16_t
get_appropriate_port(uint16_t orig_port, uint16_t add)
{
    uint16_t dest_port = orig_port;

    if (dest_port < (65536 - add)) {
        dest_port += add;
    } else {
        dest_port  = 1024 + add;
    }

    return dest_port;
}

static unsigned int seed = 0;

uint16_t
get_port_by_rand_addition(uint16_t orig_port)
{
    struct timeval  tp;
    uint16_t        port_add;

    if (0 == seed) {    
        gettimeofday(&tp, NULL);
        seed = tp.tv_usec;
    }    
    port_add = (uint16_t) (4096*(rand_r(&seed)/(RAND_MAX + 1.0)));
    port_add = port_add + 32768;

    return get_appropriate_port(ntohs(orig_port), port_add);
}

uint16_t
get_port_from_shift(uint16_t orig_port, uint16_t rand_port, int shift_factor)
{
    uint16_t        port_add;

    port_add = (shift_factor << 11) + rand_port;

    return get_appropriate_port(ntohs(orig_port), port_add);
}

ip_port_pair_mapping_t *
get_test_pair(ip_port_pair_mappings_t *transfer, uint32_t ip, uint16_t port)
{
    int                     i;
    ip_port_pair_mapping_t *pair, **mappings;

    pair     = NULL;
    mappings = transfer->mappings;
    for (i = 0; i < transfer->num; i++) {
        pair = mappings[i];
        if (ip == pair->online_ip && port == pair->online_port) {
            return pair;
        } else if (pair->online_ip == 0 && port == pair->online_port) {
            return pair;
        }
    }
    return NULL;
}

int
check_pack_src(ip_port_pair_mappings_t *transfer, uint32_t ip,
        uint16_t port, int src_flag)
{
    int                     i, ret;
    ip_port_pair_mapping_t *pair, **mappings;

    ret = UNKNOWN;
    mappings = transfer->mappings;

    for (i = 0; i < transfer->num; i++) {

        pair = mappings[i];
        if (CHECK_DEST == src_flag) {
            /* interested in INPUT raw socket */
            if (ip == pair->online_ip && port == pair->online_port) {
                ret = LOCAL;
                break;
            } else if (0 == pair->online_ip && port == pair->online_port) {
                ret = LOCAL;
                break;
            }
        } else if (CHECK_SRC == src_flag) {
            if (ip == pair->target_ip && port == pair->target_port) {
                ret = REMOTE;
                break;
            }
        }
    }

    return ret;
}

unsigned char *
cp_fr_ip_pack(tc_ip_header_t *ip_header)
{
    int            frame_len;
    uint16_t       tot_len;
    unsigned char *frame;
    
    tot_len   = ntohs(ip_header->tot_len);
    frame_len = ETHERNET_HDR_LEN + tot_len;
    frame     = (unsigned char *) malloc(frame_len);

    if (frame != NULL) {    
        memcpy(frame + ETHERNET_HDR_LEN, ip_header, tot_len);
    }    

    return frame;
}

inline bool
tcp_seq_before(uint32_t seq1, uint32_t seq2)
{
    return (int32_t)(seq1-seq2) < 0;
}

unsigned short
csum(unsigned short *packet, int pack_len) 
{ 
    register unsigned long sum = 0; 

    while (pack_len > 1) {
        sum += *(packet++); 
        pack_len -= 2; 
    } 
    if (pack_len > 0) {
        sum += *(unsigned char *) packet; 
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16); 
    }

    return (unsigned short) ~sum; 
} 


static unsigned short buf[32768]; 

unsigned short
tcpcsum(unsigned char *iphdr, unsigned short *packet, int pack_len)
{       
    unsigned short        res;

    memcpy(buf, iphdr + 12, 8); 
    *(buf + 4) = htons((unsigned short) (*(iphdr + 9)));
    *(buf + 5) = htons((unsigned short) pack_len);
    memcpy(buf + 6, packet, pack_len);
    res = csum(buf, pack_len + 12);

    return res; 
}  


uint16_t
retrieve_wscale(tc_tcp_header_t *tcp_header)
{
    unsigned int opt, opt_len;
    unsigned char *p, *end;

    p = ((unsigned char *) tcp_header) + TCP_HEADER_MIN_LEN;
    end =  ((unsigned char *) tcp_header) + (tcp_header->doff << 2);  
    while (p < end) {
        opt = p[0];
        switch (opt) {
            case TCPOPT_WSCALE:
                return p[2];
            case TCPOPT_NOP:
                p = p + 1; 
                break;
            case TCPOPT_EOL:
                return 0;
            default:
                opt_len = p[1];
                p += opt_len;
                break;
        }    
    }
    return 0;
}

void
set_wscale(tc_tcp_header_t *tcp_header)
{
    u_short        wscale;
    unsigned char *opt;

    opt = (unsigned char *) ((char *) tcp_header + sizeof(tc_tcp_header_t));
    wscale = (u_short) retrieve_wscale(tcp_header);
    if (wscale > 0) {
        opt[0] = TCPOPT_WSCALE;
        opt[1] = 4;
        bcopy((void *) &wscale, (void *) (opt + 2), sizeof(wscale));
        tcp_header->doff = (sizeof(tc_tcp_header_t) + 4) >> 2;
    } 

    return;
}

#if (TCPCOPY_UDP)
static int
do_checksum_math(u_int16_t *data, int len)
{   
    int sum = 0;
    union {
        u_int16_t s;
        u_int8_t b[2];
    } pad;

    while (len > 1) {
        sum += *data++;
        len -= 2;
    }

    if (len == 1) {
        pad.b[0] = *(u_int8_t *)data;
        pad.b[1] = 0;
        sum += pad.s;
    }

    return (sum);
} 

void udpcsum(tc_ip_header_t *ip_header, tc_udp_header_t *udp_packet)
{       
    int            sum;
    uint16_t       len;
    unsigned char *ip_src;

    udp_packet->check = 0;

    len    = ntohs(udp_packet->len);
    ip_src = (unsigned char *) (&ip_header->saddr);
    sum    = do_checksum_math((u_int16_t *) ip_src, 8);
    sum   += ntohs(IPPROTO_UDP + len);
    sum   += do_checksum_math((u_int16_t *) udp_packet, len);
    udp_packet->check = CHECKSUM_CARRY(sum);

}
#endif

#if (TCPCOPY_PCAP)
int
retrieve_devices(char *raw_device, devices_t *devices)
{
    int          count = 0;
    size_t       len;
    const char  *split, *p;

    p = raw_device;

    while (true) {
        split = strchr(p, ',');
        if (split != NULL) {
            len = (size_t) (split - p);
        } else {
            len = strlen(p);
        }

        strncpy(devices->device[count].name, p, len);

        if (count == MAX_DEVICE_NUM) {
            tc_log_info(LOG_WARN, 0, "reach the limit for devices");
            break;
        }

        count++;

        if (split == NULL) {
            break;
        } else {
            p = split + 1;
        }
    }

    devices->device_num = count;

    return 1;
}

char *
construct_filter(int flag, uint32_t ip, uint16_t port, char *filter)
{
    char          *pt, direction[16];
    struct in_addr net_address;

    memset(direction, 0, 16);
    if (flag == SRC_DIRECTION) {
        strcpy(direction, "src");
    } else if (flag == DST_DIRECTION) {
        strcpy(direction, "dst");
    }
    pt = filter;
    strcpy(pt, "(");
    pt = pt + strlen(pt);

    if (port > 0) {
        sprintf(pt, "%s port %d", direction, ntohs(port));
        pt = pt + strlen(pt);
    }

    if (ip > 0) {
        net_address.s_addr = ip;
        if (port == 0) {
            sprintf(pt, "%s host %s", direction, inet_ntoa(net_address));
        } else {
            sprintf(pt, " and %s host %s", direction, inet_ntoa(net_address));
        }
        pt = pt + strlen(pt);
    }       

    strcpy(pt, ")");
    pt = pt + strlen(pt);

    return pt;
}
#endif

#if (TCPCOPY_PCAP || TCPCOPY_OFFLINE)
int
get_l2_len(const unsigned char *frame, const int pkt_len, const int datalink)
{
    struct ethernet_hdr *eth_hdr;

    switch (datalink) {
        case DLT_RAW:
            return 0;
            break;
        case DLT_EN10MB:
            eth_hdr = (struct ethernet_hdr *) frame;
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

unsigned char *
get_ip_data(pcap_t *pcap, unsigned char *frame, const int pkt_len, 
        int *p_l2_len)
{
    int      l2_len;
    u_char  *ptr;

    l2_len    = get_l2_len(frame, pkt_len, pcap_datalink(pcap));
    *p_l2_len = l2_len;

    if (pkt_len <= l2_len) {
        return NULL;
    }
#ifdef FORCE_ALIGN
    if (l2_len % 4 == 0) {
        ptr = (&(frame)[l2_len]);
    } else {
        ptr = pcap_ip_buf;
        memcpy(ptr, (&(frame)[l2_len]), pkt_len - l2_len);
    }
#else
    ptr = (&(frame)[l2_len]);
#endif

    return ptr;

}
#endif

#if (TCPCOPY_PCAP_SEND)
inline void
fill_frame(struct ethernet_hdr *hdr, unsigned char *smac, unsigned char *dmac)
{
    memcpy(hdr->ether_shost, smac, ETHER_ADDR_LEN);
    memcpy(hdr->ether_dhost, dmac, ETHER_ADDR_LEN);
    hdr->ether_type = htons(ETH_P_IP); 
}
#endif

