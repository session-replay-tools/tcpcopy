
#include <xcopy.h>
#include <tcpcopy.h>


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

        strncpy(devices->device[count++].name, p, len);

        if (count == MAX_DEVICE_NUM) {
            tc_log_info(LOG_WARN, 0, "reach the limit for devices");
            break;
        }

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

