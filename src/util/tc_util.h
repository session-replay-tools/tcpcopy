#ifndef  TC_UTIL_INCLUDED
#define  TC_UTIL_INCLUDED

#include <xcopy.h>
#include <tcpcopy.h>


#define TCP_HDR_LEN(tcph) (tcph->doff << 2)
#define IP_HDR_LEN(iph) (iph->ihl << 2)                                                                 
#define EXTRACT_32BITS(p)   ((uint32_t)ntohl(*(uint32_t *)(p)))

#define TCP_PAYLOAD_LENGTH(iph, tcph) \
        (ntohs(iph->tot_len) - IP_HDR_LEN(iph) - TCP_HDR_LEN(tcph))

#if (TCPCOPY_UDP)
#define CHECKSUM_CARRY(x) \
        (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))
#endif

uint16_t get_port_by_rand_addition(uint16_t orig_port);
ip_port_pair_mapping_t *get_test_pair(ip_port_pair_mappings_t *target,
        uint32_t ip, uint16_t port);
int check_pack_src(ip_port_pair_mappings_t *target, uint32_t ip, 
        uint16_t port, int src_flag);
unsigned char *cp_fr_ip_pack(tc_ip_header_t *ip_header);
unsigned short csum (unsigned short *packet, int pack_len);
unsigned short tcpcsum(unsigned char *iphdr, unsigned short *packet,
        int pack_len);
#if (TCPCOPY_UDP)
void udpcsum(tc_ip_header_t *ip_header, tc_udp_header_t *udp_packet);
#endif
#if (TCPCOPY_PCAP)
int retrieve_devices(char *raw_device, devices_t *devices);
char *construct_filter(int flag, uint32_t ip, uint16_t port, char *filter);
#endif

#if (TCPCOPY_PCAP || TCPCOPY_OFFLINE)
int get_l2_len(const unsigned char *frame, const int pkt_len, 
        const int datalink);
unsigned char *
get_ip_data(pcap_t *pcap, unsigned char *frame, const int pkt_len, 
        int *p_l2_len);
#endif

#if (TCPCOPY_PCAP_SEND)
static inline void 
fill_frame(struct ethernet_hdr *hdr, unsigned char *smac, unsigned char *dmac)
{
    memcpy(hdr->ether_shost, smac, ETHER_ADDR_LEN);
    memcpy(hdr->ether_dhost, dmac, ETHER_ADDR_LEN);
    hdr->ether_type = htons(ETH_P_IP); 
}
#endif

static inline uint64_t
get_key(uint32_t ip, uint16_t port)
{
    uint64_t value = ((uint64_t) ip ) << 16;

    value += port;

    return value;
}

static inline uint16_t
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

static inline uint16_t
get_port_from_shift(uint16_t orig_port, uint16_t rand_port, int shift_factor)
{
    uint16_t        port_add;

    port_add = (shift_factor << 11) + rand_port;

    return get_appropriate_port(ntohs(orig_port), port_add);
}


#endif   /* ----- #ifndef TC_UTIL_INCLUDED  ----- */

