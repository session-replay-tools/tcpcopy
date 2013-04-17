#ifndef  TC_UTIL_INCLUDED
#define  TC_UTIL_INCLUDED

#include <xcopy.h>
#include <tcpcopy.h>


#define TCP_HDR_LEN(tcph) (tcph->doff << 2)
#define IP_HDR_LEN(iph) (iph->ihl << 2)                                                                 
#define TCP_PAYLOAD_LENGTH(iph, tcph) \
        (ntohs(iph->tot_len) - IP_HDR_LEN(iph) - TCP_HDR_LEN(tcph))

inline uint64_t get_key(uint32_t s_ip, uint16_t s_port);
inline uint16_t get_appropriate_port(uint16_t orig_port, uint16_t add);
uint16_t get_port_by_rand_addition(uint16_t orig_port);
uint16_t get_port_from_shift(uint16_t orig_port, uint16_t rand_port,
        int shift_factor);
ip_port_pair_mapping_t *get_test_pair(ip_port_pair_mappings_t *target,
        uint32_t ip, uint16_t port);
int check_pack_src(ip_port_pair_mappings_t *target, uint32_t ip, 
        uint16_t port, int src_flag);
unsigned char *copy_ip_packet(tc_ip_header_t *ip_header);
inline bool tcp_seq_before(uint32_t seq1, uint32_t seq2);
unsigned short csum (unsigned short *packet, int pack_len);
unsigned short tcpcsum(unsigned char *iphdr, unsigned short *packet,
        int pack_len);
uint16_t retrieve_wscale(tc_tcp_header_t *tcp_header);
void set_wscale(tc_tcp_header_t *tcp_header);

#endif   /* ----- #ifndef TC_UTIL_INCLUDED  ----- */

