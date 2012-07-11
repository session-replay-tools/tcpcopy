#ifndef  _TCPCOPY_UTIL_H_INC
#define  _TCPCOPY_UTIL_H_INC

#include "../core/xcopy.h"

inline uint64_t get_key(uint32_t s_ip, uint16_t s_port);
inline uint16_t get_appropriate_port(uint16_t orig_port, uint16_t add);
uint16_t get_port_by_rand_addition(uint16_t orig_port);
uint16_t get_port_from_shift(uint16_t orig_port, uint16_t rand_port,
        int shift_factor);
ip_port_pair_mapping_t *get_test_pair(ip_port_pair_mappings_t *target,
        uint32_t ip, uint16_t port);
int check_pack_src(ip_port_pair_mappings_t *target, uint32_t ip, 
        uint16_t port);
unsigned char *copy_ip_packet(struct iphdr *ip_header);
unsigned short csum (unsigned short *packet, int pack_len);
unsigned short tcpcsum(unsigned char *iphdr, unsigned short *packet,
        int pack_len);


#endif   /* ----- #ifndef _TCPCOPY_UTIL_H_INC  ----- */

