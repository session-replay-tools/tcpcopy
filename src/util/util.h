#ifndef  _TCPCOPY_UTIL_H_INC
#define  _TCPCOPY_UTIL_H_INC

#ifdef __cplusplus
extern "C"
{
#endif
#include <xcopy.h>

uint16_t get_port_by_rand_addition(uint16_t orig_port);
uint16_t get_port_from_shift(uint16_t orig_port);

ip_port_pair_mapping_t *get_test_pair(uint32_t ip, uint16_t port);
int check_pack_src(uint32_t ip, uint16_t port);
struct timeval get_time();
inline uint32_t minus_one(uint32_t seq);
inline uint32_t plus_one(uint32_t seq);
int check_seq_valid(uint32_t cur_seq, uint32_t last_seq);
int check_retransmission(struct tcphdr *tcp_header, 
		uint32_t last_cont_sent_seq);

unsigned char *copy_ip_packet(struct iphdr *ip_header);
unsigned short csum (unsigned short *packet, int pack_len);
unsigned short tcpcsum(unsigned char *iphdr, unsigned short *packet,
		int pack_len);

#ifdef __cplusplus
}
#endif

#endif   /* ----- #ifndef _TCPCOPY_UTIL_H_INC  ----- */

#include <xcopy.h>

