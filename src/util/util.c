#include "../core/hash.h"
#include "util.h"

inline uint64_t get_ip_port_value(uint32_t s_ip,uint16_t s_port)
{
	uint64_t value =((uint64_t)s_ip) << 16;
	value += s_port;
	return value;
}

inline uint16_t get_appropriate_port(uint16_t orig_port, uint16_t add)
{
	uint16_t dest_port;
	dest_port = orig_port;
	if(dest_port < (65536 - add)){
		dest_port += add;
	}else{
		dest_port  = 32768 + add;
	}
	return dest_port;
}

uint16_t get_port_by_rand_addition(uint16_t orig_port)
{
	static unsigned int seed = 0;
	struct timeval  tp;
	uint16_t        port_add;

	if(0 == seed){    
		gettimeofday(&tp, NULL);
		seed = tp.tv_usec;
	}    
	port_add = (uint16_t)(4096*(rand_r(&seed)/(RAND_MAX + 1.0)));
	port_add = port_add + 1024;

	return get_appropriate_port(ntohs(orig_port), port_add);
	
}

uint16_t get_port_from_shift(uint16_t orig_port, uint16_t rand_port,
		int shift_factor)
{
	uint16_t        port_add;
	port_add = (2048 << shift_factor) + rand_port;

	return get_appropriate_port(ntohs(orig_port), port_add);
}

ip_port_pair_mapping_t *get_test_pair(ip_port_pair_mappings_t *transfer,
		uint32_t ip, uint16_t port)
{
	int i;
	ip_port_pair_mapping_t *pair;
	ip_port_pair_mapping_t **mappings;
	mappings = transfer->mappings;
	for(i = 0; i < transfer->num; i++){
		pair = mappings[i];
		if(ip == pair->target_ip && port == pair->target_port){
			break;
		}
	}
	return pair;
}

int check_pack_src(ip_port_pair_mappings_t *transfer,
		uint32_t ip, uint16_t port)
{
	int i;
	int ret = UNKNOWN;
	ip_port_pair_mapping_t *pair;
	ip_port_pair_mapping_t **mappings = transfer->mappings;
	for(i = 0; i < transfer->num; i++){
		pair = mappings[i];
		if(ip == pair->online_ip && port == pair->online_port){
			ret = LOCAL;
			break;
		}else if(0 == pair->online_ip && port == pair->online_port){
			ret = LOCAL;
			break;
		}else if(ip == pair->target_ip && port == pair->target_port){
			ret = REMOTE;
			break;
		}
	}
	return ret;
}

struct timeval get_time()
{
	struct timeval tp; 
	gettimeofday(&tp, NULL);
	return tp; 
}

inline uint32_t minus_one(uint32_t seq)
{
	return htonl(ntohl(seq) - 1);
}

inline uint32_t plus_one(uint32_t seq)
{
	return htonl(ntohl(seq) + 1);
}

bool check_seq_valid(uint32_t cur_seq, uint32_t last_seq)
{
	if(cur_seq <= last_seq){
		return false;
	}
	return true;
}

/* suppose this function is called when the packet is content packet */
bool check_retransmission(struct tcphdr *tcp_header, 
		uint32_t last_cont_sent_seq)
{
	uint32_t cur_seq = ntohl(tcp_header->seq);
	if(cur_seq <= last_cont_sent_seq){
		return true;
	}
	return false;
}

unsigned char *copy_ip_packet(struct iphdr *ip_header)
{
	uint16_t tot_len    = ntohs(ip_header->tot_len);
	unsigned char *data = (unsigned char *)malloc(tot_len);
	if(NULL != data){    
		memcpy(data, ip_header, tot_len);
	}    
	return data;
}

unsigned short csum (unsigned short *packet, int pack_len) 
{ 
	register unsigned long sum = 0; 
	while (pack_len > 1) {
		sum += *(packet++); 
		pack_len -= 2; 
	} 
	if (pack_len > 0) {
		sum += *(unsigned char *)packet; 
	}
	while (sum >> 16){
		sum = (sum & 0xffff) + (sum >> 16); 
	}
	return (unsigned short) ~sum; 
} 


static unsigned short buf[2048]; 

unsigned short tcpcsum(unsigned char *iphdr, unsigned short *packet,
		int pack_len)
{       
	unsigned short        res;

	memcpy(buf, iphdr + 12, 8); 
	*(buf + 4) = htons((unsigned short)(*(iphdr + 9)));
	*(buf + 5) = htons((unsigned short)pack_len);
	memcpy(buf + 6, packet, pack_len);
	res = csum(buf, pack_len + 12);

	return res; 
}  

