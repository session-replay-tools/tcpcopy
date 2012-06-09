#include <xcopy.h>


uint16_t get_port_rand_addition(){
	static unsigned int seed = 0;
	struct timeval  tp;
	uint16_t        port_add;

	if(0 == seed){    
		gettimeofday(&tp, NULL);
		seed = tp.tv_usec;
	}    
	port_add = (uint16_t)(4096*(rand_r(&seed)/(RAND_MAX + 1.0)));
	port_add = port_add + 1024;

	return port_add;
}

uint16_t get_port_from_shift(uint16_t ori_port){
	uint16_t        port_add, transferred_port;
	port_add = (2048 << port_shift_factor) + rand_shift_port;
	transferred_port = ntohs(ori_port);
	if(transferred_port <= (65535 - port_add))
	{    
		transferred_port = transferred_port + port_add;
	}else
	{    
		transferred_port = 1024 + port_add;
	}    
	return transferred_port;
}

int check_pack_src(uint32_t ip, uint16_t port){
	int i   = 0;
	int ret = SRC_UNKNOWN;
	ip_port_pair_mapping_t *pair;
	for(; i < g_transfer_target.num; i++){
		pair = g_transfer_target[i];
		if(ip == pair->src_ip && port == pair->src_port){
			ret = SRC_LOCAL;
			break;
		}else if(ip == pair->dst_ip && port == pair->dst_port){
			ret = SRC_REMOTE;
			break;
		}
	}
	return ret;
}

struct timeval getTime(){
	struct timeval tp; 
	gettimeofday(&tp, NULL);
	return tp; 
}

inline uint32_t minus_one(uint32_t seq){
	return htonl(ntohl(seq) - 1);
}

inline uint32_t plus_one(uint32_t seq){
	return htonl(ntohl(seq) + 1);
}

int check_seq_valid(struct tcphdr *tcp_header, uint32_t last_seq){
	uint32_t cur_seq = ntohl(tcp_header->seq);
	if(cur_seq <= last_seq){
		return 0;
	}
	return 1;
}

/* TODO it will have to change function name */
int check_retransmission(struct tcphdr *tcp_header, uint32_t last_seq){
	uint32_t cur_seq = ntohl(tcp_header->seq);
	if(cur_seq <= last_seq){
		return 1;
	}
	return 0;
}

unsigned char *copy_ip_packet(struct iphdr *ip_header){
	uint16_t tot_len    = ntohs(ip_header->tot_len);
	unsigned char *data = (unsigned char *)malloc(tot_len);
	if(NULL != data){    
		memcpy(data, ip_header, tot_len);
	}    
	return data;
}

unsigned short csum (unsigned short *packet, int pack_len) { 
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


unsigned short tcpcsum(unsigned char *iphdr, unsigned short *packet,
		int pack_len){       
	static unsigned short buf[2048]; 
	unsigned short        res;

	if(pack_len > DEFAULT_MTU){
		log_info(LOG_ERR, "packet is too long:%d", pack_len);
		return 0;
	}
	memcpy(buf, iphdr + 12, 8); 
	*(buf + 4) = htons((unsigned short)(*(iphdr + 9)));
	*(buf + 5) = htons((unsigned short)pack_len);
	memcpy(buf + 6, packet, pack_len);
	res = csum(buf, pack_len + 12);

	return res; 
}  

