#include "../communication/msg.h"
#include "../event/select_server.h"
#include "../log/log.h"
#include "address.h"

static struct address_node addr[65536];

void add_msg_connetion(uint16_t src_port,uint32_t dst_ip,uint16_t dst_port){
	addr[src_port].ip = dst_ip;
	addr[src_port].port = dst_port;
	addr[src_port].sock = msg_copyer_init(dst_ip);
	select_sever_add(addr[src_port].sock);
}

int address_find_sock(uint16_t src_port){
	if(addr[src_port].sock == 0){
		logInfo(LOG_WARN,"it does not find address socket:%u",
				ntohs(src_port));
		return -1;
	}
	return addr[src_port].sock;
}

int address_copy_or_not(uint16_t src_port){
	if(addr[src_port].sock == 0){
		logInfo(LOG_INFO,"address socket is not valid:%u",
				ntohs(src_port));
		return 0;
	}
	return 1;
}

address *address_find_node(uint16_t src_port){
	if(addr[src_port].sock == 0){
		logInfo(LOG_INFO,"it does not find address socket pointer:%d",
				ntohs(src_port));
		return NULL;
	}
	return &addr[src_port];
}

