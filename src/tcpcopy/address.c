#include "address.h"
#include "../event/select_server.h"
#include "../communication/msg.h"

static address_node_t addr[65536];

/* this is for copying multiple ports */
void address_add_msg_conn(uint16_t local_port, uint32_t dst_ip,
		uint16_t dst_port)
{
	addr[local_port].ip   = dst_ip;
	addr[local_port].port = dst_port;
	addr[local_port].sock = msg_client_init(dst_ip, dst_port);
	select_sever_add(addr[local_port].sock);
}

/* find the message socket through local port */
int address_find_sock(uint16_t local_port)
{
	if(0 == addr[local_port].sock){
		log_info(LOG_WARN, "it can't find address socket:%u",
				ntohs(local_port));
		return -1;
	}
	return addr[local_port].sock;
}

