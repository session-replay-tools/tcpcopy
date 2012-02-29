#ifndef  _TCPCOPY_MSG_H__INC
#define  _TCPCOPY_MSG_H__INC

#ifdef __cplusplus
extern "C"
{
#endif

#include <netinet/tcp.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/ip.h>
#include "../log/log.h"

#define  SERVER_PORT  36524

#if (TCPCOPY_MYSQL_ADVANCED)
#define  MAX_PAYLOAD_LEN 128
#endif

#define  CLIENT_ADD   1
#define  CLIENT_DEL   2


#pragma pack(push,1)
	struct copyer_msg_st{
		uint32_t  client_ip;
		uint16_t  client_port;
		uint16_t  type;
	};

	struct receiver_msg_st{
		struct iphdr ip_header;
		struct tcphdr tcp_header;
#if (TCPCOPY_MYSQL_ADVANCED)	
		unsigned char payload[MAX_PAYLOAD_LEN];
#endif
	};
#pragma pack(pop)

	int msg_copyer_init(uint32_t receiver_ip);
	int msg_receiver_init();

	int msg_copyer_send(int,uint32_t,uint16_t ,uint16_t );
	struct receiver_msg_st* msg_copyer_recv(int sock);

	int msg_receiver_send(int ,struct receiver_msg_st *);
	struct copyer_msg_st* msg_receiver_recv(int sock);

#ifdef __cplusplus
}
#endif

#endif   /* ----- #ifndef _TCPCOPY_MSG_H__INC  ----- */

