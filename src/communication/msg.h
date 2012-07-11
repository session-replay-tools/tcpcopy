#ifndef  _TCPCOPY_MSG_H__INC
#define  _TCPCOPY_MSG_H__INC

#include "../core/xcopy.h"

#pragma pack(push,1)
    struct msg_client_s{
        uint32_t  client_ip;
        uint16_t  client_port;
        uint16_t  type;
    };

    struct msg_server_s{
        struct iphdr ip_header;
        struct tcphdr tcp_header;
#if (TCPCOPY_MYSQL_ADVANCED)    
        unsigned char payload[MAX_PAYLOAD_LEN];
#endif
    };
#pragma pack(pop)

    int msg_client_init(uint32_t server_ip, uint16_t port);
    int msg_server_init(const char *binded_ip, uint16_t port);

    int msg_client_send(int, uint32_t, uint16_t, uint16_t);
    struct msg_server_s *msg_client_recv(int sock);

    int msg_server_send(int, struct msg_server_s *);
    struct msg_client_s *msg_server_recv(int sock);


#endif   /* ----- #ifndef _TCPCOPY_MSG_H__INC  ----- */

