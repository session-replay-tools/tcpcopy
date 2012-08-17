#ifndef  _TCPCOPY_MSG_H__INC
#define  _TCPCOPY_MSG_H__INC

#include <xcopy.h>

typedef struct msg_client_s msg_client_t;
typedef struct msg_server_s msg_server_t;

#pragma pack(push,1)
struct msg_client_s {
    uint32_t  client_ip;
    uint16_t  client_port;
    uint16_t  type;
};

struct msg_server_s {
    struct iphdr  ip_header;
    struct tcphdr tcp_header;

#if (TCPCOPY_MYSQL_ADVANCED)
    unsigned char payload[MAX_PAYLOAD_LEN];
#endif
};
#pragma pack(pop)

#define MSG_CLIENT_SIZE sizeof(msg_client_t)
#define MSG_SERVER_SIZE sizeof(msg_server_t)

#endif /*  _TCPCOPY_MSG_H__INC */

