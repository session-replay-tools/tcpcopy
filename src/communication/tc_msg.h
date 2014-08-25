#ifndef  TC_MSG_INCLUDED
#define  TC_MSG_INCLUDED

#include <xcopy.h>

typedef struct msg_clt_s msg_clt_t;
typedef struct msg_server_s msg_server_t;

#pragma pack(push,1)

struct msg_clt_s {
    uint32_t  clt_ip;
    uint16_t  clt_port;
    uint16_t  type;
    uint32_t  target_ip;
    uint16_t  target_port;
};

struct msg_server_s {
    tc_iph_t  ip;
    tc_tcph_t tcp;
#if (TC_PAYLOAD)
    unsigned char extension[MAX_OPTION_LEN + MAX_PAYLOAD_LEN];
#else 
    unsigned char extension[MAX_OPTION_LEN];
#endif
};
#pragma pack(pop)

#define MSG_CLT_SIZE sizeof(msg_clt_t)
#define MSG_SERVER_SIZE sizeof(msg_server_t)

#endif /*  TC_MSG_INCLUDED */

