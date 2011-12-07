#ifndef  _TCP_REDIRECT_SEND_H_INC
#define  _TCP_REDIRECT_SEND_H_INC

int send_init();
int send_close();
uint32_t send_ip_packet(struct iphdr* ip_header,uint16_t tot_len);

#endif   /* ----- #ifndef _TCP_REDIRECT_SEND_H_INC  ----- */


