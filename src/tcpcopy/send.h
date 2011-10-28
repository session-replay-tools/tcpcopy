#ifndef  _TCP_REDIRECT_SEND_H_INC
#define  _TCP_REDIRECT_SEND_H_INC

int send_init();
int send_close();
uint32_t send_ip_packet(uint64_t fake_ip_addr,
		unsigned char *data,uint32_t ack_seq,uint32_t* sendSeq);


#endif   /* ----- #ifndef _TCP_REDIRECT_SEND_H_INC  ----- */


