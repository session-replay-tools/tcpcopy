#ifndef  _TCPCOPY_RECEIVER_DELAY_H_INC
#define  _TCPCOPY_RECEIVER_DELAY_H_INC

#ifdef __cplusplus
extern "C"
{
#endif

#include "../communication/msg.h"

	void delay_table_init();
	void delay_table_add(uint64_t key,struct receiver_msg_st *);
	void delay_table_send(uint64_t key,int fd);
	void delay_table_del(uint64_t key);
	void delay_table_destroy();

#ifdef __cplusplus
}
#endif

#endif   /* ----- #ifndef _TCPCOPY_RECEIVER_DELAY_H_INC  ----- */

