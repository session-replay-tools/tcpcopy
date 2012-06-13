#ifndef  _DELAY_H_INC
#define  _DELAY_H_INC

#ifdef __cplusplus
extern "C"
{
#endif

#include "../core/xcopy.h"
#include "../communication/msg.h"

	void delay_table_init();
	void delay_table_add(uint64_t key, struct msg_server_s *);
	void delay_table_send(uint64_t key, int fd);
	void delay_table_del(uint64_t key);
	void delay_table_destroy();

#ifdef __cplusplus
}
#endif

#endif   /* ----- #ifndef _DELAY_H_INC  ----- */

