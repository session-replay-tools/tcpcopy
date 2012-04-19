#ifndef  _TCPCOPY_SERVER_H_INC
#define  _TCPCOPY_SERVER_H_INC


#ifdef __cplusplus
extern "C"
{
#endif

#include "../log/log.h"
#include <stdint.h>

	typedef struct passed_ip_addr{
		uint32_t ips[16];
		int num;
	}passed_ip_addr;


	extern int global_out_level;
	extern passed_ip_addr passed_ips;

	void interception_init();
	void interception_run();
	void interception_over();
#ifdef __cplusplus
}
#endif

#endif   /* ----- #ifndef _TCPCOPY_SERVER_H_INC  ----- */

