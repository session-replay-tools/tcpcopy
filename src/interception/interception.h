#ifndef  _TCPCOPY_SERVER_H_INC
#define  _TCPCOPY_SERVER_H_INC

#ifdef __cplusplus
extern "C"
{
#endif

#include "../log/log.h"
	extern int output_level;

	void interception_init();
	void interception_run();
	void interception_over();
#ifdef __cplusplus
}
#endif

#endif   /* ----- #ifndef _TCPCOPY_SERVER_H_INC  ----- */

