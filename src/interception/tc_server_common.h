#ifndef  TC_SERVER_COMMON_INCLUDED
#define  TC_SERVER_COMMON_INCLUDED

#include <xcopy.h> 

void tc_intercept_close_fd(int fd, tc_event_t *rev);
void tc_intercept_close_tunnel(int fd);
#if (TCPCOPY_SINGLE)  
void tc_intercept_check_tunnel_for_single(int fd);
#endif

#endif /* TC_SERVER_COMMON_INCLUDED */

