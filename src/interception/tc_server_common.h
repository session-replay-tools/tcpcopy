#ifndef  TC_SERVER_COMMON_INCLUDED
#define  TC_SERVER_COMMON_INCLUDED

#include <xcopy.h> 

void tc_intercept_release_tunnel(int fd, tc_event_t *rev);
void tc_intercept_rel_tunnel_by_single_fd(int fd);
#if (TCPCOPY_SINGLE)  
bool tc_intercept_check_tunnel_for_single(int fd);
#endif
void release_tunnel_resources();

#endif /* TC_SERVER_COMMON_INCLUDED */

