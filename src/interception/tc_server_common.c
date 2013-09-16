#include <xcopy.h>
#include <intercept.h>

void
tc_intercept_close_fd(int fd, tc_event_t *rev)
{
    tc_socket_close(fd);                                                                              
#if (INTERCEPT_COMBINED)
    set_fd_valid(fd, false);
#endif
    tc_log_info(LOG_NOTICE, 0, "close sock:%d", fd);
    tc_event_del(rev->loop, rev, TC_EVENT_READ);
}

