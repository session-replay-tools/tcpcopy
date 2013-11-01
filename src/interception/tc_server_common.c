#include <xcopy.h>
#include <intercept.h>

void
tc_intercept_close_fd(int fd, tc_event_t *rev)
{
    tc_socket_close(fd);           
#if (INTERCEPT_COMBINED)
    if (fd > 0) {
        srv_settings.tunnel[fd].fd_valid = false;
    }
#endif
    tc_log_info(LOG_NOTICE, 0, "close sock:%d", fd);
    tc_event_del(rev->loop, rev, TC_EVENT_READ);
}

void
tc_intercept_close_tunnel(int fd)
{
    tc_event_t *ev;

    ev = srv_settings.tunnel[fd].ev;
    tc_intercept_close_fd(fd, ev);
}

#if (TCPCOPY_SINGLE)  
void tc_intercept_check_tunnel_for_single(int fd)
{
    int i, diff;

    if (srv_settings.accepted_tunnel_time == 0) {
        srv_settings.accepted_tunnel_time = tc_current_time_sec;
    }

    diff = tc_current_time_sec - srv_settings.accepted_tunnel_time;

    if (diff > 3) {
        tc_log_info(LOG_WARN, 0, "it does not support distributed tcpcopy");
        for (i = 0; i < srv_settings.s_fd_num; i++) {
            tc_intercept_close_tunnel(fd);
        }
        srv_settings.s_fd_num = 0;
        srv_settings.s_fd_index = 0;
        srv_settings.accepted_tunnel_time = tc_current_time_sec;
    }

    if (srv_settings.s_fd_num < MAX_SINGLE_CONNECTION_NUM) {
        srv_settings.s_router_fds[srv_settings.s_fd_num] = fd;
        srv_settings.s_fd_num++;
    } else {
        tc_log_info(LOG_WARN, 0, "reach the fd limit for single:%d", 
                srv_settings.s_fd_num);
    }
}
#endif


