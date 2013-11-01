#include <xcopy.h>
#include <intercept.h>

void
tc_intercept_release_tunnel(int fd, tc_event_t *rev)
{
    tc_log_info(LOG_NOTICE, 0, "release tunnel related resources, fd:%d", fd);
    tc_socket_close(fd);           
#if (INTERCEPT_COMBINED)
    srv_settings.tunnel[fd].fd_valid = false;
    free(srv_settings.tunnel[fd].combined);
    srv_settings.tunnel[fd].combined = NULL;
#endif
    if (rev == NULL) {
        tc_event_del(srv_settings.tunnel[fd].ev->loop, 
                srv_settings.tunnel[fd].ev, TC_EVENT_READ);
        tc_event_destroy(srv_settings.tunnel[fd].ev);
        srv_settings.tunnel[fd].ev = NULL;
    } else {
        tc_event_del(rev->loop, rev, TC_EVENT_READ);
        rev->events = TC_EVENT_NONE;
    }
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
            tc_intercept_release_tunnel(fd, NULL);
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

void 
release_tunnel_resources()
{
    int i;

    for (i = 0; i <= srv_settings.max_fd; i++) {
        if (srv_settings.tunnel[i].fd_valid) {
            tc_intercept_release_tunnel(i, NULL);
        }   
    }   
}


