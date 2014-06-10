#include <xcopy.h>
#include <intercept.h>

void
tc_intercept_release_tunnel(int fd, tc_event_t *rev)
{
    if (!srv_settings.tunnel[fd].fd_valid) {
        tc_log_info(LOG_WARN, 0, "already released, fd:%d", fd);
        return;
    }

    tc_log_info(LOG_NOTICE, 0, "release tunnel related resources, fd:%d", fd);
    tc_socket_close(fd);           
    srv_settings.tunnel[fd].fd_valid = 0;
#if (INTERCEPT_COMBINED)
    if (srv_settings.tunnel[fd].combined != NULL) {
        free(srv_settings.tunnel[fd].combined);
        srv_settings.tunnel[fd].combined = NULL;
    } else {
        tc_log_info(LOG_NOTICE, 0, "crazy here, combined is null, fd:%d", fd);
    }
#endif
    if (rev == NULL) {
        if (srv_settings.tunnel[fd].ev == NULL) {
            tc_log_info(LOG_NOTICE, 0, "crazy here, ev is null, fd:%d", fd);
        } else {
            tc_event_del(srv_settings.tunnel[fd].ev->loop, 
                    srv_settings.tunnel[fd].ev, TC_EVENT_READ);
            tc_event_destroy(srv_settings.tunnel[fd].ev, 1);
            srv_settings.tunnel[fd].ev = NULL;
        }
    } else {
        tc_event_del(rev->loop, rev, TC_EVENT_READ);
    }
}


#if (TCPCOPY_SINGLE)  
bool  tc_intercept_check_tunnel_for_single(int fd)
{
    int  i, diff, old_fd;
    bool previous_fd_valid = false; 

    if (srv_settings.accepted_tunnel_time == 0) {
        srv_settings.accepted_tunnel_time = tc_current_time_sec;
    }

    diff = tc_current_time_sec - srv_settings.accepted_tunnel_time;

    if (diff > 3) {
        tc_log_info(LOG_WARN, 0, "it does not support distributed clients");
        for (i = 0; i < srv_settings.s_fd_num; i++) {
            old_fd = srv_settings.s_router_fds[i];
            if (srv_settings.tunnel[old_fd].fd_valid) {
                previous_fd_valid = true;
                if (!srv_settings.conn_protected) {
                    tc_intercept_release_tunnel(old_fd, NULL);
                }
            }
        }
        if (srv_settings.conn_protected && previous_fd_valid) {
            return false;
        }
        srv_settings.s_fd_num = 0;
        srv_settings.accepted_tunnel_time = tc_current_time_sec;
    }

    if (srv_settings.s_fd_num < MAX_SINGLE_CONNECTION_NUM) {
        srv_settings.s_router_fds[srv_settings.s_fd_num] = fd;
        srv_settings.s_fd_num++;
    } else {
        tc_log_info(LOG_WARN, 0, "reach the fd limit for single:%d", 
                srv_settings.s_fd_num);
    }

    return true;
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


