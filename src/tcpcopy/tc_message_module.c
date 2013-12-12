
#include <xcopy.h>
#include <tcpcopy.h>

static int tc_process_server_msg(tc_event_t *rev);

int
tc_message_init(tc_event_loop_t *event_loop, uint32_t ip, uint16_t port)
{
    int            fd;
    tc_event_t    *ev;

#if (TCPCOPY_DR)
    socklen_t      len;
    struct timeval timeout = {3,0}; 
#endif

    if ((fd = tc_socket_init()) == TC_INVALID_SOCKET) {
        return TC_INVALID_SOCKET;
    }

    if (tc_socket_connect(fd, ip, port) == TC_ERROR) {
        return TC_INVALID_SOCKET;
    }

    if (tc_socket_set_nodelay(fd) == TC_ERROR) {
        return TC_INVALID_SOCKET;
    }
#if (TCPCOPY_COMBINED)
    if (tc_socket_set_nonblocking(fd) == TC_ERROR) {
        return TC_INVALID_SOCKET;
    }
#endif

#if (TCPCOPY_DR)
    len = (socklen_t) sizeof(struct timeval);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, len);
#endif

    ev = tc_event_create(fd, tc_process_server_msg, NULL);
    if (ev == NULL) {
        return TC_INVALID_SOCKET;
    }

    clt_settings.ev[fd] = ev;

    if (tc_event_add(event_loop, ev, TC_EVENT_READ) == TC_EVENT_ERROR) {
        return TC_INVALID_SOCKET;
    }


    return fd;
}

static int
tc_process_server_msg(tc_event_t *rev)
{
#if (TCPCOPY_DR)
    int            i, j;
    connections_t *connections;
#endif
#if (!TCPCOPY_COMBINED)
    int            len;
    msg_server_t   msg;
#else
    int            num, k;
    unsigned char *p, aggr_resp[COMB_LENGTH + sizeof(uint16_t)];
#endif

#if (!TCPCOPY_COMBINED)
    len = MSG_SERVER_SIZE;
#endif

#if (!TCPCOPY_COMBINED)
    if (tc_socket_recv(rev->fd, (char *) &msg, len) == TC_ERROR)
#else
    if (tc_socket_cmb_recv(rev->fd, &num, (char *) aggr_resp) == TC_ERROR)
#endif
    {
        tc_log_info(LOG_ERR, 0, "Recv socket(%d)error", rev->fd);
#if (TCPCOPY_DR)
        for (i = 0; i < clt_settings.real_servers.num; i++) {

            connections = &(clt_settings.real_servers.connections[i]);
            for (j = 0; j < connections->num; j++) {
                if (connections->fds[j] == rev->fd) {
                    if (connections->fds[j] > 0) {
                        tc_socket_close(connections->fds[j]);
                        tc_log_info(LOG_NOTICE, 0, "close sock:%d", 
                                connections->fds[j]);
                        tc_event_del(rev->loop, rev, TC_EVENT_READ);
                        connections->fds[j] = -1;
                        connections->remained_num--;
                    }
                    if (connections->remained_num == 0 && 
                            clt_settings.real_servers.active[i]) 
                    {
                        clt_settings.real_servers.active[i] = 0;
                        clt_settings.real_servers.active_num--;
                    }

                    break;
                }
            }
        }

        if (clt_settings.real_servers.active_num == 0) {
            if (!clt_settings.lonely) {
                tc_over = SIGRTMAX;
            }
        } 
        return TC_OK;
#else 
        tc_event_del(rev->loop, rev, TC_EVENT_READ);

        return TC_ERR_EXIT;
#endif
    }

#if (!TCPCOPY_COMBINED)
    process_out((unsigned char *) &msg);
#else
    tc_log_debug1(LOG_DEBUG, 0, "resp packets:%d", num);
    p = aggr_resp + sizeof(uint16_t);
    for (k = 0; k < num; k++) {
        process_out(p);
        p = p + MSG_SERVER_SIZE;
    }
#endif

    return TC_OK;
}


