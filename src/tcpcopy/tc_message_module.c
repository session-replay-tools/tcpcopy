
#include <xcopy.h>
#include <tcpcopy.h>

static int tc_proc_server_msg(tc_event_t *rev);

int
tc_message_init(tc_event_loop_t *event_loop, uint32_t ip, uint16_t port)
{
    int            fd;
    tc_event_t    *ev;
    socklen_t      len;
    struct timeval timeout = {3,0}; 

    if ((fd = tc_socket_init()) == TC_INVALID_SOCK) {
        return TC_INVALID_SOCK;
    }

    if (tc_socket_connect(fd, ip, port) == TC_ERR) {
        return TC_INVALID_SOCK;
    }

    if (tc_socket_set_nodelay(fd) == TC_ERR) {
        return TC_INVALID_SOCK;
    }

    if (tc_socket_set_nonblocking(fd) == TC_ERR) {
        return TC_INVALID_SOCK;
    }

    len = (socklen_t) sizeof(struct timeval);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, len);

    ev = tc_event_create(event_loop->pool, fd, tc_proc_server_msg, NULL);
    if (ev == NULL) {
        return TC_INVALID_SOCK;
    }

    clt_settings.ev[fd] = ev;

    if (tc_event_add(event_loop, ev, TC_EVENT_READ) == TC_EVENT_ERROR) {
        return TC_INVALID_SOCK;
    }


    return fd;
}

static int
tc_proc_server_msg(tc_event_t *rev)
{
    int            i, j;
    conns_t       *conns;
#if (!TC_COMBINED)
    int            len;
    msg_server_t   msg;
#else
    int            num, k;
    unsigned char *p, resp[COMB_LENGTH + sizeof(uint16_t)];
#endif


#if (!TC_COMBINED)
    len = MSG_SERVER_SIZE;
    if (tc_socket_rcv(rev->fd, (char *) &msg, len) != TC_ERR)
#else
    if (tc_socket_cmb_rcv(rev->fd, &num, (char *) resp) != TC_ERR)
#endif
    {
#if (!TC_COMBINED)
        tc_proc_outgress((unsigned char *) &msg);
#else
        tc_log_debug1(LOG_DEBUG, 0, "resp packets:%d", num);
        p = resp + sizeof(uint16_t);
        for (k = 0; k < num; k++) {
            tc_proc_outgress(p);
            p = p + MSG_SERVER_SIZE;
        }
#endif
        return TC_OK;

    } else {

        tc_log_info(LOG_ERR, 0, "Recv socket(%d)error", rev->fd);
        for (i = 0; i < clt_settings.real_servers.num; i++) {

            conns = &(clt_settings.real_servers.conns[i]);
            for (j = 0; j < conns->num; j++) {
                if (conns->fds[j] == rev->fd) {
                    if (conns->fds[j] > 0) {
                        tc_socket_close(conns->fds[j]);
                        tc_log_info(LOG_NOTICE, 0, "close sock:%d", 
                                conns->fds[j]);
                        tc_event_del(rev->loop, rev, TC_EVENT_READ);
                        conns->fds[j] = -1;
                        conns->remained_num--;
                    }
                    if (conns->remained_num == 0 && conns[i].active) {
                        conns[i].active = 0;
                        clt_settings.real_servers.active_num--;
                    }

                    break;
                }
            }
        }

        if (clt_settings.real_servers.active_num == 0) {
            if (!clt_settings.lonely) {
                tc_log_info(LOG_WARN, 0, "active num is zero");
                tc_over = SIGRTMAX;
            }
        } 
        return TC_OK;
    }
}

