#include <xcopy.h>
#include <intercept.h>

#if (INTERCEPT_COMBINED)

void
buffer_and_send(int fd, msg_server_t *msg)
{
    int                ret = TC_OK, is_send = 0, bytes;
    unsigned char     *p;
    aggregation_t     *aggr;

    if (fd > srv_settings.max_fd) {
        srv_settings.max_fd = fd;
    }

    if (srv_settings.max_fd > MAX_FD_VALUE) {
        tc_log_info(LOG_WARN, 0, "fd is too large:%d", srv_settings.max_fd);
        srv_settings.max_fd = MAX_FD_VALUE;
        return;
    }

    if (!srv_settings.tunnel[fd].fd_valid) {
        tc_log_debug1(LOG_DEBUG, 0, "fd is not valid:%d", fd);
        return;
    }

    aggr = srv_settings.tunnel[fd].combined;
    if (!aggr) {
        aggr = (aggregation_t *) malloc(sizeof(aggregation_t));
        if (aggr == NULL) {
            tc_log_info(LOG_ERR, errno, "can't malloc memory");
        } else {
            tc_log_info(LOG_INFO, 0, "malloc memory for fd:%d", fd);
            memset(aggr, 0, sizeof(aggregation_t));
            aggr->cur_write = aggr->aggr_resp;
            srv_settings.tunnel[fd].combined = aggr;
        }
    }

    if (aggr) {
        if (msg != NULL) {
            p = aggr->cur_write;
            memcpy((char *) p, (char *) msg, MSG_SERVER_SIZE); 
            aggr->cur_write = p + MSG_SERVER_SIZE;
            aggr->num = aggr->num + 1;
        } else {
            if (aggr->num == 0) {
                return;
            }
        }

        if (aggr->num >= srv_settings.cur_combined_num) {
            is_send = NUM_DRIVEN;
        } else if (aggr->access_time < tc_current_time_sec) {
            is_send = TIME_DRIVEN;
        } else if (aggr->access_time == tc_current_time_sec) {
            if (aggr->access_msec != tc_current_time_msec) {
                is_send = TIME_DRIVEN;
            }
        }

        if (is_send) {
            tc_log_debug2(LOG_DEBUG, 0, "combined send:%u, max:%u", 
                    aggr->num, srv_settings.cur_combined_num);
            if (is_send == TIME_DRIVEN) {
                if (aggr->num < srv_settings.cur_combined_num) {
                    if (srv_settings.cur_combined_num > 1) {
                        srv_settings.cur_combined_num--;
                    }
                }
            } else {
                if (srv_settings.cur_combined_num < COMB_MAX_NUM) {
                    srv_settings.cur_combined_num++;
                }
            }
            aggr->num = htons(aggr->num);
            p = (unsigned char *) (&(aggr->num));
            bytes = aggr->cur_write - aggr->aggr_resp + sizeof(aggr->num);
            tc_log_debug1(LOG_DEBUG, 0, "send bytes:%d", bytes);
            ret = tc_socket_send(fd, (char *) p, bytes);
            aggr->num = 0;
            aggr->cur_write = aggr->aggr_resp;
        } 

        aggr->access_time = tc_current_time_sec;
        aggr->access_msec = tc_current_time_msec;

        if (ret == TC_ERROR) {
            tc_intercept_release_tunnel(fd, NULL);
        }
    }
}

void
send_buffered_packets()
{
    int i;

    for (i = 0; i <= srv_settings.max_fd; i++) {
        if (srv_settings.tunnel[i].fd_valid) {
            buffer_and_send(i, NULL);
        }
    }
}

#endif


