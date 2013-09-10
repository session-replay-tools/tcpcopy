#include <xcopy.h>
#include <intercept.h>

#if (INTERCEPT_COMBINED)
static aggregation_t  *combined[MAX_FD_NUM];
static int             fd_invalid[MAX_FD_NUM];
static int             max_fd = 0;

void
buffer_and_send(int mfd, int fd, msg_server_t *msg)
{
    int                  ret = TC_OK, is_send = 0, bytes;
    unsigned char       *p;
    aggregation_t       *aggr;

#if (TCPCOPY_SINGLE)
    if (mfd == 0) {
        return;
    }
#endif

    if (fd > max_fd) {
        max_fd = fd;
    }

    if (max_fd > MAX_FD_VALUE) {
        tc_log_info(LOG_WARN, 0, "fd is too large:%d", max_fd);
        max_fd = MAX_FD_VALUE;
        return;
    }

    if (fd_invalid[fd]) {
        return;
    }

    aggr = combined[fd];
    if (!aggr) {
        aggr = (aggregation_t *) malloc(sizeof(aggregation_t));
        if (aggr == NULL) {
            tc_log_info(LOG_ERR, errno, "can't malloc memory");
        } else {
            tc_log_info(LOG_INFO, 0, "malloc memory for fd:%d", fd);
            memset(aggr, 0, sizeof(aggregation_t));
            aggr->cur_write = aggr->aggr_resp;
            combined[fd] = aggr;
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

        if (aggr->num == COMB_MAX_NUM) {
            is_send = 1;
        } else if (aggr->access_time < tc_current_time_sec) {
            is_send = 1;
        } else if (aggr->access_time == tc_current_time_sec) {
            if (aggr->access_msec != tc_current_time_msec) {
                is_send = 1;
            }
        }

        if (is_send) {
            tc_log_debug1(LOG_DEBUG, 0, "combined send:%d", aggr->num);
            aggr->num = htons(aggr->num);
            p = (unsigned char *) (&(aggr->num));
            bytes = aggr->cur_write - aggr->aggr_resp + sizeof(aggr->num);
            tc_log_debug1(LOG_DEBUG, 0, "send bytes:%d", bytes);
#if (!TCPCOPY_SINGLE)
            ret = tc_socket_send(fd, (char *) p, bytes);
#else
            ret = tc_socket_send(mfd, (char *) p, bytes);
#endif
            aggr->num = 0;
            aggr->cur_write = aggr->aggr_resp;
        } 

        aggr->access_time = tc_current_time_sec;
        aggr->access_msec = tc_current_time_msec;

        if (ret == TC_ERROR) {
            fd_invalid[fd] = 1;
            free(combined[fd]);
            combined[fd] = NULL;
        }
    }
}

void
send_buffered_packets(time_t cur_time)
{
    int i;

    for (i = 0; i <= max_fd; i++) {
        if (combined[i] != NULL) {
            buffer_and_send(srv_settings.router_fd, i, NULL);
        }
    }
}

void
release_combined_resouces()
{
    int i;

    for (i = 0; i <= max_fd; i++) {
        if (combined[i] != NULL) {
            free(combined[i]);
            combined[i] = NULL;
            tc_log_info(LOG_NOTICE, 0, "release resources for fd %d", i);
        }
    }
}

#endif


