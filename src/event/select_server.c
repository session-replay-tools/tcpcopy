
#include <xcopy.h>

static int                        max_fd, fd_nums, valid_fds[MAX_FD_NUM];
static fd_set                     read_set;
static select_server_func         callback_func;
#if (TCPCOPY_OFFLINE)
static select_server_offline_func offline_func;
#endif

/* Set select event callback function */
void
select_server_set_callback(select_server_func func)
{
    callback_func = func;
}

#if (TCPCOPY_OFFLINE)
/* Set select offline callback function */
void
select_offline_set_callback(select_server_offline_func func)
{
    offline_func = func;
}
#endif

/* Add fd to select read set */
void
select_server_add(int fd)
{
    if (fd > MAX_FD_VALUE) {
        log_info(LOG_WARN, "fd:%d which is more than 1023", fd);
    } else {
        if (fd_nums >= MAX_FD_NUM) {
            log_info(LOG_WARN, "too many fds");
        } else {
            FD_SET(fd, &read_set);
            if (fd > max_fd) {
                max_fd = fd;
            }
            valid_fds[fd_nums] = fd;
            fd_nums++;
        }
    }
}

/* Delete fd from select read set */
void
select_server_del(int fd)
{
    int i, j;

    if (fd <= MAX_FD_VALUE) {
        FD_CLR(fd, &read_set);
        max_fd = 0;
        for (i = 0; i < fd_nums; i++) {
            if (valid_fds[i] == fd) {
                j = i;
                while (j < (fd_nums-1)) {
                    valid_fds[j] = valid_fds[j + 1];
                    if (valid_fds[j] > max_fd) {
                        max_fd = valid_fds[j];
                    }
                    j++;
                }
                fd_nums--;
                break;
            }
            if (valid_fds[i] > max_fd) {
                max_fd = valid_fds[i];
            }
        }
    }
}

/* Run for receiving messages */
void
select_server_run()
{
    int     i, ret;
    fd_set  r_set;
 
    while (true) {
        r_set = read_set;
        ret   = select(max_fd + 1, &r_set, NULL, NULL, NULL);
        if (-1 == ret) {
            continue;
        } else if (0 == ret) {
            continue;
        } else {
            for (i = 0; i < fd_nums; i++ ) {
                if (FD_ISSET(valid_fds[i], &r_set)) {
                    callback_func(valid_fds[i]);
                }
            }
        }
    }
}

/* Run for receiving messages */
void 
select_server_client_run(tc_event_loop_t *loop)
{
    int     i, ret;
    fd_set  r_set;
    struct  timeval timeout; 

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    r_set = read_set;

    ret   = select(max_fd + 1, &r_set, NULL, NULL, &timeout);

    if (-1 == ret) {
        return;
    } else if (0 == ret) {
#if (TCPCOPY_OFFLINE)
            if (offline_func) {
                offline_func(0);
            }
#endif
        return;
    } else {
        for (i = 0; i < fd_nums; i++ ) {
            if (FD_ISSET(valid_fds[i], &r_set)) {
                callback_func(valid_fds[i]);
            }
        }
    }
}

