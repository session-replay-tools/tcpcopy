#include "select_module.h"

int select_create (net_event_loop_t *loop)
{
    select_multiplex_io_t *io;

    io = malloc(sizeof(select_multiplex_io_t));
    if (io == NULL) {
        return EVENT_ERROR;
    }

    FD_ZERO(&io->r_set);
    FD_ZERO(&io->w_set);

    io->max_fd = -1;
    io->last = 0;

    loop->io = io;

    return EVENT_OK;
}

int select_destroy (net_event_loop_t *loop)
{
    free(loop->io);

    return EVENT_OK;
}

// TODO the function has defect, it can't add 'write event'.
int select_add_event(net_event_loop_t *loop, int fd, int events)
{
    select_multiplex_io_t *io;

    io = loop->io;

    if (fd > MAX_FD_VALUE || (events & EV_READ_EVENT) == 0) {
        log_info(LOG_WARN, "fd:%d which is more than 1023", fd);
        return EVENT_ERROR;
    }

    if (io->last >= MAX_FD_NUM) {  
        log_info(LOG_WARN, "too many fds");
        return EVENT_ERROR;

    }

    if (events & EV_READ_EVENT) {
        FD_SET(fd, &io->r_set);
    }
        
    if (fd > io->max_fd) {
        io->max_fd = fd;
    }

    io->fds[io->last] = fd;
    io->last++;

    return EVENT_OK;
}

// TODO the function need to optimize
int select_del_event(net_event_loop_t *loop, int fd, int events)
{
    int                    i, j;
    select_multiplex_io_t *io;

    io = loop->io;

    if (fd > MAX_FD_VALUE || (events & EV_READ_EVENT) == 0) {
        return EVENT_ERROR;
    }

    FD_CLR(fd, &io->r_set);

    io->max_fd = 0;

    for (i = 0; i < io->last; i++) {
        if (io->fds[i] == fd) {
            j = i;

            while (j < io->last - 1) {
                io->fds[j] = io->fds[j + 1];

                if (io->fds[j] > io->max_fd) {
                   io->max_fd = io->fds[j];
                }

                j++;
            }

            io->last--;
            break;
        }

        if (io->fds[i] > io->max_fd) {
            io->max_fd = io->fds[i];
        }
    }

    return EVENT_OK;
}

int select_polling(net_event_loop_t *loop)
{
    int                     i, ret;
    fd_set                  cur_read_set;
    active_event_t         *active;
    select_multiplex_io_t  *io;

    io = loop->io;
    active = loop->actives;

    cur_read_set = io->r_set;

    ret = select(io->max_fd + 1, &cur_read_set, NULL, NULL, NULL);

    if (ret == -1) {
        return EVENT_ERROR;
    }

    if (ret == 0) {
        return EVENT_AGAIN;
    }


    for (i = 0; i < io->last; i++) {
        if (FD_ISSET(io->fds[i], &cur_read_set)) {
            active->fd = io->fds[i];
            active->events = EV_READ_EVENT;
            active++;
        }
    }

    active->fd = ACTIVE_FD_END;
    active->events = EV_NONE_EVENT;

    return EVENT_OK;
}
