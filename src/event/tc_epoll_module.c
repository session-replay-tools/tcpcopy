#include <xcopy.h>
#include <errno.h>

int tc_epoll_create(tc_event_loop_t *loop)
{
    int                        efd = -1;
    tc_event_t               **evs;
    struct epoll_event        *events = NULL;
    tc_epoll_multiplex_io_t   *io;

    evs = tc_palloc(loop->pool, loop->size * sizeof(tc_event_t *));
    if (evs == NULL) {
        return TC_EVENT_ERROR;
    }

    io = tc_palloc(loop->pool, sizeof(tc_epoll_multiplex_io_t));
    if (io == NULL) {
        goto bad;
    }

    efd = epoll_create(MAX_FD_NUM);
    if(efd == -1) {
        tc_log_info(LOG_ERR, 0, "epoll_create failed!");
        goto bad;
    }

    events = tc_pcalloc(loop->pool, (MAX_FD_NUM * sizeof(struct epoll_event)));
    if(events == NULL) {
        tc_log_info(LOG_ERR, 0, "tc_pcalloc struct epoll_event failed!");
        goto bad;
    }

    io->max_fd = -1;
    io->efd = efd;
    io->events = events;
    io->evs = evs;

    loop->io = io;

    return TC_EVENT_OK;

bad:
    tc_pfree(loop->pool, evs);
    tc_pfree(loop->pool, io);
    tc_pfree(loop->pool, events);
    if (efd != -1) {
        close(efd);
    }

    return TC_EVENT_ERROR;
}


int tc_epoll_destroy(tc_event_loop_t *loop)
{
    int                       i;
    tc_event_t               *event;
    tc_epoll_multiplex_io_t  *io;

    io = loop->io;

    for (i = 0; i <= io->max_fd; i++) {
        event = io->evs[i];
        if (event != NULL && event->fd > 0) {
            tc_log_info(LOG_NOTICE, 0, "tc_epoll_destroy, close fd:%d",
                    event->fd);
            tc_socket_close(event->fd);
            event->fd = -1;
        }
        tc_pfree(loop->pool, event);
    }

    if (io->efd) {
        close(io->efd);
        io->efd = -1;
    }
    io->max_fd = -1;

    tc_pfree(loop->pool, io->events);
    tc_pfree(loop->pool, io->evs);
    tc_pfree(loop->pool, loop->io);

    return TC_EVENT_OK;
}


int tc_epoll_add_event(tc_event_loop_t *loop, tc_event_t *ev, int events)
{
    struct epoll_event       event;
    tc_epoll_multiplex_io_t *io;

    io = loop->io;

    if (events == TC_EVENT_NONE) {
        return TC_EVENT_OK;
    }

    if (io->max_fd >= loop->size || ev->fd >= loop->size) {
        /* too many */
        errno = ERANGE;
        return TC_EVENT_ERROR;
    }

    if ((events == TC_EVENT_READ && ev->read_handler
            && ev->write_handler == NULL))
    {
        event.data.u64 = 0;
        event.data.fd = ev->fd;
        event.events = EPOLLIN;
        if(epoll_ctl(io->efd, EPOLL_CTL_ADD, ev->fd, &event) == -1) {
            tc_log_info(LOG_ALERT, 0, "epoll_ctl add read fd failed.");
            return TC_EVENT_ERROR;
        }
    } else if (events == TC_EVENT_WRITE && ev->write_handler
            && ev->read_handler == NULL) 
    {
        event.data.u64 = 0;
        event.data.fd = ev->fd;
        event.events = EPOLLOUT;
        if(epoll_ctl(io->efd, EPOLL_CTL_ADD, ev->fd, &event) == -1) {
            tc_log_info(LOG_ALERT, 0, "epoll_ctl add write fd failed.");
            return TC_EVENT_ERROR;
        }
    } else {
        return TC_EVENT_ERROR;
    }

    io->evs[ev->fd] = ev;

    if(ev->fd >= io->max_fd) {
        io->max_fd = ev->fd;
    }

    return TC_EVENT_OK;
}


int tc_epoll_del_event(tc_event_loop_t *loop, tc_event_t *ev, int delevents)
{
    int                       events;
    struct epoll_event        event;
    tc_epoll_multiplex_io_t  *io;

    events = ev->reg_evs & (~ delevents);

    io = loop->io;

    if (ev->fd >= loop->size || ev->fd > io->max_fd) {
        errno = ERANGE;
        return TC_EVENT_ERROR;
    }

    event.events = 0;
    if (events & TC_EVENT_READ) {
        event.events |= EPOLLIN;
    }

    if (events & TC_EVENT_WRITE) {
        event.events |= EPOLLOUT;
    }

    event.data.u64 = 0;
    event.data.fd = ev->fd;

    if (events != TC_EVENT_NONE) {
        epoll_ctl(io->efd, EPOLL_CTL_MOD, ev->fd, &event);
    } else {
        epoll_ctl(io->efd, EPOLL_CTL_DEL, ev->fd, &event);
    }

    events = ev->reg_evs & (~ delevents);
    if (ev->fd == io->max_fd && events == TC_EVENT_NONE) {
        /* update the max_fd fd */
        int j;

        for (j = io->max_fd - 1; j >= 0; j--) {
            if (io->evs[j] && (io->evs[j])->reg_evs != TC_EVENT_NONE) {
                break;
            }
        }
        io->max_fd = j;
    }

    return TC_EVENT_OK;
}


int tc_epoll_polling(tc_event_loop_t *loop, long to)
{
    int                         i, ret;
    long                        timeout;
    tc_event_t                **evs;
    struct epoll_event         *events;
    tc_epoll_multiplex_io_t    *io;

    io = loop->io;
    evs = io->evs;
    events = io->events;

    timeout = to;

    ret = epoll_wait(io->efd, events, MAX_FD_NUM, timeout);

    if (ret == -1) {
        if (errno == EINTR) {
           return TC_EVENT_AGAIN;
        }
        return TC_EVENT_ERROR;
    }

    if (ret == 0) {
        return TC_EVENT_AGAIN;
    }

    for (i = 0; i < ret; i++) {
        int mask = 0;
        struct epoll_event *e = events + i;
        int fd = e->data.fd;
        /* clear the active events, and reset */
        evs[fd]->events = TC_EVENT_NONE;

        if (e->events & EPOLLIN) {
            mask |= TC_EVENT_READ;
        }

        if ((e->events & EPOLLOUT) || (e->events & EPOLLERR) || 
                (e->events & EPOLLHUP)) 
        {
            mask |= TC_EVENT_WRITE;
        }

        evs[fd]->events |= mask;
        tc_event_push_active_event(loop->active_events, evs[fd]);
    }

    return TC_EVENT_OK;
}

