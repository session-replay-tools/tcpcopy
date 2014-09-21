#include <xcopy.h>
#include <errno.h>

int tc_epoll_create(tc_event_loop_t *loop)
{
    tc_event_t               **evs;
    tc_epoll_multiplex_io_t   *io;
    struct epoll_event        *events;
    int                        efd;

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

    for (i = 0; i < io->last; i++) {
        event = io->evs[i];
        if (event->fd > 0) {
            tc_log_info(LOG_NOTICE, 0, "tc_epoll_destroy, close fd:%d",
                    event->fd);
            tc_socket_close(event->fd);
        }
        event->fd = -1;
        tc_pfree(loop->pool, event);
    }

    if (io->efd) {
        close(io->efd);
        io->efd = -1;
    }

    tc_pfree(loop->pool, io->events);
    tc_pfree(loop->pool, io->evs);
    tc_pfree(loop->pool, loop->io);

    return TC_EVENT_OK;
}

int tc_epoll_add_event(tc_event_loop_t *loop, tc_event_t *ev, int events)
{
    tc_epoll_multiplex_io_t *io;
    struct epoll_event       event;

    io = loop->io;

    if (io->last >= loop->size || ev->fd >= loop->size) {
        /* too many */
        errno = ERANGE;
        return TC_EVENT_ERROR;
    }

    if ((events == TC_EVENT_READ && ev->read_handler
            && ev->write_handler == NULL))
    {
        event.data.fd = ev->fd;
        event.events = EPOLLIN;
        if(epoll_ctl(io->efd, EPOLL_CTL_ADD, ev->fd, &event) == -1) {
            tc_log_info(LOG_ALERT, 0, "epoll_ctl ADD fd failed.");
            return TC_EVENT_ERROR;
        }
    } else if (events == TC_EVENT_WRITE && ev->write_handler
            && ev->read_handler == NULL) {
        event.data.fd = ev->fd;
        event.events = EPOLLOUT;
        if(epoll_ctl(io->efd, EPOLL_CTL_ADD, ev->fd, &event) == -1) {
            tc_log_info(LOG_ALERT, 0, "epoll_ctl ADD fd failed.");
            return TC_EVENT_ERROR;
        }
    } else {
        return TC_EVENT_ERROR;
    }

    io->evs[ev->fd] = ev;
    if(ev->fd >= io->last)
        io->last = ev->fd;

    return TC_EVENT_OK;
}

int tc_epoll_del_event(tc_event_loop_t *loop, tc_event_t *ev, int events)
{
    //tc_event_t               *last_ev;
    tc_epoll_multiplex_io_t  *io;
    struct epoll_event        event;

    io = loop->io;

    if (events == TC_EVENT_NONE)
        return TC_EVENT_OK;

    if (ev->fd >= loop->size || ev->fd > io->last) {
        errno = ERANGE;
        return TC_EVENT_ERROR;
    }

    if (events == TC_EVENT_READ || events == TC_EVENT_WRITE) {
        event.data.fd = ev->fd;
        //TODO: check diff of the below two module
        //event.events = EPOLLIN | EPOLLET;
        event.events = EPOLLIN;
        if(epoll_ctl(io->efd, EPOLL_CTL_DEL, ev->fd, &event) == -1) {
            tc_log_info(LOG_ALERT, 0, "epoll_ctl DEL fd failed.");
            return TC_EVENT_ERROR;
        }
    } else {
        return TC_EVENT_ERROR;
    }

    ev->events = ev->events & (~events);
    if (ev->fd == io->last && ev->events == TC_EVENT_NONE) {
        /* update the last fd */
        int j;

        for (j = io->last-1; j >= 0; j--)
            if ((io->evs[j])->events != TC_EVENT_NONE) break;
        io->last = j;
    }

    return TC_EVENT_OK;
}

int tc_epoll_polling(tc_event_loop_t *loop, long to)
{
    int                         i, ret;
    tc_event_t                **evs;
    long                        timeout;
    tc_epoll_multiplex_io_t    *io;
    struct epoll_event         *events;

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
    //    /* clear the active events, and reset */
    //    evs[i]->events = TC_EVENT_NONE;
        evs[fd]->events = TC_EVENT_NONE;

        if (e->events & EPOLLIN) mask |= TC_EVENT_READ;
        if (e->events & EPOLLOUT) mask |= TC_EVENT_WRITE;
        if (e->events & EPOLLERR) mask |= TC_EVENT_WRITE;
        if (e->events & EPOLLHUP) mask |= TC_EVENT_WRITE;

        if (evs[fd]->read_handler) {
            evs[fd]->events |= mask;
            tc_event_push_active_event(loop->active_events, evs[fd]);
        } else {
            evs[fd]->events |= mask;
            tc_event_push_active_event(loop->active_events, evs[fd]);
        }
    }

    return TC_EVENT_OK;
}

