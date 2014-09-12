#include <xcopy.h>

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

    if (io->last >= loop->size) {
        /* too many */
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

    ev->index = io->last;
    io->evs[io->last++] = ev;

    return TC_EVENT_OK;
}

int tc_epoll_del_event(tc_event_loop_t *loop, tc_event_t *ev, int events)
{
    tc_event_t               *last_ev;
    tc_epoll_multiplex_io_t  *io;
    struct epoll_event        event;

    io = loop->io;

    if (ev->index < 0 || ev->index >= io->last) {
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

    if (ev->index < --(io->last)) {
        last_ev = io->evs[io->last];
        io->evs[ev->index] = last_ev;
        last_ev->index = ev->index;
    }

    ev->index = -1;

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

    //ret = epoll(io->max_fd + 1, &cur_read_set, &cur_write_set, NULL,
    //             &timeout);
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
    //    /* clear the active events, and reset */
    //    evs[i]->events = TC_EVENT_NONE;

    //    if (evs[i]->read_handler) {
    //        if (FD_ISSET(evs[i]->fd, &cur_read_set)) {
    //            evs[i]->events |= TC_EVENT_READ;
    //            tc_event_push_active_event(loop->active_events, evs[i]);
    //        }
    //    } else {
    //        if (FD_ISSET(evs[i]->fd, &cur_write_set)) {
    //            evs[i]->events |= TC_EVENT_WRITE;
    //            tc_event_push_active_event(loop->active_events, evs[i]);
    //        }
    //    }
    }

    return TC_EVENT_OK;
}

