#include <xcopy.h>

int tc_select_create(tc_event_loop_t *loop)
{
    tc_event_t               **evs;
    tc_select_multiplex_io_t  *io;

    evs = malloc(loop->size * sizeof(tc_event_t *));
    if (evs == NULL) {
        return TC_EVENT_ERROR;
    }

    io = malloc(sizeof(tc_select_multiplex_io_t));
    if (io == NULL) {
        free(evs);
        return TC_EVENT_ERROR;
    }

    FD_ZERO(&io->r_set);
    FD_ZERO(&io->w_set);

    io->max_fd = -1;
    io->last = 0;
    io->evs = evs;

    loop->io = io;

    return TC_EVENT_OK;
}

int tc_select_destroy(tc_event_loop_t *loop)
{
    int                       i;
    tc_event_t               *event;
    tc_select_multiplex_io_t *io;
    
    io = loop->io;

    for (i = 0; i < io->last; i++) {
        event = io->evs[i];
        if (event->fd > 0) {
            close(event->fd);
        }
        event->fd = -1;
        free(event);
    }

    free(io->evs);
    free(loop->io);

    return TC_EVENT_OK;
}

int tc_select_add_event(tc_event_loop_t *loop, tc_event_t *ev, int events)
{
    tc_select_multiplex_io_t *io;

    io = loop->io;

    if (io->last >= loop->size) {
        /* too many */
        return TC_EVENT_ERROR;
    }

    if (events == TC_EVENT_READ && ev->read_handler
            && ev->write_handler == NULL)
    {
        FD_SET(ev->fd, &io->r_set);
    } else if (events == TC_EVENT_WRITE && ev->write_handler
            && ev->read_handler == NULL)
    {
        FD_SET(ev->fd, &io->w_set);
    } else {
        return TC_EVENT_ERROR;
    }
        
    if (io->max_fd != -1 && ev->fd > io->max_fd) {
        io->max_fd = ev->fd;
    }

    ev->index = io->last;
    io->evs[io->last++] = ev;

    return TC_EVENT_OK;
}

int tc_select_del_event(tc_event_loop_t *loop, tc_event_t *ev, int events)
{
    tc_event_t               *last_ev;
    tc_select_multiplex_io_t *io;

    io = loop->io;

    if (ev->index < 0 || ev->index >= io->last) {
        return TC_EVENT_ERROR;
    }

    if (events == TC_EVENT_READ) {
        FD_CLR(ev->fd, &io->r_set);
    } else if (events == TC_EVENT_WRITE) {
        FD_CLR(ev->fd, &io->w_set);
    } else {
        return TC_EVENT_ERROR;
    }

    if (ev->index < --(io->last)) {
        last_ev = io->evs[io->last];
        io->evs[ev->index] = last_ev;
        last_ev->index = ev->index;
    }

    ev->index = -1;

    if (io->max_fd == ev->fd) {
        io->max_fd = -1;
    }

    return TC_EVENT_OK;
}

int tc_select_polling(tc_event_loop_t *loop, long to)
{
    int                         i, ret;
    fd_set                      cur_read_set, cur_write_set;
    tc_event_t                **evs;
    struct timeval              timeout;
    tc_select_multiplex_io_t   *io;

    io = loop->io;
    evs = io->evs;

    if (io->max_fd == -1) {
        for (i = 0; i < io->last; i++) {
            if (io->max_fd < evs[i]->fd) {
                io->max_fd = evs[i]->fd;
            }
        }
    }

    timeout.tv_sec = (long) (to / 1000);
    timeout.tv_usec = (long) ((to % 1000) * 1000);

    cur_read_set = io->r_set;
    cur_write_set = io->w_set;

    ret = select(io->max_fd + 1, &cur_read_set, &cur_write_set, NULL,
                 &timeout);

    if (ret == -1) {
        return TC_EVENT_ERROR;
    }

    if (ret == 0) {
        return TC_EVENT_AGAIN;
    }

    for (i = 0; i < io->last; i++) {
        /* clear the active events, and reset */
        evs[i]->events = TC_EVENT_NONE;

        if (evs[i]->read_handler) {
            if (FD_ISSET(evs[i]->fd, &cur_read_set)) {
                evs[i]->events |= TC_EVENT_READ;
                tc_event_push_active_event(loop->active_events, evs[i]);
            }
        } else {
            if (FD_ISSET(evs[i]->fd, &cur_write_set)) {
                evs[i]->events |= TC_EVENT_WRITE;
                tc_event_push_active_event(loop->active_events, evs[i]);
            }
        }
    }

    return TC_EVENT_OK;
}
