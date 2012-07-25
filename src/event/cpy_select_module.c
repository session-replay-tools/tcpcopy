#include "cpy_select_module.h"

int cpy_select_create (cpy_event_loop_t *loop)
{
    cpy_event_t               **evs;
    cpy_select_multiplex_io_t  *io;

    evs = malloc(loop->size * sizeof(cpy_event_t *));
    if (evs == NULL) {
        return CPY_EVENT_ERROR;
    }

    io = malloc(sizeof(cpy_select_multiplex_io_t));
    if (io == NULL) {
        return CPY_EVENT_ERROR;
    }

    FD_ZERO(&io->r_set);
    FD_ZERO(&io->w_set);

    io->max_fd = -1;
    io->last = 0;
    io->evs = evs;

    io->timeout.tv_sec = (long) 0;
    io->timeout.tv_usec = (long) 500000;

    loop->io = io;

    return CPY_EVENT_OK;
}

int cpy_select_destroy (cpy_event_loop_t *loop)
{
    cpy_select_multiplex_io_t *io;
    
    io = loop->io;

    free(io->evs);
    free(loop->io);

    return CPY_EVENT_OK;
}

int cpy_select_add_event(cpy_event_loop_t *loop, cpy_event_t *ev, int events)
{
    cpy_select_multiplex_io_t *io;

    io = loop->io;

    if (io->last >= loop->size) {
        /* too many */
        return CPY_EVENT_ERROR;
    }

    if (events == CPY_EVENT_READ && ev->read_handler
            && ev->write_handler == NULL)
    {
        FD_SET(ev->fd, &io->r_set);
    } else if (events == CPY_EVENT_WRITE && ev->write_handler
            && ev->read_handler == NULL)
    {
        FD_SET(ev->fd, &io->w_set);
    } else {
        return CPY_EVENT_ERROR;
    }
        
    if (io->max_fd != -1 && ev->fd > io->max_fd) {
        io->max_fd = ev->fd;
    }

    ev->index = io->last;
    io->evs[io->last++] = ev;

    return CPY_EVENT_OK;
}

int cpy_select_del_event(cpy_event_loop_t *loop, cpy_event_t *ev, int events)
{
    cpy_event_t               *last_ev;
    cpy_select_multiplex_io_t *io;

    io = loop->io;

    if (ev->index < 0 || ev->index >= io->last) {
        return CPY_EVENT_ERROR;
    }

    if (events == CPY_EVENT_READ) {
        FD_CLR(ev->fd, &io->r_set);
    } else if (events == CPY_EVENT_WRITE) {
        FD_CLR(ev->fd, &io->w_set);
    } else {
        return CPY_EVENT_ERROR;
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

    return CPY_EVENT_OK;
}

int cpy_select_polling(cpy_event_loop_t *loop)
{
    int                          i, ret;
    fd_set                       cur_read_set, cur_write_set;
    cpy_event_t                **evs;
    cpy_select_multiplex_io_t   *io;

    io = loop->io;
    evs = io->evs;

    if (io->max_fd == -1) {
        for (i = 0; i < io->last; i++) {
            if (io->max_fd < evs[i]->fd) {
                io->max_fd = evs[i]->fd;
            }
        }
    }

    cur_read_set = io->r_set;
    cur_write_set = io->w_set;

    ret = select(io->max_fd + 1, &cur_read_set, &cur_write_set, NULL,
                 &io->timeout);

    if (ret == -1) {
        return CPY_EVENT_ERROR;
    }

    if (ret == 0) {
        return CPY_EVENT_AGAIN;
    }

    for (i = 0; i < io->last; i++) {
        /* clear the active events, then reset */
        evs[i]->events = CPY_EVENT_NONE;

        if (evs[i]->read_handler) {
            if (FD_ISSET(evs[i]->fd, &cur_read_set)) {
                evs[i]->events |= CPY_EVENT_READ;
                cpy_event_push_active_event(loop->active_events, evs[i]);
            }
        } else {
            if (FD_ISSET(evs[i]->fd, &cur_write_set)) {
                evs[i]->events |= CPY_EVENT_WRITE;
                cpy_event_push_active_event(loop->active_events, evs[i]);
            }
        }
    }

    return CPY_EVENT_OK;
}
