
#include "net_event.h"

#include "select_server_wrapper.h"
#include "select_module.h"


static event_actions_t event_actions[] = {
    /* old implementing */
    { select_server_create_fake,
      select_server_destroy_fake,
      select_server_add_wrapper,
      select_server_del_wrapper,
      select_server_run_wrapper },

    /* select */
    { select_create,
      select_destroy,
      select_add_event,
      select_del_event,
      select_polling },

    /* epoll - not implement */
#if 0
    { epoll_create,
      epoll_destroy,
      epoll_add_event,
      epoll_del_event,
      epoll_polling }
#endif
    { NULL, NULL, NULL, NULL, NULL }
};


int event_loop_init(net_event_loop_t *loop, int type, int size,
        event_handler_pt rh, event_handler_pt wh)
{
    int              i;
    event_actions_t *actions;

    actions = &event_actions[type];

    if (actions->create_handler(loop) == EVENT_ERROR) {
        return EVENT_ERROR;
    }

    loop->actives = malloc(size * sizeof(active_event_t));
    if (loop->actives == NULL) {
        return EVENT_ERROR;
    }

    for (i = 0; i < size; i++) {
        loop->actives[i].fd = ACTIVE_FD_END;
        loop->actives[i].events = EV_NONE_EVENT;
    }

    loop->size = size;
    loop->actions = actions;
    loop->read_handler = rh;
    loop->write_handler = wh;

    return EVENT_OK;
}

int process_events_cycle(net_event_loop_t *loop)
{
    int              ret;
    active_event_t  *active;
    event_actions_t *actions;

    actions = loop->actions;
    
    for ( ;; ) {
        ret = actions->poll_handler(loop);

        if (ret == EVENT_ERROR) {
            continue;
        }

        for (active = loop->actives; active->fd != ACTIVE_FD_END; active++) {
            if (active->events & EV_READ_EVENT) {
                loop->read_handler(active->fd);
            }

            if (active->events & EV_WRITE_EVENT) {
                loop->write_handler(active->fd);
            }
        }
    }

    return EVENT_OK;
}

int add_event(net_event_loop_t *loop, int fd, int events)
{
    event_actions_t *actions;

    actions = loop->actions;

    if (events == EV_NONE_EVENT) {
        return EVENT_OK;
    }

    return actions->add_handler(loop, fd, events);
}

int del_event(net_event_loop_t *loop, int fd, int events)
{
    event_actions_t *actions;

    actions = loop->actions;

    if (events == EV_NONE_EVENT) {
        return EVENT_OK;
    }

    return actions->del_handler(loop, fd, events);
}
