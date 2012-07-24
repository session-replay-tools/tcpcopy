
#include "cpy_event.h"

#include "select_server_wrapper.h"
#include "cpy_select_module.h"


static cpy_event_actions_t cpy_event_actions[] = {
    /* old implementing */
    { select_server_create_fake,
      select_server_destroy_fake,
      select_server_add_wrapper,
      select_server_del_wrapper,
      select_server_run_wrapper },

    /* select */
    { cpy_select_create,
      cpy_select_destroy,
      cpy_select_add_event,
      cpy_select_del_event,
      cpy_select_polling },

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


int cpy_event_loop_init(cpy_event_loop_t *loop, int type, int size)
{
    cpy_event_actions_t *actions;

    actions = &cpy_event_actions[type];

    if (actions->create(loop) == CPY_EVENT_ERROR) {
        return CPY_EVENT_ERROR;
    }

    loop->size = size;
    loop->actions = actions;
    loop->active_events = NULL;

    return CPY_EVENT_OK;
}

int cpy_event_add(cpy_event_loop_t *loop, cpy_event_t *ev, int events)
{
    cpy_event_actions_t *actions;

    actions = loop->actions;

    if (events == CPY_EVENT_NONE) {
        return CPY_EVENT_OK;
    }

    return actions->add(loop, ev, events);
}

int cpy_event_del(cpy_event_loop_t *loop, cpy_event_t *ev, int events)
{
    cpy_event_actions_t *actions;

    actions = loop->actions;

    if (events == CPY_EVENT_NONE) {
        return CPY_EVENT_OK;
    }

    return actions->del(loop, ev, events);
}


int cpy_event_process_cycle(cpy_event_loop_t *loop)
{
    int                  ret;
    cpy_event_t         *act_event;
    cpy_event_actions_t *actions;

    actions = loop->actions;

    for ( ;; ) {
        loop->active_events = NULL;

        ret = actions->poll(loop);

        if (ret == CPY_EVENT_ERROR || ret == CPY_EVENT_AGAIN) {
            continue;
        }

        for (act_event = loop->active_events; act_event;
                act_event = act_event->next)
        {
            if (act_event->events & CPY_EVENT_READ) {
                act_event->read_handler(act_event);
            }

            if (act_event->events & CPY_EVENT_WRITE) {
                act_event->write_handler(act_event);
            }
        }
    }

    return CPY_EVENT_OK;
}

cpy_event_t *cpy_event_create(int fd, cpy_event_handler_pt reader,
        cpy_event_handler_pt writer)
{
    cpy_event_t *ev;

    ev = malloc(sizeof(cpy_event_t));
    if (ev == NULL) {
        return NULL;
    }

    ev->index = -1;
    ev->fd = fd;
    ev->next = NULL;
    ev->read_handler = reader;
    ev->write_handler = writer;

    return ev;
}

void cpy_event_destroy(cpy_event_t *ev)
{
    free(ev);
}


