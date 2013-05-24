
#include <xcopy.h>

tc_atomic_t  tc_over = 0;

static long tc_event_timer_find(tc_event_loop_t *loop);
static void tc_event_timer_run(tc_event_loop_t *loop);

static tc_event_actions_t tc_event_actions = {
    tc_select_create,
    tc_select_destroy,
    tc_select_add_event,
    tc_select_del_event,
    tc_select_polling 
};


int tc_event_loop_init(tc_event_loop_t *loop, int size)
{
    tc_event_actions_t *actions;

    actions = &tc_event_actions;

    loop->size = size;
    loop->actions = actions;
    loop->active_events = NULL;
    loop->timers = NULL;

    if (actions->create(loop) == TC_EVENT_ERROR) {
        return TC_EVENT_ERROR;
    }

    return TC_EVENT_OK;
}

int tc_event_loop_finish(tc_event_loop_t *loop)
{
    tc_event_timer_t   *timer, *curr;
    tc_event_actions_t *actions;

    actions = loop->actions;

    if (actions != NULL) {
        /* destroy io module */
        actions->destroy(loop);

        loop->actions = NULL;
    }

    /* destroy all timers */
    for (timer = loop->timers; timer; ) {
        curr = timer;
        timer = timer->next;

        free(curr);
    }

    loop->timers = NULL;

    return TC_EVENT_OK;
}

int tc_event_add(tc_event_loop_t *loop, tc_event_t *ev, int events)
{
    tc_event_actions_t *actions;

    ev->loop = loop;
    actions = loop->actions;

    if (events == TC_EVENT_NONE) {
        return TC_EVENT_OK;
    }

    if (actions->add(loop, ev, events) == TC_EVENT_ERROR) {
        return TC_EVENT_ERROR;
    }

    if (events & TC_EVENT_READ) {
        ev->reg_evs |= TC_EVENT_READ;
    }

    if (events & TC_EVENT_WRITE) {
        ev->reg_evs |= TC_EVENT_WRITE;
    }

    return TC_EVENT_OK;
}

int tc_event_del(tc_event_loop_t *loop, tc_event_t *ev, int events)
{
    tc_event_actions_t *actions;

    actions = loop->actions;

    if (events == TC_EVENT_NONE) {
        return TC_EVENT_OK;
    }

    if (actions->del(loop, ev, events) == TC_EVENT_ERROR) {
        return TC_EVENT_ERROR;
    }

    if (events & TC_EVENT_READ) {
        ev->reg_evs &= ~TC_EVENT_READ;
    }

    if (events & TC_EVENT_WRITE) {
        ev->reg_evs &= ~TC_EVENT_WRITE; 
    }

    return TC_EVENT_OK;
}


int tc_event_process_cycle(tc_event_loop_t *loop)
{
    int                  ret;
    long                 timeout;
    tc_event_t          *act_event, *act_next;
    tc_event_actions_t  *actions;

    actions = loop->actions;

    for ( ;; ) {
        timeout = tc_event_timer_find(loop);
        if (timeout == 0 || timeout > 1000) {
            timeout = 500;
        }

        loop->active_events = NULL;

        ret = actions->poll(loop, timeout);

        if (tc_over) {
            goto FINISH;
        }

        if (tc_update_time) {
            tc_time_update();
            tc_update_time = 0;
        }

        tc_event_timer_run(loop);

        if (ret == TC_EVENT_ERROR || ret == TC_EVENT_AGAIN) {
            continue;
        }

        for (act_event = loop->active_events; act_event; act_event = act_next) {
            act_next = act_event->next;

            if (act_event->events & TC_EVENT_READ) {
                if (act_event->read_handler(act_event) == TC_ERR_EXIT) {
                    goto FINISH;
                }
            }

            if (act_event->events & TC_EVENT_WRITE) {
                if (act_event->write_handler(act_event) == TC_ERR_EXIT) {
                    goto FINISH;
                }
            }

            if (act_event->reg_evs == TC_EVENT_NONE) {
                tc_event_destroy(act_event);
            }
        }
    }

FINISH:
    return TC_EVENT_OK;
}

tc_event_t *tc_event_create(int fd, tc_event_handler_pt reader,
        tc_event_handler_pt writer)
{
    tc_event_t *ev;

    ev = malloc(sizeof(tc_event_t));
    if (ev == NULL) {
        return NULL;
    }

    ev->events = 0;
    ev->reg_evs = 0;
    ev->index = -1;
    ev->fd = fd;
    ev->next = NULL;
    ev->read_handler = reader;
    ev->write_handler = writer;

    return ev;
}

void tc_event_destroy(tc_event_t *ev)
{
    ev->loop = NULL;
    ev->read_handler = NULL;
    ev->write_handler = NULL;

    free(ev);
}


int tc_event_timer_add(tc_event_loop_t *loop, long msec,
        tc_event_timer_handler_pt handler)
{
    tc_event_timer_t *timer;

    timer = malloc(sizeof(tc_event_timer_t));
    if (timer == NULL) {
        return TC_EVENT_ERROR;
    }


    timer->handler = handler;
    timer->msec = tc_current_time_msec + msec;

    timer->next = loop->timers;
    loop->timers = timer;

    return TC_EVENT_OK;
}

static long tc_event_timer_find(tc_event_loop_t *loop)
{
    long              min;
    tc_event_timer_t *timer;

    min   = 0;
    timer = loop->timers;

    if (timer) {
        min   = timer->msec;
        timer = timer->next;

        for (; timer; timer = timer->next) {
            if (timer->msec < min) {
                min = timer->msec;
            }
        }
    }

    if (min > 0) {
        min -= tc_current_time_msec;
    }

    return min < 0 ? 0 : min;
}

static void tc_event_timer_run(tc_event_loop_t *loop)
{
    tc_event_timer_t *timer, *prev, *next;

    prev = NULL;

    for (timer = loop->timers; timer; ) {
        if (timer->msec <= tc_current_time_msec && timer->handler) {
            timer->handler(timer);

            if (timer->handler == NULL) {
                if (prev) {
                    prev->next = timer->next;
                } else {
                    loop->timers = timer->next;
                }

                next = timer->next;
                free(timer);
                timer = next;

                continue;
            }
        }

        prev = timer;
        timer = timer->next;
    }
}


