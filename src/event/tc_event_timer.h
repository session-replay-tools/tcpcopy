
#ifndef _TC_EVENT_TIMER_H_INCLUDED_
#define _TC_EVENT_TIMER_H_INCLUDED_


#include <xcopy.h>

#define TC_TIMER_INFINITE  (tc_msec_t) -1

#define TC_TIMER_LAZY_DELAY  1


tc_int_t tc_event_timer_init(void);
tc_msec_t tc_event_find_timer(void);
void tc_event_expire_timers(void);


extern tc_rbtree_t  tc_event_timer_rbtree;


static inline void
tc_event_del_timer(tc_event_timer_t *ev)
{
    tc_log_debug2(LOG_DEBUG, 0, "pool:%llu, del timer:%llu", ev->pool, ev); 
    tc_rbtree_delete(&tc_event_timer_rbtree, &ev->timer);
    ev->timer_set = 0;
}

static inline void
tc_event_update_timer(tc_event_timer_t *ev, tc_msec_t timer)
{
    tc_msec_t         key;
    tc_msec_int_t     diff;

    if (ev != NULL) {
        key = ((tc_msec_t) tc_current_time_msec) + timer;

        if (ev->timer_set) {
            diff = (tc_msec_int_t) (key - ev->timer.key);
            if (tc_abs(diff) < TC_TIMER_LAZY_DELAY) {
                return;
            }
            tc_event_del_timer(ev);
        }

        ev->timer.key = key;

        tc_log_debug2(LOG_DEBUG, 0, "pool:%llu, up timer:%llu", ev->pool, ev);
        tc_rbtree_insert(&tc_event_timer_rbtree, &ev->timer);

        ev->timer_set = 1;
    } else {
        tc_log_info(LOG_WARN, 0, "ev is null");
    }
}

static inline tc_event_timer_t* 
tc_event_add_timer(tc_pool_t *pool, tc_msec_t timer, void *data, 
        tc_event_timer_handler_pt handler)
{
    tc_msec_t         key;
    tc_event_timer_t *ev;

    ev = (tc_event_timer_t *) tc_palloc(pool, sizeof(tc_event_timer_t));
    if (ev != NULL) {
        ev->pool = pool;
        ev->handler = handler;
        ev->data = data;
        key = ((tc_msec_t) tc_current_time_msec) + timer;
        ev->timer.key = key;

        tc_rbtree_insert(&tc_event_timer_rbtree, &ev->timer);

        tc_log_debug2(LOG_DEBUG, 0, "pool:%llu, add timer:%llu", pool, 
                &ev->timer); 

        ev->timer_set = 1;
    }
    return ev;
}


#endif /* _TC_EVENT_TIMER_H_INCLUDED_ */
