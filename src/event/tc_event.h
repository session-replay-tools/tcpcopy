#ifndef TC_EVENT_H
#define TC_EVENT_H

#include <xcopy.h>

#define TC_EVENT_SELECT_OLD   0
#define TC_EVENT_SELECT       1
#define TC_EVENT_EPOLL        2

#define TC_EVENT_OK     0
#define TC_EVENT_ERROR -1
#define TC_EVENT_AGAIN  1

#define TC_EVENT_NONE  0
#define TC_EVENT_READ  1
#define TC_EVENT_WRITE 2

#define tc_event_push_active_event(head, ev) \
    ev->next = head; head = ev; 

typedef struct tc_event_loop_s tc_event_loop_t;
typedef struct tc_event_s      tc_event_t;
typedef struct tc_event_timer_s tc_event_timer_t;

typedef int (*ev_create_pt) (tc_event_loop_t *loop);
typedef int (*ev_destroy_pt) (tc_event_loop_t *loop);
typedef int (*ev_add_event_pt) (tc_event_loop_t *loop, tc_event_t *ev,
        int events);
typedef int (*ev_delete_event_pt) (tc_event_loop_t *loop, tc_event_t *ev,
        int events);
typedef int (*ev_event_poll_pt) (tc_event_loop_t *loop, long timeout);

typedef int (*tc_event_handler_pt) (tc_event_t *ev);
typedef void (*tc_event_timer_handler_pt) (tc_event_timer_t *evt);

typedef struct {
    ev_create_pt        create;
    ev_destroy_pt       destroy;
    ev_add_event_pt     add;
    ev_delete_event_pt  del;    
    ev_event_poll_pt    poll;
} tc_event_actions_t;

struct tc_event_s {
    int                  fd;
    int                  events;
    int                  reg_evs;
    int                  index;
    tc_event_loop_t     *loop;
    tc_event_handler_pt  read_handler;
    tc_event_handler_pt  write_handler;
    tc_event_t          *next;
};

struct tc_event_timer_s {
    long                       msec;
    tc_event_timer_handler_pt  handler;
    tc_event_timer_t          *next;
};

struct tc_event_loop_s {
    void               *io;
    int                 size;
    tc_event_t         *active_events;
    tc_event_actions_t *actions;
    tc_event_timer_t   *timers;
};


int tc_event_loop_init(tc_event_loop_t *loop, int size);
int tc_event_loop_finish(tc_event_loop_t *loop);
int tc_event_process_cycle(tc_event_loop_t *loop);
int tc_event_add(tc_event_loop_t *loop, tc_event_t *ev, int events);
int tc_event_del(tc_event_loop_t *loop, tc_event_t *ev, int events);

tc_event_t *tc_event_create(int fd, tc_event_handler_pt reader,
        tc_event_handler_pt writer);
void tc_event_destroy(tc_event_t *ev);

int tc_event_timer_add(tc_event_loop_t *loop, long timer,
        tc_event_timer_handler_pt handler);

extern tc_atomic_t  tc_over;

#endif  /* TC_EVENT_H */
