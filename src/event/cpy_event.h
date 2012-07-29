#ifndef __NET_EVENT_H__
#define __NET_EVENT_H__

#include "../core/xcopy.h"

#define CPY_EVENT_SELECT_OLD   0
#define CPY_EVENT_SELECT       1
#define CPY_EVENT_EPOLL        2

#define CPY_EVENT_OK     0
#define CPY_EVENT_ERROR -1
#define CPY_EVENT_AGAIN  1

#define CPY_EVENT_NONE  0
#define CPY_EVENT_READ  1
#define CPY_EVENT_WRITE 2

#define cpy_event_push_active_event(head, ev) \
    ev->next = head; head = ev; 

typedef int (*ev_create_pt) (cpy_event_loop_t *loop);
typedef int (*ev_destroy_pt) (cpy_event_loop_t *loop);
typedef int (*ev_add_event_pt) (cpy_event_loop_t *loop, cpy_event_t *ev,
        int events);
typedef int (*ev_delete_event_pt) (cpy_event_loop_t *loop, cpy_event_t *ev,
        int events);
typedef int (*ev_event_poll_pt) (cpy_event_loop_t *loop);

typedef void (*cpy_event_handler_pt) (cpy_event_t *ev);

typedef struct {
    ev_create_pt        create;
    ev_destroy_pt       destroy;
    ev_add_event_pt     add;
    ev_delete_event_pt  del;    
    ev_event_poll_pt    poll;
} cpy_event_actions_t;

struct cpy_event_s {
    int                   fd;
    int                   events;
    int                   index;
    cpy_event_handler_pt  read_handler;
    cpy_event_handler_pt  write_handler;
    cpy_event_t          *next;
};

struct cpy_event_loop_s {
    void                *io;
    int                  size;
    cpy_event_t         *active_events;
    cpy_event_actions_t *actions;
};


int cpy_event_loop_init(cpy_event_loop_t *loop, int type, int size);
int cpy_event_process_cycle(cpy_event_loop_t *loop);
int cpy_event_add(cpy_event_loop_t *loop, cpy_event_t *ev, int events);
int cpy_event_del(cpy_event_loop_t *loop, cpy_event_t *ev, int events);

cpy_event_t *cpy_event_create(int fd, cpy_event_handler_pt reader,
        cpy_event_handler_pt writer);
void cpy_event_destroy(cpy_event_t *ev);

#endif  /* __NET_EVENT_H__ */
