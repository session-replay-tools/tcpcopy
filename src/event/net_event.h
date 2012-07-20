#ifndef __NET_EVENT_H__
#define __NET_EVENT_H__

#include <stdlib.h>

#define EV_SELECT_OLD   0
#define EV_SELECT       1
#define EV_EPOLL        2

#define EVENT_OK     0
#define EVENT_ERROR -1

#define EV_NONE_EVENT  0
#define EV_READ_EVENT  1
#define EV_WRITE_EVENT 2

#define ACTIVE_FD_END   -1


typedef struct net_event_loop_s     net_event_loop_t;
typedef struct active_event_s       active_event_t;

typedef int (*ev_create_pt) (net_event_loop_t *loop);
typedef int (*ev_destroy_pt) (net_event_loop_t *loop);
typedef int (*ev_add_event_pt) (net_event_loop_t *loop, int fd, int events);
typedef int (*ev_delete_event_pt) (net_event_loop_t *loop, int fd, int events);
typedef int (*ev_event_poll_pt) (net_event_loop_t *loop);

typedef void (*event_handler_pt) (int fd);

typedef struct {
    ev_create_pt        create_handler;
    ev_destroy_pt       destroy_handler;
    ev_add_event_pt     add_handler;
    ev_delete_event_pt  del_handler;    
    ev_event_poll_pt    poll_handler;
} event_actions_t;

struct active_event_s {
    int fd;
    int events;
};

struct net_event_loop_s {
    void               *io;
    int                 size;
    event_actions_t    *actions;
    active_event_t     *actives;
    event_handler_pt    read_handler;
    event_handler_pt    write_handler;
};


int event_loop_init(net_event_loop_t *loop, int type, int size,
        event_handler_pt rh, event_handler_pt wh);
int process_events(net_event_loop_t *loop);
int add_event(net_event_loop_t *loop, int fd, int events);
int del_event(net_event_loop_t *loop, int fd, int events);

#endif  /* __NET_EVENT_H__ */
