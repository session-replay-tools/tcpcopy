#ifndef TC_EPOLL_MODULE_INCLUDED
#define TC_EPOLL_MODULE_INCLUDED

#include <xcopy.h>

typedef struct tc_epoll_multiplex_io_s   tc_epoll_multiplex_io_t;

struct tc_epoll_multiplex_io_s {
    int                  max_fd;
    int                  efd;
    tc_event_t         **evs;
    struct epoll_event  *events;
};

int tc_epoll_create(tc_event_loop_t *loop);
int tc_epoll_destroy(tc_event_loop_t *loop);
int tc_epoll_add_event(tc_event_loop_t *loop, tc_event_t *ev, int events);
int tc_epoll_del_event(tc_event_loop_t *loop, tc_event_t *ev, int events);
int tc_epoll_polling(tc_event_loop_t *loop, long timeout);

#endif
