#ifndef __SELECT_MODULE_H__
#define __SELECT_MODULE_H__

#include <sys/select.h>

#include "../core/xcopy.h"
#include "net_event.h"

typedef struct select_multiplex_io_s   select_multiplex_io_t;

struct select_multiplex_io_s {
    int     max_fd;
    int     last;
    int     fds[MAX_FD_NUM];
    fd_set  r_set;
    fd_set  w_set;
};


int select_create (net_event_loop_t *loop);
int select_destroy (net_event_loop_t *loop);
int select_add_event(net_event_loop_t *loop, int fd, int events);
int select_del_event(net_event_loop_t *loop, int fd, int events);
int select_polling(net_event_loop_t *loop);

#endif
