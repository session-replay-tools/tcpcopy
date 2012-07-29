#ifndef __SELECT_MODULE_H__
#define __SELECT_MODULE_H__

#include "../core/xcopy.h"

typedef struct cpy_select_multiplex_io_s   cpy_select_multiplex_io_t;

struct cpy_select_multiplex_io_s {
    int              max_fd;
    int              last;
    fd_set           r_set;
    fd_set           w_set;
    cpy_event_t    **evs;
    struct timeval   timeout;
};


int cpy_select_create(cpy_event_loop_t *loop);
int cpy_select_destroy(cpy_event_loop_t *loop);
int cpy_select_add_event(cpy_event_loop_t *loop, cpy_event_t *ev, int events);
int cpy_select_del_event(cpy_event_loop_t *loop, cpy_event_t *ev, int events);
int cpy_select_polling(cpy_event_loop_t *loop);

#endif
