
#include "select_server_wrapper.h"

int select_server_create_fake(net_event_loop_t *loop)
{
    return EVENT_OK;
}

int select_server_destroy_fake(net_event_loop_t *loop)
{
    return EVENT_OK;
}

int select_server_add_wrapper(net_event_loop_t *loop, int fd, int events)
{
    select_server_add(fd);

    return EVENT_OK;
}

int select_server_del_wrapper(net_event_loop_t *loop, int fd, int events)
{
    select_server_del(fd);

    return EVENT_OK;
}

int select_server_run_wrapper(net_event_loop_t *loop)
{
    select_server_run2(loop);

    return EVENT_AGAIN;
}


