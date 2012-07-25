
#include "select_server_wrapper.h"
#include "select_server.h"
#include "../tcpcopy/manager.h"

int select_server_create_fake(cpy_event_loop_t *loop)
{
    select_server_set_callback(dispose_event);
    return CPY_EVENT_OK;
}

int select_server_destroy_fake(cpy_event_loop_t *loop)
{
    return CPY_EVENT_OK;
}

int select_server_add_wrapper(cpy_event_loop_t *loop, cpy_event_t *efd,
        int events)
{
    select_server_add(efd->fd);

    return CPY_EVENT_OK;
}

int select_server_del_wrapper(cpy_event_loop_t *loop, cpy_event_t *efd,
        int events)
{
    select_server_del(efd->fd);

    return CPY_EVENT_OK;
}

int select_server_run_wrapper(cpy_event_loop_t *loop)
{
    select_server_run2(loop);

    return CPY_EVENT_AGAIN;
}


