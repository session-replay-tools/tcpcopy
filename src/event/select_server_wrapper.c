
#include <xcopy.h>

int select_server_create_fake(tc_event_loop_t *loop)
{
    return TC_EVENT_OK;
}

int select_server_destroy_fake(tc_event_loop_t *loop)
{
    return TC_EVENT_OK;
}

int select_server_add_wrapper(tc_event_loop_t *loop, tc_event_t *efd,
        int events)
{
    select_server_add(efd->fd);
    free(efd);

    return TC_EVENT_OK;
}

int select_server_del_wrapper(tc_event_loop_t *loop, tc_event_t *efd,
        int events)
{
    select_server_del(efd->fd);

    return TC_EVENT_OK;
}

int select_server_run_wrapper(tc_event_loop_t *loop, long timeout)
{
    select_server_client_run(loop);

    return TC_EVENT_AGAIN;
}


