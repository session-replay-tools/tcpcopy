
#include <xcopy.h>
#include <tcpcopy.h>

static void tc_process_server_msg(tc_event_t *rev);

int
tc_message_init(tc_event_loop_t *event_loop, uint32_t ip, uint16_t port)
{
    int          fd;
    tc_event_t  *ev;

    if ((fd = tc_socket_init()) == TC_INVALID_SOCKET) {
        return TC_INVALID_SOCKET;
    }

    if (tc_socket_connect(fd, ip, port) == TC_ERROR) {
        return TC_INVALID_SOCKET;
    }

    if (tc_socket_set_nodelay(fd) == TC_ERROR) {
        return TC_INVALID_SOCKET;
    }

    ev = tc_event_create(fd, tc_process_server_msg, NULL);
    if (ev == NULL) {
        return TC_INVALID_SOCKET;
    }

    if (tc_event_add(event_loop, ev, TC_EVENT_READ) == TC_EVENT_ERROR) {
        return TC_INVALID_SOCKET;
    }

    return fd;
}

static void
tc_process_server_msg(tc_event_t *rev)
{
    msg_server_t msg;

    if (tc_socket_recv(rev->fd, (char *) &msg,
                MSG_SERVER_SIZE) == TC_ERROR)
    {
        tc_log_info(LOG_ERR, 0, 
                    "Recv socket(%d)error, server may be close", rev->fd);
        return;
    }

    process((char *) &msg, REMOTE);
}


