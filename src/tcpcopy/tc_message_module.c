
#include <xcopy.h>
#include <tcpcopy.h>

void
tc_process_server_msg(tc_event_t *rev)
{
    msg_server_t msg;

    if (tc_socket_recv(rev->fd, (char *) &msg, MSG_SERVER_SIZE) == TC_ERROR) {
        tc_log_info(LOG_ERR, 0, 
                "Recv socket(%d) from server error, server may be close",
                rev->fd);
        exit(EXIT_FAILURE);
    }

    process((char *) &msg, REMOTE);
}


