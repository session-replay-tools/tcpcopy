#include <xcopy.h>
#include <intercept.h>

static time_t last_clean_time;

static uint32_t      seq = 1;
static unsigned char buffer[128];

extern tc_event_loop_t s_event_loop;

static int
dispose_netlink_packet(int fd, int verdict, unsigned long packet_id)
{
    struct nlmsghdr        *nl_header = (struct nlmsghdr*)buffer;
    struct ipq_verdict_msg *ver_data;
    struct sockaddr_nl      addr;

    /*
     * The IPQM_VERDICT message is used to communicate with
     * the kernel ip queue module.
     */
    nl_header->nlmsg_type  = IPQM_VERDICT;
    nl_header->nlmsg_len   = NLMSG_LENGTH(sizeof(struct ipq_verdict_msg));
    nl_header->nlmsg_flags = (NLM_F_REQUEST);
    nl_header->nlmsg_pid   = getpid();
    nl_header->nlmsg_seq   = seq++;
    ver_data = (struct ipq_verdict_msg *)NLMSG_DATA(nl_header);
    ver_data->value = verdict;
    ver_data->id    = packet_id;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family  = AF_NETLINK;
    addr.nl_pid     = 0;
    addr.nl_groups  = 0;

    /*
     * In an effort to keep packets properly ordered,
     * the impelmentation of the protocol requires that
     * the user space application send an IPQM_VERDICT message
     * after every IPQM PACKET message is received.
     *
     */
    if (sendto(fd, (void *)nl_header, nl_header->nlmsg_len, 0,
                (struct sockaddr *)&addr, sizeof(struct sockaddr_nl)) < 0)
    {
        tc_log_info(LOG_ERR, errno, "unable to send mode message");
        return 0;
    }

    return 1;
}

void
tc_msg_event_accept(tc_event_t *rev)
{
    int         fd;
    tc_event_t *ev;

    if ((fd = tc_socket_accept(rev->fd)) == TC_INVALID_SOCKET) {
        tc_log_info(LOG_ERR, 0, "msg accept failed, from listen:%d", rev->fd);
        return;
    }

    if (tc_socket_set_nodelay(fd) == TC_ERROR) {
        tc_log_info(LOG_ERR, 0, "Set no delay to socket(%d) failed.", rev->fd);
        return;
    }

    ev = tc_event_create(fd, tc_msg_event_process, NULL);
    if (ev == NULL) {
        tc_log_info(LOG_ERR, 0, "Msg event create failed.");
        return;
    }

    if (tc_event_add(&s_event_loop, ev, TC_EVENT_READ) == TC_EVENT_ERROR) {
        return;
    }
}

void
tc_msg_event_process(tc_event_t *rev)
{
    msg_client_t msg;

    if (tc_socket_recv(rev->fd, (char *) &msg, MSG_CLIENT_SIZE) == TC_ERROR) {
        tc_socket_close(rev->fd);
        tc_event_del(&s_event_loop, rev, TC_EVENT_READ);
        tc_log_info(LOG_NOTICE, 0, "close sock:%d", rev->fd);
        return;
    }

    switch (msg.type) {
        case CLIENT_ADD:
            tc_log_debug1(LOG_DEBUG, 0, "add client router:%u",
                          ntohs(msg.client_port));
            router_add(msg.client_ip, msg.client_port, rev->fd);
            break;
        case CLIENT_DEL:
            tc_log_debug1(LOG_DEBUG, 0, "del client router:%u",
                          ntohs(msg.client_port));
            router_del(msg.client_ip, msg.client_port);
            break;
    }
}

void
tc_nl_event_process(tc_event_t *rev)
{
    int             diff, i, pass_through_flag = 0;
    char            buffer[65535];
    time_t          now;
    unsigned long   packet_id;
    tc_ip_header_t *ip_hdr;

    packet_id = 0;

    if (tc_nl_socket_recv(rev->fd, buffer, 65535) == TC_ERROR) {
        return;
    }

    ip_hdr = tc_nl_ip_header(buffer);
    packet_id = tc_nl_packet_id(buffer);

    if (ip_hdr != NULL) {
        /* Check if it is the valid user to pass through firewall */
        for (i = 0; i < srv_settings.passed_ips.num; i++) {
            if (srv_settings.passed_ips.ips[i] == ip_hdr->daddr) {
                pass_through_flag = 1;
                break;
            }
        }

        if (pass_through_flag) {
            /* Pass through the firewall */
            dispose_netlink_packet(rev->fd, NF_ACCEPT, packet_id);
        } else {
            router_update(ip_hdr);
            now  = time(0);
            diff = now - last_clean_time;
            if (diff > CHECK_INTERVAL) {
                route_delete_obsolete(now);
                delay_table_delete_obsolete(now);
                last_clean_time = now;
            }
            /* Drop the packet */
            dispose_netlink_packet(rev->fd, NF_DROP, packet_id);
        }
    }
}

/* Initiate for tcpcopy server */
int
interception_init(tc_event_loop_t *event_loop, char *ip, uint16_t port)
{
    int         fd;
    tc_event_t *ev;

    delay_table_init(srv_settings.hash_size);
    router_init(srv_settings.hash_size << 1);

    /* Init the listening socket */
    if ((fd = tc_socket_init()) == TC_INVALID_SOCKET) {
        return TC_ERROR;

    } else {
        if (tc_socket_listen(fd, ip, port) == TC_ERROR) {
            return TC_ERROR;
        }

        tc_log_info(LOG_NOTICE, 0, "msg listen socket:%d", fd);

        ev = tc_event_create(fd, tc_msg_event_accept, NULL);
        if (ev == NULL) {
            return TC_ERROR;
        }

        if (tc_event_add(event_loop, ev, TC_EVENT_READ) == TC_EVENT_ERROR) {
            return TC_ERROR;
        }
    }

    /* Init the netlink socket */
    if ((fd = tc_nl_socket_init()) == TC_INVALID_SOCKET) {
        return TC_ERROR;

    } else {
        tc_log_info(LOG_NOTICE, 0, "firewall socket:%d", fd);

        ev = tc_event_create(fd, tc_nl_event_process, NULL);
        if (ev == NULL) {
            return TC_ERROR;
        }

        if (tc_event_add(event_loop, ev, TC_EVENT_READ) == TC_EVENT_ERROR) {
            return TC_ERROR;
        }
    }

    return TC_OK;
}

/* Clear resources for interception */
void
interception_over()
{
    router_destroy();
    delay_table_destroy();
}

