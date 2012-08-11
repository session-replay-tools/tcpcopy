#include <xcopy.h>
#include <intercept.h>

static int    firewall_sock, msg_listen_sock;
static time_t last_clean_time;

static uint32_t      seq = 1;
static unsigned char buffer[128];

static int
dispose_netlink_packet(int verdict, unsigned long packet_id)
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
    if (sendto(firewall_sock, (void *)nl_header, nl_header->nlmsg_len, 0,
                (struct sockaddr *)&addr, sizeof(struct sockaddr_nl)) < 0)
    {
        tc_log_info(LOG_ERR, errno, "unable to send mode message");
        exit(0);
    }

    return 1;
}

static void
interception_process(int fd)
{
    int                    diff, new_fd, i, pass_through_flag = 0;
    char                   buffer[65535];
    time_t                 now;
    msg_client_t           msg;
    struct iphdr          *ip_header;
    unsigned long          packet_id;

    if (fd == msg_listen_sock) {
        if ((new_fd = tc_socket_accept(msg_listen_sock)) == TC_INVALID_SOCKET) {
            return;
        }

        if (tc_socket_set_nodelay(new_fd) == TC_ERROR) {
            return;
        }

        select_server_add(new_fd);

    } else if (fd == firewall_sock) {
        packet_id = 0;

        if (tc_nl_socket_recv(firewall_sock, buffer, 65535) == TC_ERROR) {
            return;
        }

        ip_header = tc_nl_ip_header(buffer);
        packet_id = tc_nl_packet_id(buffer);

        if (ip_header != NULL) {
            /* Check if it is the valid user to pass through firewall */
            for (i = 0; i < srv_settings.passed_ips.num; i++) {
                if (srv_settings.passed_ips.ips[i] == ip_header->daddr) {
                    pass_through_flag = 1;
                    break;
                }
            }
            if (pass_through_flag) {
                /* Pass through the firewall */
                dispose_netlink_packet(NF_ACCEPT, packet_id);   
            } else {
                router_update(ip_header);
                now  = time(0);
                diff = now - last_clean_time;
                if (diff > CHECK_INTERVAL) {
                    route_delete_obsolete(now);
                    delay_table_delete_obsolete(now);
                    last_clean_time = now;
                }
                 /* Drop the packet */
                dispose_netlink_packet(NF_DROP, packet_id);     
            }
        }
    } else {
        if (tc_socket_recv(fd, (char *) &msg, MSG_CLIENT_SIZE) == TC_ERROR) {
            tc_socket_close(fd);
            select_server_del(fd);
            tc_log_info(LOG_NOTICE, 0, "close sock:%d", fd);
            return;
        }

        switch (msg.type) {
        case CLIENT_ADD:
            tc_log_debug1(LOG_DEBUG, 0, "add client router:%u", 
                          ntohs(msg.client_port));
            router_add(msg.client_ip, msg.client_port, fd);
            break;
        case CLIENT_DEL:
            tc_log_debug1(LOG_DEBUG, 0, "del client router:%u", 
                          ntohs(msg.client_port));
            router_del(msg.client_ip, msg.client_port);
            break;
        }
    }
}

/* Initiate for tcpcopy server */
int
interception_init(uint16_t port)
{
    int fd;

    delay_table_init(srv_settings.hash_size);
    router_init(srv_settings.hash_size << 1);

    select_server_set_callback(interception_process);

    if ((fd = tc_socket_init()) == TC_INVALID_SOCKET) {
        return TC_ERROR;

    } else {
        if (tc_socket_listen(fd, srv_settings.binded_ip, port) == TC_ERROR) {
            return TC_ERROR;
        }

        tc_log_info(LOG_NOTICE, 0, "msg listen socket:%d", fd);
        select_server_add(fd);
        msg_listen_sock = fd;
    }

    if ((fd = tc_nl_socket_init()) == TC_INVALID_SOCKET) {
        return TC_ERROR;

    } else {
        tc_log_info(LOG_NOTICE, 0, "firewall socket:%d", fd);
        select_server_add(fd);
        firewall_sock = fd;
    }

    return TC_OK;
}


/* Main procedure for interception */
void interception_run()
{
    select_server_run();
}

/* Clear resources for interception */
void
interception_over()
{
    if (firewall_sock != -1) {
        close(firewall_sock);
        firewall_sock = -1;
        tc_log_info(LOG_NOTICE, 0, "firewall sock is closed");
    }

    if (msg_listen_sock != -1) {
        close(msg_listen_sock);
        msg_listen_sock = -1;
        tc_log_info(LOG_NOTICE, 0, "msg listen sock is closed");
    }

    router_destroy();
    delay_table_destroy();
}

