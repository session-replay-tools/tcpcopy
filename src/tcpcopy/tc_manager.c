
#include <xcopy.h>
#include <tcpcopy.h>

#if (!TCPCOPY_DR)
static hash_table *addr_table = NULL;

static void
address_init()
{
    addr_table = hash_create(32);
    strcpy(addr_table->name, "address-table");
    tc_log_info(LOG_NOTICE, 0, "create %s, size:%u",
            addr_table->name, addr_table->size);
}

int
address_find_sock(uint32_t ip, uint16_t port)
{
    int                      fd;
    uint64_t                 key;
    connections_t           *connections;
    ip_port_pair_mapping_t  *test;

    test = get_test_pair(&(clt_settings.transfer), ip, port);
    if (test == NULL) {
        tc_log_info(LOG_WARN, 0, "it can't find test pair,%u:%u",
                    ntohl(ip), ntohs(port));
        return -1;
    }

    key = get_key(test->online_ip, test->online_port);
    connections = hash_find(addr_table, key);

    if (connections == NULL) {
        tc_log_info(LOG_WARN, 0, "it can't find address socket,%u:%u",
                    ntohl(ip), ntohs(port));
        return -1;
    }

    fd = connections->fds[connections->index];
    connections->index = (connections->index + 1) % connections->num;

    return fd;
}

static void
address_add_sock(uint32_t ip, uint16_t port, int fd) 
{
    uint64_t        key;
    connections_t  *connections;

    key = get_key(ip, port);

    connections = hash_find(addr_table, key);

    if (connections == NULL) {
        connections = (connections_t *)malloc(sizeof(connections_t));
        if (connections == NULL) {
            tc_log_info(LOG_ERR, errno, "can't malloc memory for conn");
            return;
        }
        memset(connections, 0, sizeof(connections_t));
        hash_add(addr_table, key, connections);
    }

    if (connections->num >= MAX_CONNECTION_NUM) {
        return;
    }

    connections->fds[connections->num] = fd;
    connections->num = connections->num + 1;

}

static void 
address_release()
{   
    int             i, j, fd;
    hash_node      *hn;
    link_list      *list;
    p_link_node     ln, tmp_ln;
    connections_t  *connections;

    if (addr_table == NULL) {
        return;
    }

    for (i = 0; i < addr_table->size; i++) {

        list = addr_table->lists[i];
        ln   = link_list_first(list);   
        while (ln) {

            tmp_ln = link_list_get_next(list, ln);
            hn = (hash_node *) ln->data;
            if (hn->data != NULL) {

                connections = (connections_t *) hn->data;
                hn->data = NULL;

                for (j = 0; j < connections->num; j++) {
                    fd = connections->fds[j];
                    if (fd > 0) {
                        tc_log_info(LOG_NOTICE, 0, "it close socket:%d", fd);
                        tc_socket_close(fd);
                        tc_event_del(clt_settings.ev[fd]->loop, 
                                clt_settings.ev[fd], TC_EVENT_READ);
                        tc_event_destroy(clt_settings.ev[fd], 0);
                        connections->fds[j] = -1;
                    }
                }
                free(connections);
            }
            ln = tmp_ln;
        }
    }

    tc_log_info(LOG_NOTICE, 0, "destroy addr table");
    hash_destroy(addr_table);
    free(addr_table);
    addr_table = NULL;

}
#endif

/* check resource usage, such as memory usage and cpu usage */
static void
check_resource_usage(tc_event_timer_t *evt)
{
    int           ret, who;
    struct rusage usage;

    who = RUSAGE_SELF;

    ret = getrusage(who, &usage);
    if (ret == -1) {
        tc_log_info(LOG_ERR, errno, "getrusage");
    }

    /* total amount of user time used */
    tc_log_info(LOG_NOTICE, 0, "user time used:%ld", usage.ru_utime.tv_sec);

    /* total amount of system time used */
    tc_log_info(LOG_NOTICE, 0, "sys  time used:%ld", usage.ru_stime.tv_sec);

    /* maximum resident set size (in kilobytes) */
    /* only valid since Linux 2.6.32 */
    tc_log_info(LOG_NOTICE, 0, "max memory size:%ld", usage.ru_maxrss);

    if (usage.ru_maxrss > clt_settings.max_rss) {
        tc_log_info(LOG_WARN, 0, "occupies too much memory, limit:%ld",
                 clt_settings.max_rss);
        /* biggest signal number + 1 */
        tc_over = SIGRTMAX;
    }

    evt->msec = tc_current_time_msec + 60000;
}

void
tcp_copy_release_resources()
{
    int i;

    tc_log_info(LOG_WARN, 0, "sig %d received", tc_over); 

    output_stat();

    tc_time_remove_timer();
    tc_log_info(LOG_NOTICE, 0, "remove timer over");

    destroy_for_sessions();

#if (!TCPCOPY_DR)
    address_release();
#endif
    tc_event_loop_finish(&event_loop);
    tc_log_info(LOG_NOTICE, 0, "tc_event_loop_finish over");

#if (TCPCOPY_DIGEST)
    tc_destroy_sha1();
    tc_destroy_digests();
#endif

    tc_log_end();

#ifdef TCPCOPY_MYSQL_ADVANCED
    release_mysql_user_pwd_info();
#endif

#if (TCPCOPY_PCAP)
    for (i = 0; i < clt_settings.devices.device_num; i++) {
        if (clt_settings.devices.device[i].pcap != NULL) {
            pcap_close(clt_settings.devices.device[i].pcap);
            clt_settings.devices.device[i].pcap = NULL;
        }
    }
#endif

#if (TCPCOPY_OFFLINE)
    if (clt_settings.pcap != NULL) {
        pcap_close(clt_settings.pcap);
        clt_settings.pcap = NULL;
    }
#endif

    if (tc_raw_socket_out > 0) {
        tc_socket_close(tc_raw_socket_out);
        tc_raw_socket_out = TC_INVALID_SOCKET;
    }

#if (TCPCOPY_PCAP_SEND)
    tc_pcap_over();
#endif

    if (clt_settings.transfer.mappings != NULL) {

        for (i = 0; i < clt_settings.transfer.num; i++) {
            free(clt_settings.transfer.mappings[i]);
        }

        free(clt_settings.transfer.mappings);
        clt_settings.transfer.mappings = NULL;
    }
}

void
tcp_copy_over(const int sig)
{
    tc_over = sig;
}

static bool send_version(int fd) {
    msg_client_t    msg;

    memset(&msg, 0, sizeof(msg_client_t));
    msg.client_ip = htonl(0);
    msg.client_port = htons(0);
    msg.type = htons(INTERNAL_VERSION);

    if (tc_socket_send(fd, (char *) &msg, MSG_CLIENT_SIZE) == TC_ERROR) {
        tc_log_info(LOG_ERR, 0, "send version error:%d", fd);
        return false;
    }

    return true;
}

static int
connect_to_server(tc_event_loop_t *event_loop)
{
    int                      i, j, fd;
    uint32_t                 target_ip;
#if (TCPCOPY_DR)
    uint16_t                 target_port;
    connections_t           *connections;
#else
    ip_port_pair_mapping_t  *pair, **mappings;
#endif


#if (TCPCOPY_DR)
    /* 
     * add connections to the real servers for sending router info 
     * and receiving response packet
     */
    for (i = 0; i < clt_settings.real_servers.num; i++) {

        target_ip = clt_settings.real_servers.ips[i];
        target_port = clt_settings.real_servers.ports[i];
        if (target_port == 0) {
            target_port = clt_settings.srv_port;
        }

        if (clt_settings.real_servers.active[i] != 0) {
            continue;
        }

        /* release resources */
        connections = &(clt_settings.real_servers.connections[i]);
        for (j = 0; j < connections->num; j++) {
             fd = connections->fds[j];
             if (fd > 0) {
                 tc_log_info(LOG_NOTICE, 0, "it close socket:%d", fd);
                 tc_socket_close(fd);
                 tc_event_del(clt_settings.ev[fd]->loop, 
                         clt_settings.ev[fd], TC_EVENT_READ);
                 tc_event_destroy(clt_settings.ev[fd], 0);
                 connections->fds[j] = -1;
             }
        }

        /* reinit resources */
        clt_settings.real_servers.connections[i].num = 0;
        clt_settings.real_servers.connections[i].remained_num = 0;

        for (j = 0; j < clt_settings.par_connections; j++) {
            fd = tc_message_init(event_loop, target_ip, target_port);
            if (fd == TC_INVALID_SOCKET) {
                return TC_ERROR;
            }

            if (!send_version(fd)) {
                return TC_ERROR;
            }

            if (j == 0) {
                clt_settings.real_servers.active_num++;
                clt_settings.real_servers.active[i] = 1;
            }

            clt_settings.real_servers.connections[i].fds[j] = fd;
            clt_settings.real_servers.connections[i].num++;
            clt_settings.real_servers.connections[i].remained_num++;

        }

        tc_log_info(LOG_NOTICE, 0, "add dr tunnels for exchanging info:%u:%u",
                target_ip, target_port);
    }

#else

    mappings = clt_settings.transfer.mappings;
    for (i = 0; i < clt_settings.transfer.num; i++) {

        pair = mappings[i];
        target_ip = pair->target_ip;

        for ( j = 0; j < clt_settings.par_connections; j++) {
            fd = tc_message_init(event_loop, target_ip, clt_settings.srv_port);
            if (fd == TC_INVALID_SOCKET) {
                return TC_ERROR;
            }

            if (!send_version(fd)) {
                return TC_ERROR;
            }

            address_add_sock(pair->online_ip, pair->online_port, fd);

        }

        tc_log_info(LOG_NOTICE, 0, "add tunnels for exchanging info:%u:%u",
                    target_ip, clt_settings.srv_port);
    }

#endif

    return TC_OK;


}

#if (TCPCOPY_DR)
static void 
restore_work(tc_event_timer_t *evt) 
{
    connect_to_server(&event_loop);

    evt->msec = tc_current_time_msec + RETRY_INTERVAL;

    clt_settings.tries++;
}
#endif


/* initiate TCPCopy client */
int
tcp_copy_init(tc_event_loop_t *event_loop)
{

    /* register some timer */
    tc_event_timer_add(event_loop, 60000, check_resource_usage);
    tc_event_timer_add(event_loop, OUTPUT_INTERVAL, tc_interval_dispose);

#if (TCPCOPY_DR)
    if (clt_settings.lonely) {
        tc_event_timer_add(event_loop, RETRY_INTERVAL, restore_work);
    }
#endif

    /* init session table */
    init_for_sessions();

#if (!TCPCOPY_DR)
    address_init();
#endif

    if (connect_to_server(event_loop) == TC_ERROR) {
        return TC_ERROR;
    }

    /* init packets for processing */
#if (TCPCOPY_OFFLINE)
    if (tc_offline_init(event_loop, clt_settings.pcap_file) == TC_ERROR) {
        return TC_ERROR;
    }
#else
    if (tc_packets_init(event_loop) == TC_ERROR) {
        return TC_ERROR;
    }
#endif

    return TC_OK;
}

