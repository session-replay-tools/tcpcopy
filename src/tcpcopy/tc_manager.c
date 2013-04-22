
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
    void                    *fd;
    uint64_t                 key;
    ip_port_pair_mapping_t  *test;

    test = get_test_pair(&(clt_settings.transfer), ip, port);
    if (test == NULL) {
        tc_log_info(LOG_WARN, 0, "it can't find test pair,%u:%u",
                    ntohl(ip), ntohs(port));
        return -1;
    }

    key = get_key(test->online_ip, test->online_port);
    fd  = hash_find(addr_table, key);

    if (fd == NULL) {
        tc_log_info(LOG_WARN, 0, "it can't find address socket,%u:%u",
                    ntohl(ip), ntohs(port));
        return -1;
    }
    return (int) (long) fd;
}

static void
address_add_sock(uint32_t ip, uint16_t port, int fd) 
{
    uint64_t key = get_key(ip, port);
    hash_add(addr_table, key, (void *) (long) fd);
}

static void 
address_release()
{   
    int          i, fd;
    hash_node   *hn;
    link_list   *list;
    p_link_node  ln, tmp_ln;

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

                fd  = (int) (long) hn->data;
                hn->data = NULL;

                if (fd > 0) {
                    tc_log_info(LOG_NOTICE, 0, "it close socket:%d", fd);
                    close(fd);
                }
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
        tc_over = 1;
    }

    evt->msec = tc_current_time_msec + 60000;
}

void
tcp_copy_release_resources()
{
    int i;

    if (tc_over > 1) {
        tc_log_info(LOG_WARN, 0, "sig %d received", tc_over); 
    }

    output_stat();

    tc_time_remove_timer();
    tc_log_info(LOG_NOTICE, 0, "remove timer over");

    destroy_for_sessions();

    tc_event_loop_finish(&event_loop);
    tc_log_info(LOG_NOTICE, 0, "tc_event_loop_finish over");

#if (!TCPCOPY_DR)
    address_release();
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
    pcap_close(clt_settings.pcap);
#endif

    if (tc_raw_socket_out > 0) {
        close(tc_raw_socket_out);
        tc_raw_socket_out = -1;
    }

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
    tc_over = (sig != 0 ? sig : 1);
}


/* initiate TCPCopy client */
int
tcp_copy_init(tc_event_loop_t *event_loop)
{
    int                      i, fd;
#if (TCPCOPY_PCAP)
    int                      j, filter_port_num = 0;
    char                    *pt;
    uint16_t                 filter_port[MAX_FILTER_PORTS];
#endif
    uint32_t                 target_ip;
    ip_port_pair_mapping_t  *pair, **mappings;

    /* register some timer */
    tc_event_timer_add(event_loop, 60000, check_resource_usage);
    tc_event_timer_add(event_loop, 5000, tc_interval_dispose);

    /* init session table */
    init_for_sessions();

#if (TCPCOPY_PCAP)
    memset((void *) filter_port, 0, MAX_FILTER_PORTS << 1);
#endif

#if (TCPCOPY_DR)
    /* 
     * add connections to the real servers for sending router info 
     * and receiving response packet
     */
    for (i = 0; i < clt_settings.real_servers.num; i++) {

        target_ip = clt_settings.real_servers.ips[i];

        fd = tc_message_init(event_loop, target_ip, clt_settings.srv_port);
        if (fd == TC_INVALID_SOCKET) {
            return TC_ERROR;
        }
        clt_settings.real_servers.active_num++;
        clt_settings.real_servers.active[i] = 1;
        clt_settings.real_servers.fds[i] = fd;

        tc_log_info(LOG_NOTICE, 0, "add a dr tunnel for exchanging info:%u:%u",
                ntohl(target_ip), clt_settings.srv_port);
    }

#else
    address_init();
#endif

    mappings = clt_settings.transfer.mappings;
    for (i = 0; i < clt_settings.transfer.num; i++) {

        pair = mappings[i];
        target_ip = pair->target_ip;

#if (TCPCOPY_PCAP)
        for (j = 0; j < MAX_FILTER_PORTS; j++) {
            if (filter_port[j] == 0) {
                filter_port[j] = pair->online_port;
                filter_port_num++;
                break;
            } else if (filter_port[j] == pair->online_port) {
                break;
            }
        }
#endif

#if (!TCPCOPY_DR)
        fd = tc_message_init(event_loop, target_ip, clt_settings.srv_port);
        if (fd == TC_INVALID_SOCKET) {
            return TC_ERROR;
        }

        address_add_sock(pair->online_ip, pair->online_port, fd);
#endif
        tc_log_info(LOG_NOTICE, 0, "add a tunnel for exchanging info:%u:%u",
                    ntohl(target_ip), clt_settings.srv_port);
    }

#if (TCPCOPY_PCAP)
    if (filter_port_num == 0) {
        tc_log_info(LOG_ERR, 0, "filter_port_num is zero");
        return TC_ERROR;
    }
    pt = clt_settings.filter;
#if (TCPCOPY_UDP)
    strcpy(pt, "udp dst port ");
#else
    strcpy(pt, "tcp dst port ");
#endif
    pt = pt + strlen(pt);
    for (i = 0; i < filter_port_num -1; i++) {
        sprintf(pt, "%d or ", ntohs(filter_port[i]));
        pt = pt + strlen(pt);
    }
    sprintf(pt, "%d", ntohs(filter_port[i]));
    tc_log_info(LOG_NOTICE, 0, "filter = %s", clt_settings.filter);
#endif

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

