
#include <xcopy.h>
#include <tcpcopy.h>

static address_node_t addr[65536];

int
address_find_sock(uint16_t local_port)
{
    if (0 == addr[local_port].sock) {
        tc_log_info(LOG_WARN, 0, "it can't find address socket:%u",
                    ntohs(local_port));
        return -1;
    }
    return addr[local_port].sock;
}

/* Close sockets */
int
address_close_sock()
{
    int i;

    for (i = 0; i< 65536; i++) {
        if (0 != addr[i].sock) {
            tc_log_info(LOG_WARN, 0, "it close socket:%d", addr[i].sock);
            close(addr[i].sock);
            addr[i].sock = 0;
        }
    }

    return 0;
}

/* Check resource usage, such as memory usage and cpu usage */
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

    /* Total amount of user time used */
    tc_log_info(LOG_NOTICE, 0, "user time used:%ld", usage.ru_utime.tv_sec);

    /* Total amount of system time used */
    tc_log_info(LOG_NOTICE, 0, "sys  time used:%ld", usage.ru_stime.tv_sec);

    /* Maximum resident set size (in kilobytes) */
    /* This is only valid since Linux 2.6.32 */
    tc_log_info(LOG_NOTICE, 0, "max memory size:%ld", usage.ru_maxrss);

    if (usage.ru_maxrss > clt_settings.max_rss) {
        tc_log_info(LOG_WARN, 0, "occupies too much memory,limit:%ld",
                 clt_settings.max_rss);
    }

    evt->msec = tc_current_time_msec + 60000;
}

void
tcp_copy_exit()
{
    int i;

    output_stat();

    tc_event_loop_finish(&event_loop);
    destroy_for_sessions();

    tc_log_end();

#ifdef TCPCOPY_MYSQL_ADVANCED
    release_mysql_user_pwd_info();
#endif

    if (clt_settings.transfer.mappings != NULL) {

        for (i = 0; i < clt_settings.transfer.num; i++) {
            free(clt_settings.transfer.mappings[i]);
        }

        free(clt_settings.transfer.mappings);
        clt_settings.transfer.mappings = NULL;
    }

    exit(EXIT_SUCCESS);
}

void
tcp_copy_over(const int sig)
{
    long int pid   = (long int)syscall(SYS_gettid);

    tc_log_info(LOG_WARN, 0, "sig %d received, pid=%ld", sig, pid);
    exit(EXIT_SUCCESS);
}


/* Initiate tcpcopy client */
int
tcp_copy_init(tc_event_loop_t *event_loop)
{
    int                      i, fd;
    uint16_t                 online_port;
    uint32_t                 target_ip;
    ip_port_pair_mapping_t  *pair, **mappings;

    /* Register some timer */
    tc_event_timer_add(event_loop, 60000, check_resource_usage);
    tc_event_timer_add(event_loop, 5000, tc_interval_dispose);

    /* Init session table*/
    init_for_sessions();

    /* Init packets for processing */
#if (TCPCOPY_OFFLINE)
    if (tc_offline_init(event_loop, clt_settings.pcap_file) == TC_ERROR) {
        return TC_ERROR;
    }
#else
    if (tc_packets_init(event_loop) == TC_ERROR) {
        return TC_ERROR;
    }
#endif

    /* Add connections to the tested server for exchanging info */
    mappings = clt_settings.transfer.mappings;
    for (i = 0; i < clt_settings.transfer.num; i++) {

        pair = mappings[i];
        online_port = pair->online_port;
        target_ip = pair->target_ip;

        fd = tc_message_init(event_loop, target_ip, clt_settings.srv_port);
        if (fd == TC_INVALID_SOCKET) {
            return TC_ERROR;
        }

        addr[online_port].ip = target_ip;
        addr[online_port].port = clt_settings.srv_port;
        addr[online_port].sock = fd;

        tc_log_info(LOG_NOTICE, 0, "add a tunnel for exchanging info:%u",
                    ntohs(clt_settings.srv_port));
    }

    return TC_OK;
}
