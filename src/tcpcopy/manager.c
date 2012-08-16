
#include <xcopy.h>
#include <tcpcopy.h>

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

    tc_event_loop_finish(&event_loop);
    destroy_for_sessions();

    send_close();
    address_close_sock();

#if (TCPCOPY_OFFLINE)
    if (pcap != NULL) {
        pcap_close(pcap);                                                                               
    }   
#endif
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
#if (TCPCOPY_OFFLINE)
    char                    *pcap_file, ebuf[PCAP_ERRBUF_SIZE];
#endif
    uint16_t                 online_port, target_port;
    uint32_t                 target_ip;
    tc_event_t              *raw_socket_event;
    ip_port_pair_mapping_t  *pair, **mappings;

    /* Register a timer to check resource every minute */
    tc_event_timer_add(event_loop, 60000, check_resource_usage);

    /* Init session table*/
    init_for_sessions();

    if ((fd = tc_raw_socket_out_init()) == TC_INVALID_SOCKET) {
        return TC_ERROR;
    } else {
        tcpcopy_rsc.raw_socket_out = fd;
    }

    /* Add connections to the tested server for exchanging info */
    mappings = clt_settings.transfer.mappings;
    for (i = 0; i < clt_settings.transfer.num; i++) {

        pair = mappings[i];
        online_port = pair->online_port;
        target_ip   = pair->target_ip;
        target_port = pair->target_port;

        if (address_add_msg_conn(event_loop, online_port, target_ip, 
                                 clt_settings.srv_port) == TC_ERROR)
        {
            return TC_ERROR;
        }

        tc_log_info(LOG_NOTICE, 0, "add a tunnel for exchanging info:%u",
                ntohs(target_port));
    }

#if (!TCPCOPY_OFFLINE)
    if ((fd = tc_raw_socket_in_init()) == TC_INVALID_SOCKET) {
        return TC_ERROR;
    }

    tc_socket_set_nonblocking(fd);

    /* Add the input raw socket to select */
    raw_socket_event = tc_event_create(fd, tc_process_raw_socket_packet, NULL);
    if (raw_socket_event == NULL) {
        return TC_ERROR;
    }

    if (tc_event_add(event_loop, raw_socket_event, TC_EVENT_READ)
            == TC_EVENT_ERROR)
    {
        tc_log_info(LOG_ERR, 0, "add raw socket(%d) to event loop failed.",
                    raw_socket_event->fd);
        return TC_ERROR;
    }

    tcpcopy_rsc.raw_socket_in = fd;

#else
    select_offline_set_callback(send_packets_from_pcap);

    pcap_file = clt_settings.pcap_file;
    if (pcap_file != NULL) {

        if ((pcap = pcap_open_offline(pcap_file, ebuf)) == NULL) {
            tc_log_info(LOG_ERR, 0, "open %s" , ebuf);
            fprintf(stderr, "open %s\n", ebuf);
            return TC_ERROR;

        } else {

            gettimeofday(&base_time, NULL);
            tc_log_info(LOG_NOTICE, 0, "open pcap success:%s", pcap_file);
            tc_log_info(LOG_NOTICE, 0, "send the first packets here");
            send_packets_from_pcap(1);
        }
    } else {
        return TC_ERROR;
    }
#endif

    return TC_OK;
}
