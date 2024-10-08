
#include <xcopy.h>
#include <tcpcopy.h>
#include <malloc.h>

#if (TC_PLUGIN)
static void
remove_obso_resource(tc_event_timer_t *evt)
{
    if (clt_settings.plugin && 
            clt_settings.plugin->remove_obsolete_resources) 
    {
        clt_settings.plugin->remove_obsolete_resources(0);
        if (evt) {
            tc_event_update_timer(evt, MAX_IDLE_MS_TIME);
        }
    }
}
#endif


/* Check resource usage, such as memory usage and cpu usage */
static void
check_resource_usage(tc_event_timer_t *evt)
{
    int           ret, who;
    struct rusage usage;
    struct mallinfo m;

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
    /* Only valid since Linux 2.6.32 */
    tc_log_info(LOG_NOTICE, 0, "max memory size:%ld", usage.ru_maxrss);

    if (usage.ru_maxrss > (long int) clt_settings.max_rss) {
        tc_log_info(LOG_WARN, 0, "occupies too much memory, limit:%ld",
                 clt_settings.max_rss);
        /* Biggest signal number + 1 */
        tc_over = SIGRTMAX;
    }

    m = mallinfo();
    tc_log_info(LOG_NOTICE, 0, "Total allocated space (bytes): %d", m.uordblks);
    tc_log_info(LOG_NOTICE, 0, "Total free space (bytes): %d", m.fordblks);
    tc_log_info(LOG_NOTICE, 0, "Top-most, releasable space (bytes): %d", m.keepcost);

    if (m.fordblks > m.uordblks) {
        if (usage.ru_maxrss > (long int) (clt_settings.max_rss >> 2)) {
            tc_log_info(LOG_NOTICE, 0, "call malloc_trim");
            malloc_trim(0);
            m = mallinfo();
            tc_log_info(LOG_NOTICE, 0, "New total free space (bytes): %d", m.fordblks);
            tc_log_info(LOG_NOTICE, 0, "New top-most, releasable space (bytes): %d", m.keepcost);
        }
    }

    if (evt) {
        tc_event_update_timer(evt, 60000);
    }
}


void
tcp_copy_release_resources(void)
{
#if (TC_PCAP)
    int i;
#endif 
    tc_log_info(LOG_WARN, 0, "sig %d received", tc_over); 

    tc_output_stat();

    tc_dest_sess_table();

#if (TC_PLUGIN)
    if (clt_settings.plugin && clt_settings.plugin->exit_module) {
        clt_settings.plugin->exit_module(&clt_settings);
    }
#endif

    tc_event_loop_finish(&event_loop);
    tc_log_info(LOG_NOTICE, 0, "tc_event_loop_finish over");

#if (TC_DIGEST)
    tc_destroy_sha1();
    tc_destroy_digests();
#endif

#if (TC_PCAP)
    for (i = 0; i < clt_settings.devices.device_num; i++) {
        if (clt_settings.devices.device[i].pcap != NULL) {
            pcap_close(clt_settings.devices.device[i].pcap);
            clt_settings.devices.device[i].pcap = NULL;
        }
    }
#endif

#if (TC_OFFLINE)
    if (clt_settings.pcap != NULL) {
        pcap_close(clt_settings.pcap);
        clt_settings.pcap = NULL;
    }
#endif

    if (tc_raw_socket_out > 0) {
        tc_socket_close(tc_raw_socket_out);
        tc_raw_socket_out = TC_INVALID_SOCK;
    }

#if (TC_PCAP_SND)
    tc_pcap_over();
#endif

    tc_destroy_pool(clt_settings.pool);

    check_resource_usage(NULL);

    tc_log_end();
}


void
tcp_copy_over(const int sig)
{
    tc_over = sig;
}


static bool send_version(int fd) {
    msg_clt_t    msg;

    tc_memzero(&msg, sizeof(msg_clt_t));
    msg.type = htons(INTERNAL_VERSION);

    if (tc_socket_snd(fd, (char *) &msg, MSG_CLT_SIZE) == TC_ERR) {
        tc_log_info(LOG_ERR, 0, "send version error:%d", fd);
        return false;
    }

    return true;
}


static int
connect_to_server(tc_event_loop_t *ev_lp)
{
    int              i, j, fd;
    uint32_t         target_ip;
    conns_t         *conns;
    uint16_t         target_port;

    for (i = 0; i < clt_settings.real_servers.num; i++) {

        conns = &(clt_settings.real_servers.conns[i]);
        target_ip = conns->ip;
        target_port = conns->port;
        if (target_port == 0) {
            target_port = clt_settings.srv_port;
        }

        if (conns->active != 0) {
            continue;
        }

        for (j = 0; j < conns->num; j++) {
             fd = conns->fds[j];
             if (fd > 0) {
                 tc_log_info(LOG_NOTICE, 0, "it close socket:%d", fd);
                 tc_socket_close(fd);
                 tc_event_del(clt_settings.ev[fd]->loop, 
                         clt_settings.ev[fd], TC_EVENT_READ);
                 tc_event_destroy(clt_settings.ev[fd], 0);
                 conns->fds[j] = -1;
             }
        }

        conns->num = 0;
        conns->remained_num = 0;

        for (j = 0; j < clt_settings.par_conns; j++) {
            fd = tc_message_init(ev_lp, target_ip, target_port);
            if (fd == TC_INVALID_SOCK) {
                return TC_ERR;
            }

            if (!send_version(fd)) {
                return TC_ERR;
            }

            if (j == 0) {
                clt_settings.real_servers.active_num++;
                conns->active = 1;
            }

            conns->fds[j] = fd;
            conns->num++;
            conns->remained_num++;
        }
    }

    return TC_OK;
}


static void 
restore_work(tc_event_timer_t *evt) 
{
    connect_to_server(&event_loop);
    tc_event_update_timer(evt, RETRY_INTERVAL);    
    clt_settings.tries++;
}


int
tcp_copy_init(tc_event_loop_t *ev_lp)
{
    tc_event_add_timer(ev_lp->pool, 60000, NULL, check_resource_usage);
    tc_event_add_timer(ev_lp->pool, OUTPUT_INTERVAL, NULL, tc_interval_disp);

    if (clt_settings.lonely) {
        tc_event_add_timer(ev_lp->pool, RETRY_INTERVAL, NULL, restore_work);
    }

    if  (tc_init_sess_table() == TC_ERR) {
        return TC_ERR;
    }

    if (connect_to_server(ev_lp) == TC_ERR) {
        return TC_ERR;
    }

#if (TC_PLUGIN)
    if (clt_settings.plugin && clt_settings.plugin->init_module) {
        clt_settings.plugin->init_module(&clt_settings);
    }
    if (clt_settings.plugin && clt_settings.plugin->remove_obsolete_resources) {
        tc_event_add_timer(ev_lp->pool, MAX_IDLE_MS_TIME, 
                NULL, remove_obso_resource);
    }
#endif

#if (TC_OFFLINE)
    if (tc_offline_init(ev_lp, clt_settings.pcap_file) == TC_ERR) {
        return TC_ERR;
    }
#else
    if (tc_packets_init(ev_lp) == TC_ERR) {
        return TC_ERR;
    }
#endif

    return TC_OK;
}

