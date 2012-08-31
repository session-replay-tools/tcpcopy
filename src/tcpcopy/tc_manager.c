
#include <xcopy.h>
#include <tcpcopy.h>

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
    return (int)(long) fd;
}

void
address_add_sock(uint32_t ip, uint16_t port, int fd) 
{
    uint64_t key = get_key(ip, port);
    hash_add(addr_table, key, (void *)(long)fd);
}

void 
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
            hn = (hash_node *)ln->data;
            if (hn->data != NULL) {

                fd  = (int)(long)hn->data;
                hn->data = NULL;

                if (0 != fd) {
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
tcp_copy_release_resources()
{
    int i;

    output_stat();

    tc_time_remove_timer();
    tc_log_info(LOG_NOTICE, 0, "remove timer over");

    destroy_for_sessions();

    tc_event_loop_finish(&event_loop);
    tc_log_info(LOG_NOTICE, 0, "tc_event_loop_finish over");

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
}

void
tcp_copy_over(const int sig)
{
    long int pid   = (long int)syscall(SYS_gettid);

    tc_log_info(LOG_WARN, 0, "sig %d received, pid=%ld", sig, pid);

    event_loop.event_over = 1;
}


/* Initiate tcpcopy client */
int
tcp_copy_init(tc_event_loop_t *event_loop)
{
    int                      i, fd;
    uint32_t                 target_ip;
    ip_port_pair_mapping_t  *pair, **mappings;

    /* Register some timer */
    tc_event_timer_add(event_loop, 60000, check_resource_usage);
    tc_event_timer_add(event_loop, 5000, tc_interval_dispose);

    /* Init session table*/
    init_for_sessions();

    address_init();

    /* Add connections to the tested server for exchanging info */
    mappings = clt_settings.transfer.mappings;
    for (i = 0; i < clt_settings.transfer.num; i++) {

        pair = mappings[i];
        target_ip = pair->target_ip;

        fd = tc_message_init(event_loop, target_ip, clt_settings.srv_port);
        if (fd == TC_INVALID_SOCKET) {
            return TC_ERROR;
        }

        address_add_sock(pair->online_ip, pair->online_port, fd);

        tc_log_info(LOG_NOTICE, 0, "add a tunnel for exchanging info:%u:%u",
                    ntohl(target_ip), clt_settings.srv_port);
    }

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

    return TC_OK;
}
