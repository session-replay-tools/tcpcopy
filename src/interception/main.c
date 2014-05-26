/*
 *  TCPCopy - An online replication tool for TCP based applications
 *
 *  Copyright 2011 Netease, Inc.  All rights reserved.
 *  Use and distribution licensed under the BSD license.  See
 *  the LICENSE file for full text.
 *
 *  Authors:
 *      bin wang <wangbin579@gmail.com>
 *      bo  wang <wangbo@corp.netease.com>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <xcopy.h>
#include <intercept.h>

xcopy_srv_settings srv_settings;
static tc_event_loop_t s_event_loop;

static void
server_release_resources()
{
    tc_log_info(LOG_WARN, 0, "sig %d received", tc_over); 
    tc_log_info(LOG_NOTICE, 0, "release_resources begin");
    release_tunnel_resources();
    interception_over();

    finally_release_obsolete_events();

    tc_event_loop_finish(&s_event_loop);

    tc_log_info(LOG_NOTICE, 0, "release_resources end except log file");
    tc_log_end();
}

static void
signal_handler(int sig)
{
    tc_over = sig;
}

static signal_t signals[] = {
    { SIGALRM, "SIGALRM", 0,    tc_time_sig_alarm },
    { SIGTERM, "SIGTERM", 0,    signal_handler },
    { SIGINT,  "SIGINT",  0,    signal_handler },
    { SIGPIPE, "SIGPIPE", 0,    SIG_IGN },
    { 0,        NULL,     0,    NULL }
};

#if (!INTERCEPT_ADVANCED)
/* retrieve ip addresses */
static int
retrieve_ip_addr()
{
    int          count = 0;
    char         tmp[32];
    size_t       len;
    uint32_t     address;
    const char  *split, *p;

    memset(tmp, 0, 32);
    p = srv_settings.raw_ip_list;

    while (true) {
        split = strchr(p, ',');
        if (split != NULL) {
            len = (size_t) (split - p);
        } else {
            len = strlen(p);
        }

        strncpy(tmp, p, len);
        address = inet_addr(tmp);
        srv_settings.passed_ips.ips[count++] = address;

        if (count == MAX_ALLOWED_IP_NUM) {
            tc_log_info(LOG_WARN, 0, "reach the limit for passing firewall");
            break;
        }

        if (split == NULL) {
            break;
        } else {
            p = split + 1;
        }

        memset(tmp, 0, 32);
    }

    srv_settings.passed_ips.num = count;

    return 1;
}
#else
static void
parse_target(ip_port_pair_t *pair, char *addr)
{
    char    *seq, *ip_s, *port_s;
    uint16_t tmp_port;

    if ((seq = strchr(addr, ':')) == NULL) {
        pair->ip = 0;
        port_s = addr;
    } else {
        ip_s = addr;
        port_s = seq + 1;

        *seq = '\0';
        pair->ip = inet_addr(ip_s);
        *seq = ':';
    }

    tmp_port = atoi(port_s);
    pair->port = htons(tmp_port);
}


/*
 * retrieve target addresses
 * format
 * 192.168.0.1:80,192.168.0.1:8080
 */
static int
retrieve_target_addresses(char *raw_transfer,
        ip_port_pairs_t *transfer)
{
    int   i;
    char *p, *seq;

    if (raw_transfer == NULL) {
        tc_log_info(LOG_ERR, 0, "it must have -o argument");
        fprintf(stderr, "no -o argument\n");
        return -1;
    }

    for (transfer->num = 1, p = raw_transfer; *p; p++) {
        if (*p == ',') {
            transfer->num++;
        }
    }

    transfer->mappings = malloc(transfer->num *
                                sizeof(ip_port_pair_t *));
    if (transfer->mappings == NULL) {
        return -1;
    }
    memset(transfer->mappings, 0, transfer->num * sizeof(ip_port_pair_t *));

    for (i = 0; i < transfer->num; i++) {
        transfer->mappings[i] = malloc(sizeof(ip_port_pair_t));
        if (transfer->mappings[i] == NULL) {
            return -1;
        }
        memset(transfer->mappings[i], 0, sizeof(ip_port_pair_t));
    }

    p = raw_transfer;
    i = 0;
    for ( ;; ) {
        if ((seq = strchr(p, ',')) == NULL) {
            parse_target(transfer->mappings[i++], p);
            break;
        } else {
            *seq = '\0';
            parse_target(transfer->mappings[i++], p);
            *seq = ',';

            p = seq + 1;
        }
    }

    return 0;
}
#endif


static void
usage(void)
{
    printf("intercept " VERSION "\n");
#if (!INTERCEPT_ADVANCED)
    printf("-x <passlist,> passed IP list through firewall\n"
           "               Format:\n"
           "               ip_addr1, ip_addr2 ...\n");
#endif
#if (INTERCEPT_COMBINED)
    printf("-n <num>       set the maximal num of combined packets.\n");
#endif
    printf("-p <num>       set the TCP port number to listen on. The default number is 36524.\n"
           "-s <num>       set the hash table size for intercept. The default value is 65536.\n"
           "-l <file>      save log information in <file>\n");
    printf("-P <file>      save PID in <file>, only used with -d option\n"
           "-b <ip_addr>   interface to listen on (default: INADDR_ANY, all addresses)\n");
#if (INTERCEPT_NFQUEUE) 
    printf("-q <num>       set the maximal length of the nfnetlink queue if the kernel\n"
           "               supports it.\n");
#endif
#if (INTERCEPT_ADVANCED)
#if (TCPCOPY_PCAP)
    printf("-i <device,>   The name of the interface to listen on.  This is usually a driver\n"
           "               name followed by a unit number,for example eth0 for the first\n"
           "               Ethernet interface.\n");
    printf("-F <filter>    user filter(same as pcap filter)\n");
#endif
    printf("-o <target>    set the target for capturing response packets.\n");
#endif
#if (TCPCOPY_SINGLE)
    printf("-c             set connections protected\n");
#endif
    printf("-v             intercept version\n"
           "-h             print this help and exit\n"
           "-d             run as a daemon\n");
}

static int
read_args(int argc, char **argv) {
    int  c;
#if (INTERCEPT_COMBINED)
    int num;
#endif

    opterr = 0;
    while (-1 != (c = getopt(argc, argv,
#if (!INTERCEPT_ADVANCED)
         "x:" /* ip list passed through ip firewall */
#endif
#if (INTERCEPT_COMBINED)
         "n:"
#endif
         "p:" /* TCP port number to listen on */
         "t:" /* router item timeout */
         "s:" /* hash table size for intercept */
         "b:" /* binded ip address */
#if (INTERCEPT_NFQUEUE) 
         "q:" /* max queue length for nfqueue */
#endif
#if (INTERCEPT_ADVANCED)
#if (TCPCOPY_PCAP)
         "i:" /* <device,> */
         "F:" /* <filter> */
#endif
         "o:" /* target addresses */
#endif
         "h"  /* print this help and exit */
         "l:" /* error log file path */
#if (TCPCOPY_SINGLE)
         "c"
#endif
         "P:" /* save PID in file */
         "v"  /* print version and exit*/
         "d"  /* daemon mode */
        )))
    {
        switch (c) {
#if (!INTERCEPT_ADVANCED)
            case 'x':
                srv_settings.raw_ip_list = optarg;
                break;
#endif
#if (INTERCEPT_COMBINED)
            case 'n':
                num = atoi(optarg);
                if (num >=0 && num < COMB_MAX_NUM) {
                    srv_settings.cur_combined_num = num;
                }
                break;
#endif
            case 'p':
                srv_settings.port = (uint16_t) atoi(optarg);
                break;
#if (INTERCEPT_NFQUEUE) 
            case 'q':
                srv_settings.max_queue_len = atoi(optarg);
                break;
#endif
#if (INTERCEPT_ADVANCED)
#if (TCPCOPY_PCAP)
            case 'i':
                srv_settings.raw_device = optarg;
                break;
            case 'F':
                srv_settings.user_filter = optarg;
                break;
#endif
            case 'o':
                srv_settings.raw_targets = optarg;
                break;
#endif
            case 's':
                srv_settings.hash_size = (size_t) atoi(optarg);
                break;
            case 'b':
                srv_settings.bound_ip = optarg;
                break;
#if (TCPCOPY_SINGLE)
            case 'c':
                srv_settings.conn_protected = true;
                break;
#endif
            case 'h':
                usage();
                return -1;
            case 'l':
                srv_settings.log_path = optarg;
                break;
            case 'P':
                srv_settings.pid_file = optarg;
                break;
            case 'v':
                printf ("intercept version:%s\n", VERSION);
                return -1;
            case 'd':
                srv_settings.do_daemonize = 1;
                break;
            case '?':
                switch (optopt) {    
                    case 'x':
                        fprintf(stderr, "intercept: option -%c require an ip address list\n",
                                optopt);
                        break;
                    case 'b':
                        fprintf(stderr, "intercept: option -%c require an ip address\n", 
                                optopt);
                        break;
                    case 'l':
                    case 'P':
                        fprintf(stderr, "intercept: option -%c require a file name\n", 
                                optopt);
                        break;

                    case 'n':
                    case 'p':
#if (INTERCEPT_NFQUEUE)
                    case 'q':
#endif
                    case 's':
                        fprintf(stderr, "intercept: option -%c require a number\n", 
                                optopt);
                        break;

                    default:
                        fprintf(stderr, "intercept: illegal argument \"%c\"\n", 
                                optopt);
                        break;
                }
                return -1;

            default:
                fprintf(stderr, "intercept: illegal argument \"%c\"\n", optopt);
                return -1;
        }

    }

    return 0;
}

#if (INTERCEPT_ADVANCED && TCPCOPY_PCAP)
static void 
extract_filter()
{
    int              i, cnt = 0;
    char            *pt;
    ip_port_pair_t  *pair, **mappings;

    mappings = srv_settings.targets.mappings;

    pt = srv_settings.filter;
#if (TCPCOPY_UDP)
    strcpy(pt, "udp and (");
#else
    strcpy(pt, "tcp and (");
#endif
    pt = pt + strlen(pt);
 
    for (i = 0; i < srv_settings.targets.num; i++) {

        pair = mappings[i];

        if (pair->port == 0 && pair->ip == 0) {
            continue;
        }

        if (cnt >= MAX_FILTER_ITEMS) {
            break;
        }

        cnt++; 

        if (i > 0) {
            strcpy(pt, " or ");
        }
        pt = pt + strlen(pt);

        pt = construct_filter(SRC_DIRECTION, pair->ip, pair->port, pt);
    }

    strcpy(pt, ")");

    if (cnt == 0) {
        tc_log_info(LOG_WARN, 0, "filter is not set");
    }

    tc_log_info(LOG_NOTICE, 0, "intercept filter = %s", srv_settings.filter);

    return;

}
#endif

static int  
set_details()
{
#if (INTERCEPT_ADVANCED && TCPCOPY_PCAP)
    int  len;
#endif

#if (!INTERCEPT_ADVANCED)
    /* retrieve ip address */
    if (srv_settings.raw_ip_list != NULL) {
        tc_log_info(LOG_NOTICE, 0, "-x parameter:%s", 
                srv_settings.raw_ip_list);
        retrieve_ip_addr();
    }
#endif
    
#if (INTERCEPT_ADVANCED)
    if (srv_settings.raw_targets != NULL) {
        tc_log_info(LOG_NOTICE, 0, "-o parameter:%s", 
                srv_settings.raw_targets);
        retrieve_target_addresses(srv_settings.raw_targets,
                &(srv_settings.targets));
    } else {
#if (!TCPCOPY_PCAP)
        tc_log_info(LOG_WARN, 0, "no raw targets for advanced mode");
        return -1;
#else
        tc_log_info(LOG_NOTICE, 0, "no raw targets for advanced mode");
#endif
    }

#if (TCPCOPY_PCAP)
    if (srv_settings.raw_device != NULL) {
        tc_log_info(LOG_NOTICE, 0, "device:%s", srv_settings.raw_device);
        if (strcmp(srv_settings.raw_device, DEFAULT_DEVICE) == 0) {
            srv_settings.raw_device = NULL; 
        } else {
            retrieve_devices(srv_settings.raw_device, &(srv_settings.devices));
        }
    }

    if (srv_settings.user_filter != NULL) {
        tc_log_info(LOG_NOTICE, 0, "user filter:%s", srv_settings.user_filter);
        len = strlen(srv_settings.user_filter);
        if (len >= MAX_FILTER_LENGH) {
            tc_log_info(LOG_ERR, 0, "user filter is too long");
            return -1;
        }
        memcpy(srv_settings.filter, srv_settings.user_filter, len);
    } else {
        extract_filter();
    }
#endif

#endif

#if (INTERCEPT_NFQUEUE)
    if (srv_settings.max_queue_len <= 1024) {
        srv_settings.max_queue_len = -1;
    }
#endif

    /* daemonize */
    if (srv_settings.do_daemonize) {
        if (sigignore(SIGHUP) == -1) {
            tc_log_info(LOG_ERR, errno, "failed to ignore SIGHUP");
        }
        if (daemonize() == -1) {
            fprintf(stderr, "failed to daemonize() in order to daemonize\n");
            return -1;
        }
    }

    return 0;
}

/* set default values for intercept */
static void
settings_init(void)
{
    srv_settings.port = SERVER_PORT;
    srv_settings.hash_size = 65536;
    srv_settings.bound_ip = NULL;
#if (INTERCEPT_COMBINED)
    srv_settings.cur_combined_num = COMB_MAX_NUM; 
#endif
#if (TCPCOPY_SINGLE)
    srv_settings.conn_protected = false;
#endif
#if (INTERCEPT_NFQUEUE)
    srv_settings.max_queue_len = -1;
#endif
}

static void
output_for_debug()
{
    /* print out intercept version */
    tc_log_info(LOG_NOTICE, 0, "intercept version:%s", VERSION);
    tc_log_info(LOG_NOTICE, 0, "intercept internal version:%d", 
            INTERNAL_VERSION);
    /* print out intercept working mode */
#if (TCPCOPY_MYSQL_SKIP)
    tc_log_info(LOG_NOTICE, 0, "TCPCOPY_MYSQL_SKIP mode for intercept");
#endif
#if (TCPCOPY_MYSQL_NO_SKIP)
    tc_log_info(LOG_NOTICE, 0, "TCPCOPY_MYSQL_NO_SKIP mode for intercept");
#endif
#if (INTERCEPT_NFQUEUE)
    tc_log_info(LOG_NOTICE, 0, "INTERCEPT_NFQUEUE mode");
#endif
#if (TCPCOPY_SINGLE)
    tc_log_info(LOG_NOTICE, 0, "TCPCOPY_SINGLE mode");
#endif
#if (INTERCEPT_COMBINED)
    tc_log_info(LOG_NOTICE, 0, "INTERCEPT_COMBINED mode");
#endif
#if (TCPCOPY_DNAT)
    tc_log_info(LOG_NOTICE, 0, "TCPCOPY_DNAT mode");
#endif
#if (INTERCEPT_ADVANCED)
    tc_log_info(LOG_NOTICE, 0, "INTERCEPT_ADVANCED mode");
#endif
#if (INTERCEPT_MILLION_SUPPORT)
    tc_log_info(LOG_NOTICE, 0, "INTERCEPT_MILLION_SUPPORT mode");
#endif
#if (HAVE_PCAP_CREATE)
    tc_log_info(LOG_NOTICE, 0, "HAVE_PCAP_CREATE is true,new pcap");
#endif


}

static int 
set_timer()
{
    if (tc_time_set_timer(INTERCEPT_TIMER_INTERVAL) == TC_ERROR) {
        tc_log_info(LOG_ERR, 0, "set timer error");
        return -1;
    } 

    return 0;
}


int
main(int argc, char **argv)
{
    int ret;

    settings_init();

    if (set_signal_handler(signals) == -1) {
        return -1;
    }

    tc_time_init();

    if (read_args(argc, argv) == -1) {
        return -1;
    }

    if (srv_settings.log_path == NULL) {
        srv_settings.log_path = "error_intercept.log";  
    }

    if (tc_log_init(srv_settings.log_path) == -1) {
        return -1;
    }

    ret = tc_event_loop_init(&s_event_loop, MAX_FD_NUM);
    if (ret == TC_EVENT_ERROR) {
        tc_log_info(LOG_ERR, 0, "event loop init failed");
        return -1;
    }

    /* output debug info */
    output_for_debug();
    if (set_details() == -1) {
        return -1;
    }

    if (interception_init(&s_event_loop, srv_settings.bound_ip,
                          srv_settings.port) == TC_ERROR)
    {
        return -1;
    }

    if (set_timer() == -1) {
        return -1;
    }

#if (INTERCEPT_COMBINED)
    tc_event_timer_add(&s_event_loop, CHECK_INTERVAL, interception_push);
#endif
    tc_event_timer_add(&s_event_loop, OUTPUT_INTERVAL,
            interception_output_stat);

    /* run now */
    tc_event_process_cycle(&s_event_loop);

    server_release_resources();

    return 0;
}

