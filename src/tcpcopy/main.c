/*
 *  TCPCopy
 *  An online replication tool for TCP based applications
 *
 *  Copyright 2011 Netease, Inc.  All rights reserved.
 *  Use and distribution licensed under the BSD license.
 *  See the LICENSE file for full text.
 *
 *  Authors:
 *      bin wang <wangbin579@gmail.com>
 *      bo  wang <wangbo@corp.netease.com>
 */

#include <xcopy.h>
#include <tcpcopy.h>

/* global variables for tcpcopy client */
xcopy_clt_settings clt_settings;

int tc_raw_socket_out;
tc_event_loop_t event_loop;

static void
set_signal_handler()
{
    signal(SIGALRM, tc_time_sig_alarm);
    signal(SIGINT,  tcp_copy_over);
    signal(SIGPIPE, tcp_copy_over);
    signal(SIGHUP,  tcp_copy_over);
    signal(SIGTERM, tcp_copy_over);
}

static void
usage(void)
{
    printf("TCPCopy " VERSION "\n");
    printf("-x <transfer,> what we copy and where send to\n"
           "               transfer format:\n"
           "               online_ip:online_port-target_ip:target_port,...\n"
           "               or :\n"
           "               online_port-target_ip:target_port,...\n");
    printf("-c <ip>        localhost will be changed to this ip address\n"
           "               when sending to another machine\n"
           "               default value is online ip\n");
#if (TCPCOPY_OFFLINE)
    printf("-i <file>      input pcap file(only valid for offline)\n");
#endif
#if (TCPCOPY_MYSQL_ADVANCED)
    printf("-u <pair>      user password pair for mysql\n"
           "               pair format:\n"
           "               user1@psw1:user2@psw2:...\n"
           "               attension:\n"
           "               users of the target test should be the same as\n"
           "               that of online\n");
#endif
    printf("-n <num>       the number of replication for multi-copying\n"
           "               the less,the better\n"
           "               max value allowed is 1023:\n"
           "-f <num>       port shift factor for mutiple tcpcopy instances\n"
           "               max value allowed is 1023:\n");
    printf("-m <num>       max memory to use for tcpcopy in megabytes\n"
           "               default value is 512:\n"
           "-M <num>       MTU sent to backend(default:1500)\n"
           "-t <num>       session timeout\n"
           "               if the target system is slow, set this larger\n");
    printf("-l <file>      log file path\n"
           "-r <num>       percentage of sessions transfered(int,1~100)\n"
           "-p <num>       remote server listening port\n");
    printf("-P <file>      save PID in <file>, only used with -d option\n"
           "-h             print this help and exit\n"
           "-v             version\n"
           "-d             run as a daemon\n");
}



static int
read_args(int argc, char **argv)
{
    int  c;

    while (-1 != (c = getopt(argc, argv,
         "x:" /* where we copy request from and to */
         "c:" /* localhost will be changed to this ip address */
#if (TCPCOPY_OFFLINE)
         "i:" /* input pcap file */
#endif
#if (TCPCOPY_MYSQL_ADVANCED)
         "u:" /* user password pair for mysql*/
#endif
         "n:" /* the replicated number of each request for multi-copying */
         "f:" /* port shift factor for mutiple tcpcopy instances */
         "m:" /* max memory to use for tcpcopy client in megabytes */
         "p:" /* remote server listening port */
         "r:" /* percentage of sessions transfered */
         "M:" /* MTU sent to backend */
         "t:" /* session timeout value */
         "l:" /* error log file path */
         "P:" /* save PID in file */
         "h"  /* help, licence info */
         "v"  /* verbose */
         "d"  /* daemon mode */
        ))) {
        switch (c) {
            case 'x':
                clt_settings.raw_transfer = optarg;
                break;
            case 'c':
                clt_settings.lo_tf_ip = inet_addr(optarg);
                break;
#if (TCPCOPY_OFFLINE)
            case 'i':
                clt_settings.pcap_file= optarg;
                break;
#endif
#if (TCPCOPY_MYSQL_ADVANCED)
            case 'u':
                clt_settings.user_pwd = optarg;
                break;
#endif
            case 'n':
                clt_settings.replica_num = atoi(optarg);
                break;
            case 'f':
                clt_settings.factor = atoi(optarg);
                break;
            case 'm':
                clt_settings.max_rss = 1024*atoi(optarg);
                break;
            case 'l':
                clt_settings.log_path = optarg;
                break;
            case 'M':
                clt_settings.mtu = atoi(optarg);
                break;
            case 't':
                clt_settings.session_timeout = atoi(optarg);
                break;
            case 'h':
                usage();
                return -1;
            case 'v':
                printf ("tcpcopy version:%s\n", VERSION);
                return -1;
            case 'd':
                clt_settings.do_daemonize = 1;
                break;
            case 'p':
                clt_settings.srv_port = atoi(optarg);
                break;
            case 'P':
                clt_settings.pid_file = optarg;
                break;
            case 'r':
                clt_settings.percentage= atoi(optarg);
                break;
            default:
                fprintf(stderr, "Illegal argument \"%c\"\n", c);
                return -1;
        }
    }

    return 0;
}

static void
output_for_debug(int argc, char **argv)
{
    /* print tcpcopy version */
    tc_log_info(LOG_NOTICE, 0, "tcpcopy version:%s", VERSION);
    /* print target */
    tc_log_info(LOG_NOTICE, 0, "target:%s", clt_settings.raw_transfer);

    /* print tcpcopy working mode */
#if (TCPCOPY_MYSQL_SKIP)
    tc_log_info(LOG_NOTICE, 0, "TCPCOPY_MYSQL_SKIP mode");
#endif
#if (TCPCOPY_MYSQL_NO_SKIP)
    tc_log_info(LOG_NOTICE, 0, "TCPCOPY_MYSQL_NO_SKIP mode");
#endif
#if (TCPCOPY_OFFLINE)
    tc_log_info(LOG_NOTICE, 0, "TCPCOPY_OFFLINE mode");
#endif
}

static void
parse_ip_port_pair(char *addr, uint32_t *ip, uint16_t *port)
{
    char    *seq, *ip_s, *port_s;
    uint16_t tmp_port;

    if ((seq = strchr(addr, ':')) == NULL) {
        tc_log_info(LOG_NOTICE, 0, "set global port for tcpcopy");
        *ip = 0;
        port_s = addr;
    } else {
        ip_s = addr;
        port_s = seq + 1;

        *seq = '\0';
        *ip = inet_addr(ip_s);
        *seq = ':';
    }

    tmp_port = atoi(port_s);
    *port = htons(tmp_port);
}

/*
 * one target format:
 * 192.168.0.1:80-192.168.0.2:8080
 * or
 * 80-192.168.0.2:8080
 */
static int
parse_target(ip_port_pair_mapping_t *ip_port, char *addr)
{
    char   *seq, *addr1, *addr2;

    if ((seq = strchr(addr, '-')) == NULL) {
        tc_log_info(LOG_WARN, 0, "target \"%s\" is invalid", addr);
        return -1;
    } else {
        *seq = '\0';
    }

    addr1 = addr;
    addr2 = seq + 1;

    parse_ip_port_pair(addr1, &ip_port->online_ip, &ip_port->online_port);
    parse_ip_port_pair(addr2, &ip_port->target_ip, &ip_port->target_port);

    if (clt_settings.lo_tf_ip == 0) {
        clt_settings.lo_tf_ip = ip_port->online_ip;
    }

    *seq = '-';

    return 0;
}

/*
 * retrieve target addresses
 * format
 * 192.168.0.1:80-192.168.0.2:8080,192.168.0.1:8080-192.168.0.3:80
 */
static int
retrieve_target_addresses(char *raw_transfer,
        ip_port_pair_mappings_t *transfer)
{
    int   i;
    char *p, *seq;

    if (raw_transfer == NULL) {
        tc_log_info(LOG_ERR, 0, "it must have -x argument");
        fprintf(stderr, "no -x argument\n");
        return -1;
    }

    for (transfer->num = 1, p = raw_transfer; *p; p++) {
        if (*p == ',') {
            transfer->num++;
        }
    }

    transfer->mappings = malloc(transfer->num *
                                sizeof(ip_port_pair_mapping_t *));
    if (transfer->mappings == NULL) {
        return -1;
    }

    for (i = 0; i < transfer->num; i++) {
        transfer->mappings[i] = malloc(sizeof(ip_port_pair_mapping_t));
        if (transfer->mappings[i] == NULL) {
            return -1;
        }
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

static int
sigignore(int sig)
{
    struct sigaction sa;

    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;

    if (sigemptyset(&sa.sa_mask) == -1 || sigaction(sig, &sa, 0) == -1) {
        return -1;
    }

    return 0;
}

static int
set_details()
{
    int            rand_port;
    unsigned int   seed;
    struct timeval tp;

    /* generate random port for avoiding port conflicts */
    gettimeofday(&tp, NULL);
    seed = tp.tv_usec;
    rand_port = (int) ((rand_r(&seed)/(RAND_MAX + 1.0))*512);
    clt_settings.rand_port_shifted = rand_port;

    /* set ip port pair mapping according to settings */
    if (retrieve_target_addresses(clt_settings.raw_transfer,
                              &clt_settings.transfer) == -1)
    {
        return -1;
    }

    if (clt_settings.percentage < 0 && clt_settings.percentage >99) {
        clt_settings.percentage = 0;
    }

#if (TCPCOPY_OFFLINE)
    if (clt_settings.pcap_file == NULL) {
        tc_log_info(LOG_ERR, 0, "it must have -i argument for offline");
        fprintf(stderr, "no -i argument\n");
        return -1;
    }
#endif

#if (TCPCOPY_MYSQL_ADVANCED)
    if (clt_settings.user_pwd != NULL) {
        if (retrieve_mysql_user_pwd_info(clt_settings.user_pwd) == -1) {
            return -1;
        }
    } else {
        tc_log_info(LOG_ERR, 0, "it must have -u argument");
        fprintf(stderr, "no -u argument\n");
        return -1;
    }
#endif

    /* daemonize */
    if (clt_settings.do_daemonize) {
        if (sigignore(SIGHUP) == -1) {
            tc_log_info(LOG_ERR, errno, "Failed to ignore SIGHUP");
        }
        if (daemonize() == -1) {
            fprintf(stderr, "failed to daemon() in order to daemonize\n");
            return -1;
        }    
    }    

    if (tc_time_set_timer(100) == TC_ERROR) {
        tc_log_info(LOG_ERR, 0, "set timer error");
        return -1;
    }

    return 0;
}

/* set defaults */
static void
settings_init()
{
    /* init values */
    clt_settings.mtu = DEFAULT_MTU;
    clt_settings.max_rss = MAX_MEMORY_SIZE;
    clt_settings.srv_port = SERVER_PORT;
    clt_settings.percentage = 0;
    clt_settings.session_timeout = DEFAULT_SESSION_TIMEOUT;

    tc_raw_socket_out = TC_INVALID_SOCKET;

    set_signal_handler();
}

/*
 * main entry point
 */
int
main(int argc, char **argv)
{
    int ret;

    settings_init();

    tc_time_init();

    if (read_args(argc, argv) == -1) {
        return -1;
    }

    if (tc_log_init(clt_settings.log_path) == -1) {
        return -1;
    }

    /* output debug info */
    output_for_debug(argc, argv);

    /* set details for running */
    if (set_details() == -1) {
        return -1;
    }

    ret = tc_event_loop_init(&event_loop, MAX_FD_NUM);
    if (ret == TC_EVENT_ERROR) {
        tc_log_info(LOG_ERR, 0, "event loop init failed");
        return -1;
    }

    ret = tcp_copy_init(&event_loop);
    if (ret == TC_ERROR) {
        exit(EXIT_FAILURE);
    }

    /* run now */
    tc_event_process_cycle(&event_loop);

    tcp_copy_release_resources();

    return 0;
}

