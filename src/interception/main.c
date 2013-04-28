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
    if (tc_over > 1) {
        tc_log_info(LOG_WARN, 0, "sig %d received", tc_over); 
    }

    tc_log_info(LOG_NOTICE, 0, "release_resources begin");
    interception_over();

    tc_event_loop_finish(&s_event_loop);

    tc_log_info(LOG_NOTICE, 0, "release_resources end except log file");
    tc_log_end();
}

static void
signal_handler(int sig)
{
    tc_over = (sig != 0 ? sig : 1);
}

static signal_t signals[] = {
    { SIGALRM, "SIGALRM", 0,    tc_time_sig_alarm },
    { SIGTERM, "SIGTERM", 0,    signal_handler },
    { SIGINT,  "SIGINT",  0,    signal_handler },
    { SIGPIPE, "SIGPIPE", 0,    SIG_IGN },
    { 0,        NULL,     0,    NULL }
};

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

#if (INTERCEPT_ADVANCED)
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

    for (i = 0; i < transfer->num; i++) {
        transfer->mappings[i] = malloc(sizeof(ip_port_pair_t));
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
#endif


static void
usage(void)
{
    printf("intercept " VERSION "\n");
    printf("-x <passlist,> passed IP list through firewall\n"
           "               Format:\n"
           "               ip_addr1, ip_addr2 ...\n"
           "-p <num>       set the TCP port number to listen on. The default number is 36524.\n"
           "-s <num>       set the hash table size for intercept. The default value is 65536.\n"
           "-l <file>      save log information in <file>\n");
    printf("-t <num>       set the router item timeout limit. The default value is 120 sec.\n"
           "               It should be set larger when connections are idle longer than \n"
           "               the default value\n"
           "-P <file>      save PID in <file>, only used with -d option\n"
           "-b <ip_addr>   interface to listen on (default: INADDR_ANY, all addresses)\n");
#if (INTERCEPT_ADVANCED)
#if (TCPCOPY_PCAP)
    printf("-f <filter>    set the pcap filter for capturing response packets.\n");
#endif
    printf("-o <target>    set the target for capturing response packets.\n");
#endif
    printf("-v             intercept version\n"
           "-h             print this help and exit\n"
           "-d             run as a daemon\n");
}

static int
read_args(int argc, char **argv) {
    int  c;

    opterr = 0;
    while (-1 != (c = getopt(argc, argv,
         "x:" /* ip list passed through ip firewall */
         "p:" /* TCP port number to listen on */
         "t:" /* router item timeout */
         "s:" /* hash table size for intercept */
         "b:" /* binded ip address */
#if (INTERCEPT_ADVANCED)
#if (TCPCOPY_PCAP)
         "f:" /* filter for pcap */
#endif
         "o:" /* target addresses */
#endif
         "h"  /* print this help and exit */
         "l:" /* error log file path */
         "P:" /* save PID in file */
         "v"  /* print version and exit*/
         "d"  /* daemon mode */
        )))
    {
        switch (c) {
            case 'x':
                srv_settings.raw_ip_list = optarg;
                break;
            case 'p':
                srv_settings.port = (uint16_t) atoi(optarg);
                break;
            case 't':
                srv_settings.timeout = (size_t) atoi(optarg);
                break;
#if (INTERCEPT_ADVANCED)
#if (TCPCOPY_PCAP)
            case 'f':
                srv_settings.filter = optarg;
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
                srv_settings.binded_ip = optarg;
                break;
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

                    case 'p':
                    case 't':
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

static int  
set_details()
{
    /* retrieve ip address */
    if (srv_settings.raw_ip_list != NULL) {
        tc_log_info(LOG_NOTICE, 0, "-x parameter:%s", 
                srv_settings.raw_ip_list);
        retrieve_ip_addr();
    }
    
#if (INTERCEPT_ADVANCED)
    if (srv_settings.raw_targets != NULL) {
        tc_log_info(LOG_NOTICE, 0, "-o parameter:%s", 
                srv_settings.raw_targets);
        retrieve_target_addresses(srv_settings.raw_targets,
                &(srv_settings.targets));
    } else {
        tc_log_info(LOG_WARN, 0, "no raw targets for advanced mode");
        return -1;

    }
#endif

    if (srv_settings.timeout == 0) {
        srv_settings.timeout = DEFAULT_TIMEOUT;
    }
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
    srv_settings.binded_ip = NULL;
}

static void
output_for_debug()
{
    /* print out intercept version */
    tc_log_info(LOG_NOTICE, 0, "intercept version:%s", VERSION);
    /* print out intercept working mode */
#if (TCPCOPY_MYSQL_SKIP)
    tc_log_info(LOG_NOTICE, 0, "TCPCOPY_MYSQL_SKIP mode for intercept");
#endif
#if (TCPCOPY_MYSQL_NO_SKIP)
    tc_log_info(LOG_NOTICE, 0, "TCPCOPY_MYSQL_NO_SKIP mode for intercept");
#endif
#if (INTERCEPT_THREAD)
    tc_log_info(LOG_NOTICE, 0, "INTERCEPT_THREAD mode");
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

}

static int 
set_timer()
{
#if (INTERCEPT_COMBINED)
    if (tc_time_set_timer(10) == TC_ERROR)
#else
    if (tc_time_set_timer(1000) == TC_ERROR)
#endif
    {
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

    if (interception_init(&s_event_loop, srv_settings.binded_ip,
                          srv_settings.port) == TC_ERROR)
    {
        return -1;
    }

    if (set_timer() == -1) {
        return -1;
    }

    /* run now */
    tc_event_process_cycle(&s_event_loop);

    server_release_resources();

    return 0;
}

