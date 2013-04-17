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
    interception_over();

    tc_event_loop_finish(&s_event_loop);

    tc_log_info(LOG_NOTICE, 0, "release_resources end except log file");
    tc_log_end();
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

static void
signal_handler(int sig)
{
    tc_over = sig;
}

static void
set_signal_handler()
{
    signal(SIGALRM, tc_time_sig_alarm);
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
}

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
           "-b <ip_addr>   interface to listen on (default: INADDR_ANY, all addresses)\n"
           "-v             intercept version\n"
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
    /* ignore SIGPIPE signals */
    if (sigignore(SIGPIPE) == -1) {
        tc_log_info(LOG_ERR, errno, "failed to ignore SIGPIPE");
        return -1;
    }

    /* retrieve ip address */
    if (srv_settings.raw_ip_list != NULL) {
        tc_log_info(LOG_NOTICE, 0, "-x parameter:%s", 
                srv_settings.raw_ip_list);
        retrieve_ip_addr();
    }

    if (srv_settings.timeout == 0) {
        srv_settings.timeout = DEFAULT_TIMEOUT;
    }
    /* daemonize */
    if (srv_settings.do_daemonize) {
        if (sigignore(SIGHUP) == -1) {
            tc_log_info(LOG_ERR, errno, "failed to ignore SIGHUP");
        }
        if (daemonize() == -1) {
            fprintf(stderr, "failed to daemon() in order to daemonize\n");
            return -1;
        }
    }

    if (tc_time_set_timer(1000) == TC_ERROR) {
        tc_log_info(LOG_ERR, 0, "set timer error");
        return -1;
    }   

    return 0;
}

/* set default values for intercept */
static void settings_init(void)
{
    srv_settings.port = SERVER_PORT;
    srv_settings.hash_size = 65536;
    srv_settings.binded_ip = NULL;

    set_signal_handler();
}

static void output_for_debug()
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

}


int
main(int argc, char **argv)
{
    int ret;

    settings_init();

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

    /* run now */
    tc_event_process_cycle(&s_event_loop);

    server_release_resources();

    return 0;
}

