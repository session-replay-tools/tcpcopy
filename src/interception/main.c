/*
 *  TCPCopy - an online replication tool
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
tc_event_loop_t s_event_loop;

static void
release_resources()
{
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
    tc_log_info(LOG_ERR, 0, "set signal handler:%d", sig);
    printf("set signal handler:%d\n", sig);

    if (SIGSEGV == sig) {
        tc_log_info(LOG_ERR, 0, "SIGSEGV error");
        release_resources();
        /* Avoid dead loop*/
        signal(SIGSEGV, SIG_DFL);
        kill(getpid(), sig);
    } else {
        exit(EXIT_SUCCESS);
    }
}

static void
caught_alarm_signal(int sig)
{
    tc_alarm_update_time = 1;
}

static void
set_signal_handler()
{
    int i = 1;

    atexit(release_resources);
    /* Just to try */
    for (; i<SIGTTOU; i++) {
        if (i != SIGPIPE && i != SIGKILL && i !=SIGSTOP ) {
            if (i != SIGALRM) {
                signal(i, signal_handler);
            } else {
                signal(i, caught_alarm_signal);
            }
        }
    }

}

/* Retrieve ip addresses */
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
            len = (size_t)(split - p);
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

        if (NULL == split) {
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
    printf("-x <passlist,> passed ip list through firewall\n"
           "               format:\n"
           "               ip1,ip2,...\n"
           "-p             tcp port number to listen on\n"
           "-s             hash table size for intercept\n"
           "-l <file>      log file path\n"
           "-P <file>      save PID in <file>, only used with -d option\n"
           "-b <ip>        server binded ip address for listening\n"
           "-v             intercept version\n"
           "-h             help\n"
           "-d             run as a daemon\n");
}

static int
read_args(int argc, char **argv) {
    int  c;

    while (-1 != (c = getopt(argc, argv,
         "x:" /* ip list passed through ip firewall */
         "p:" /* TCP port number to listen on */
         "s:" /* Hash table size for intercept */
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
                srv_settings.port = (uint16_t)atoi(optarg);
                break;
            case 's':
                srv_settings.hash_size = (size_t)atoi(optarg);
                break;
            case 'b':
                srv_settings.binded_ip = optarg;
                break;
            case 'h':
                usage();
                exit(EXIT_SUCCESS);
            case 'l':
                srv_settings.log_path = optarg;
                break;
            case 'P':
                srv_settings.pid_file = optarg;
                break;
            case 'v':
                printf ("intercept version:%s\n", VERSION);
                exit(EXIT_SUCCESS);
            case 'd':
                srv_settings.do_daemonize = 1;
                break;
            default:
                fprintf(stderr, "Illegal argument \"%c\"\n", c);
                exit(EXIT_FAILURE);
        }

    }

    return 0;
}

static void
set_details()
{
    /* Set signal handler */
    set_signal_handler();

    /* Ignore SIGPIPE signals */
    if (sigignore(SIGPIPE) == -1) {
        perror("failed to ignore SIGPIPE; sigaction");
        exit(EXIT_FAILURE);
    }
    /* Retrieve ip address */
    if (srv_settings.raw_ip_list != NULL) {
        retrieve_ip_addr();
    }
    /* Daemonize */
    if (srv_settings.do_daemonize) {
        /* TODO why warning*/
        if (sigignore(SIGHUP) == -1) {
            tc_log_info(LOG_ERR, errno, "Failed to ignore SIGHUP");
        }
        if (daemonize() == -1) {
            fprintf(stderr, "failed to daemon() in order to daemonize\n");
            exit(EXIT_FAILURE);
        }
    }
}

/* Set defaults */
static void settings_init(void)
{
    srv_settings.port = SERVER_PORT;
    srv_settings.hash_size = 65536;
    srv_settings.binded_ip = NULL;
}

static void output_for_debug()
{
    /* Print intercept version */
    tc_log_info(LOG_NOTICE, 0, "intercept version:%s", VERSION);
    /* Print intercept working mode */
#if (TCPCOPY_MYSQL_SKIP)
    tc_log_info(LOG_NOTICE, 0, "TCPCOPY_MYSQL_SKIP mode for intercept");
#endif
#if (TCPCOPY_MYSQL_NO_SKIP)
    tc_log_info(LOG_NOTICE, 0, "TCPCOPY_MYSQL_NO_SKIP mode for intercept");
#endif
}

int
main(int argc, char **argv)
{
    int ret;

    settings_init();

    if (tc_time_init(100) == TC_ERROR) {
        return -1;
    }

    read_args(argc, argv);

    if (tc_log_init(srv_settings.log_path) == -1) {
        return -1;
    }

    ret = tc_event_loop_init(&s_event_loop, MAX_FD_NUM);
    if (ret == TC_EVENT_ERROR) {
        tc_log_info(LOG_ERR, 0, "event loop init failed");
        return -1;
    }

    /* Output debug info */
    output_for_debug();
    set_details();

    if (interception_init(&s_event_loop, srv_settings.binded_ip,
                          srv_settings.port) == TC_ERROR)
    {
        return -1;
    }

    /* Run now */
    tc_event_process_cycle(&s_event_loop);

    return 0;
}

