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
#include "../core/xcopy.h"
#include "../log/log.h"
#include "interception.h"

xcopy_srv_settings srv_settings;

static void release_resources()
{
    log_info(LOG_NOTICE, "release_resources begin");
    interception_over();
    log_info(LOG_NOTICE, "release_resources end except log file");
    log_end();
    if(srv_settings.raw_ip_list != NULL){
        free(srv_settings.raw_ip_list);
        srv_settings.raw_ip_list = NULL;
    }
    if(srv_settings.binded_ip != NULL){
        free(srv_settings.binded_ip);
        srv_settings.binded_ip = NULL;
    }
    if(srv_settings.log_path != NULL){
        free(srv_settings.log_path);
        srv_settings.log_path = NULL;
    }
}

/* TODO It has to solve the sigignore warning problem */
static int sigignore(int sig) 
{    
    struct sigaction sa = { .sa_handler = SIG_IGN, .sa_flags = 0 };

    if (sigemptyset(&sa.sa_mask) == -1 || sigaction(sig, &sa, 0) == -1){
        return -1;
    }       
    return 0;
}

static void signal_handler(int sig)
{
    log_info(LOG_ERR, "set signal handler:%d", sig);
    printf("set signal handler:%d\n", sig);
    if(SIGSEGV == sig){    
        log_info(LOG_ERR, "SIGSEGV error");
        release_resources();
        /* Avoid dead loop*/
        signal(SIGSEGV, SIG_DFL);
        kill(getpid(), sig);
    }else{    
        exit(EXIT_SUCCESS);
    } 
}

static void set_signal_handler(){
    int i=1;
    atexit(release_resources);
    /* Just to try */
    for(; i<SIGTTOU; i++){
        if(i != SIGPIPE){
            signal(i, signal_handler);
        }
    }

}

/* Retrieve ip addresses */
static int retrieve_ip_addr()
{
    size_t      len;
    int         count = 0;
    const char  *split, *p;
    char        tmp[32];
    uint32_t    address;

    memset(tmp, 0, 32);
    p = srv_settings.raw_ip_list;

    while(1){
        split = strchr(p, ',');
        if(split != NULL){   
            len = (size_t)(split - p);
        }else{   
            len = strlen(p);
        }   
        strncpy(tmp, p, len);
        address = inet_addr(tmp);    
        srv_settings.passed_ips.ips[count++] = address;

        if(count == MAX_ALLOWED_IP_NUM){
            log_info(LOG_WARN, "reach the limit for passing firewall");
            break;
        }

        if(NULL == split){
            break;
        }else{
            p = split + 1;
        }

        memset(tmp, 0, 32);
    }

    srv_settings.passed_ips.num = count;

    return 1;
}

static void usage(void) {  
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

static int read_args(int argc, char **argv){
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
        ))) {
        switch (c) {
            case 'x':
                srv_settings.raw_ip_list = strdup(optarg);
                break;
            case 'p':
                srv_settings.port = (uint16_t)atoi(optarg);
                break;
            case 's':
                srv_settings.hash_size = (size_t)atoi(optarg);
                break;
            case 'b':
                srv_settings.binded_ip = strdup(optarg);
                break;
            case 'h':
                usage();
                exit(EXIT_SUCCESS);
            case 'l':
                srv_settings.log_path = strdup(optarg);
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

static void set_details()
{
    /* Set signal handler */    
    set_signal_handler();
    /* Ignore SIGPIPE signals */
    if (sigignore(SIGPIPE) == -1) {
        perror("failed to ignore SIGPIPE; sigaction");
        exit(EXIT_FAILURE);
    }
    /* Retrieve ip address */
    if(srv_settings.raw_ip_list != NULL){
        retrieve_ip_addr();
    }
    /* Daemonize */
    if (srv_settings.do_daemonize) {
        /* TODO why warning*/
        if (sigignore(SIGHUP) == -1) {
            perror("Failed to ignore SIGHUP");
            log_info(LOG_ERR, "Failed to ignore SIGHUP");
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

int main(int argc ,char **argv){
    /* Init settings */ 
    settings_init();
    /* Read args */
    read_args(argc, argv);
    /* Init log */
    log_init(srv_settings.log_path);
    /* Set details */
    set_details(); 
    /* Init interception */
    interception_init(srv_settings.port);
    /* Run now */
    interception_run();

    return 0;
}

