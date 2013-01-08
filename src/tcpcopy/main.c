/*
 *  TCPCopy
 *  An online replication tool for TCP based applications
 *
 *  Copyright 2011 Netease, Inc.  All rights reserved.
 *  Use and distribution licensed under the BSD license.
 *  See the LICENSE file for full text.
 *
 *  Authors:
 *      Bin Wang <wangbin579@gmail.com>
 *      Bo  Wang <wangbo@corp.netease.com>
 */

#include <xcopy.h>
#include <tcpcopy.h>

/* global variables for TCPCopy client */
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
    printf("-x <transfer,> use <transfer,> to specify the IPs and ports of the source and target\n"
           "               servers. Suppose 'sourceIP' and 'sourcePort' are the IP and port \n"
           "               number of the source server you want to copy from, 'targetIP' and \n"
           "               'targetPort' are the IP and port number of the target server you want\n"
           "               to send requests to, the format of <transfer,> could be as follows:\n"
           "               'sourceIP:sourcePort-targetIP:targetPort,...'. Most of the time,\n");
    printf("               sourceIP could be omitted and thus <transfer,> could also be:\n"
           "               'sourcePort-targetIP:targetPort,...'. As seen, the IP address and the\n"
           "               port number are segmented by ':' (colon), the sourcePort and the\n");
    printf("               targetIP are segmented by '-', and two 'transfer's are segmented by\n"
           "               ',' (comma). For example, './tcpcopy -x 80-192.168.0.2:18080' would\n"
           "               copy requests from TCP port '80' on current server to the target port\n"
           "               '18080' of the target IP '192.168.0.2'.\n");
    printf("-c <ip_addr>   change the localhost client IP to this IP address when sending to the\n"
           "               target server. For example,\n"
           "               './tcpcopy -x 8080-192.168.0.2:8080 -c 192.168.0.1' would copy\n"
           "               requests from port '8080' of current online server to the target port\n"
           "               '8080' of target server '192.168.0.2' and modify the client IP to be\n"
           "               '192.168.0.1' when client IP is localhost.\n");
#if (TCPCOPY_OFFLINE)
    printf("-i <file>      set the pcap file used for TCPCopy to <file> (only valid for the\n"
           "               offline version of TCPCopy when it is configured to run at\n"
           "               enable-offline mode)\n");
#endif
#if (TCPCOPY_PCAP)
    printf("-i <device,>   The name of the interface to Listen on.  This is usually a driver\n"
           "               name followed by a unit number,for example eth0 for the first\n"
           "               Ethernet interface.\n");
#endif
#if (TCPCOPY_MYSQL_ADVANCED)
    printf("-u <pair,>     set the user-password pairs to guarantee the copied mysql requests\n"
           "               pass the user authentication of the target mysql server. The format\n"
           "               of <pair,> could be: 'user1@psw1,user2@psw2,...'. The user name and \n"
           "               her/his password are segmented by '@', and the users are segmented \n"
           "               by ','. It should be noted that the user name of the target mysql\n");
    printf("               server should be the same as that of the online source mysql server\n"
           "               and meanwhile their privileges should be the same, whereas the \n"
           "               password of the target mysql server could be different from that\n"
           "               of the source mysql server which could protect the password of \n"
           "               the source server.\n");
#endif
    printf("-n <num>       use <num> to set the replication times when you want to get a \n"
           "               copied data stream that is several times as large as the online data.\n"
           "               The maximum value allowed is 1023. As multiple copying is based on \n"
           "               port number modification, the ports may conflict with each other,\n");
    printf("               in particular in intranet applications where there are few source IPs\n"
           "               and most connections are short. Thus, TCPCopy would perform better \n"
           "               when less copies are specified. For example, \n"
           "               './tcpcopy -x 80-192.168.0.2:8080 -n 3' would copy data flows from \n");
    printf("               port 80 on the current server, generate data stream that is three\n"
           "               times as large as the source data, and send these requests to the\n"
           "               target port 8080 on '192.168.0.2'.\n");
    printf("-f <num>       use this parameter to control the port number modification process\n"
           "               and reduce port conflications when multiple TCPCopy instances are\n"
           "               running. The value of <num> should be different for different TCPCopy\n"
           "               instances. The maximum value allowed is 1023.\n");
    printf("-m <num>       set the maximum memory allowed to use for TCPCopy in megabytes, \n"
           "               to prevent TCPCopy occupying too much memory and influencing the\n"
           "               online system. When the memory exceeds this limit, TCPCopy would quit\n"
           "               automatically. The parameter is effective only when the kernel \n"
           "               version is 2.6.32 or above. The default value is 512.\n");
    printf("-M <num>       MTU value sent to backend (default 1500)\n");
    printf("-S <num>       MSS value sent back(default 1460)\n");
#if (TCPCOPY_DR)
    printf("-s <iplist,> real server ip addresses behind lvs\n"
           "               Format:\n"
           "               ip_addr1, ip_addr2 ...\n");
#endif
    printf("-t <num>       set the session timeout limit. If TCPCopy does not receive response\n"
           "               from the target server within the timeout limit, the session would \n"
           "               be dropped by TCPCopy. When the response from the target server is\n"
           "               slow or the application protocol is context based, the value should \n"
           "               be set larger. The default value is 60 seconds\n");
    printf("-l <file>      save the log information in <file>\n"
           "-r <num>       set the percentage of sessions transfered (integer range:1~100)\n"
           "-p <num>       set the target server listening port. The default value is 36524.\n");
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
         "x:" /* <transfer,> */
         "c:" /* the localhost client ip will be changed to this ip address */
#if (TCPCOPY_OFFLINE)
         "i:" /* input pcap file */
#endif
#if (TCPCOPY_PCAP)
         "i:" /* <device,>*/
#endif
#if (TCPCOPY_MYSQL_ADVANCED)
         "u:" /* user password pair for mysql*/
#endif
         "n:" /* set the replication times */
         "f:" /* use this parameter to reduce port conflications */
         "m:" /* set the maximum memory allowed to use for TCPCopy */
         "p:" /* target server port to listen on */
         "r:" /* percentage of sessions transfered */
         "M:" /* MTU sent to backend */
         "S:" /* mss value sent to backend */
         "t:" /* set the session timeout limit */
#if (TCPCOPY_DR)
         "s:" /* real server ip addresses behind lvs */
#endif
         "l:" /* error log file */
         "P:" /* save PID in file */
         "h"  /* help, licence info */
         "v"  /* version */
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
#if (TCPCOPY_PCAP)
            case 'i':
                clt_settings.raw_device = optarg;
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
            case 'S':
                clt_settings.mss = atoi(optarg);
                break;
#if (TCPCOPY_DR)
            case 's':
                clt_settings.raw_rs_ip_list= optarg;
                break;
#endif
            case 't':
                clt_settings.session_timeout = atoi(optarg);
                break;
            case 'h':
                usage();
                return -1;
            case 'v':
                printf ("TCPCopy version:%s\n", VERSION);
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
                clt_settings.percentage = atoi(optarg);
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
    /* print out version info */
    tc_log_info(LOG_NOTICE, 0, "TCPCopy version:%s", VERSION);
    /* print out target info */
    tc_log_info(LOG_NOTICE, 0, "target:%s", clt_settings.raw_transfer);

    /* print out working mode info */
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
        tc_log_info(LOG_NOTICE, 0, "set global port for TCPCopy");
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
 * two kinds of target formats:
 * 1) 192.168.0.1:80-192.168.0.2:8080
 * 2) 80-192.168.0.2:8080
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

#if (TCPCOPY_PCAP)
/* retrieve devices */
static int
retrieve_devices()
{
    int          count = 0;
    size_t       len;
    devices_t   *devices;
    const char  *split, *p;

    p = clt_settings.raw_device;
    devices = &(clt_settings.devices);

    while (true) {
        split = strchr(p, ',');
        if (split != NULL) {
            len = (size_t) (split - p);
        } else {
            len = strlen(p);
        }

        strncpy(devices->device[count].name, p, len);

        if (count == MAX_DEVICE_NUM) {
            tc_log_info(LOG_WARN, 0, "reach the limit for devices");
            break;
        }

        count++;

        if (split == NULL) {
            break;
        } else {
            p = split + 1;
        }
    }

    devices->device_num = count;

    return 1;
}
#endif


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

#if (TCPCOPY_DR)
static int retrieve_real_servers() 
{
    int          count = 0;
    char         tmp[32];
    size_t       len;
    uint32_t     address;
    const char  *split, *p;

    memset(tmp, 0, 32);
    p = clt_settings.raw_rs_ip_list;

    while (true) {
        split = strchr(p, ',');
        if (split != NULL) {
            len = (size_t) (split - p);
        } else {
            len = strlen(p);
        }

        strncpy(tmp, p, len);
        address = inet_addr(tmp);
        clt_settings.real_servers.ips[count++] = address;

        if (count == MAX_REAL_SERVERS) {
            tc_log_info(LOG_WARN, 0, "reach the limit for real servers");
            break;
        }

        if (split == NULL) {
            break;
        } else {
            p = split + 1;
        }

        memset(tmp, 0, 32);
    }

    clt_settings.real_servers.num = count;

    return 1;

}
#endif

static int
set_details()
{
    int            rand_port;
    unsigned int   seed;
    struct timeval tp;

    /* generate a random port number for avoiding port conflicts */
    gettimeofday(&tp, NULL);
    seed = tp.tv_usec;
    rand_port = (int) ((rand_r(&seed)/(RAND_MAX + 1.0))*512);
    clt_settings.rand_port_shifted = rand_port;

    /* set the ip port pair mapping according to settings */
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

#if (TCPCOPY_PCAP)
    if (clt_settings.raw_device != NULL) {
        tc_log_info(LOG_NOTICE, 0, "device:%s", clt_settings.raw_device);
        if (strcmp(clt_settings.raw_device, DEFAULT_DEVICE) == 0) {
            clt_settings.raw_device = NULL; 
        } else {
            retrieve_devices();
        }
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

#if (TCPCOPY_DR)
    /* retrieve real server ip addresses  */
    if (clt_settings.raw_rs_ip_list != NULL) {
        tc_log_info(LOG_NOTICE, 0, "s parameter:%s", 
                clt_settings.raw_rs_ip_list);
        retrieve_real_servers();
    } else {
        tc_log_info(LOG_WARN, 0, "no real server ip addresses");
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

#if (TCPCOPY_OFFLINE)
    if (tc_time_set_timer(TIMER_INTERVAL) == TC_ERROR) {
#else
    if (tc_time_set_timer(10) == TC_ERROR) {
#endif
        tc_log_info(LOG_ERR, 0, "set timer error");
        return -1;
    }

    return 0;
}

/* set default values for TCPCopy client */
static void
settings_init()
{
    /* init values */
    clt_settings.mtu = DEFAULT_MTU;
    clt_settings.mss = DEFAULT_MSS;
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
    
    if (clt_settings.log_path == NULL) {
        clt_settings.log_path = "error_tcpcopy.log";
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

