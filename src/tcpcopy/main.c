/*
 *  TCPCopy
 *  A request replication tool for TCP based applications 
 *  Or
 *  A TCP stream replay tool(from client side)
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

#if (TCPCOPY_SIGACTION)
static signal_t signals[] = {
    { SIGALRM, "SIGALRM", 0,    tc_time_sig_alarm },
    { SIGINT,  "SIGINT",  0,    tcp_copy_over },
    { SIGPIPE, "SIGPIPE", 0,    tcp_copy_over },
    { SIGHUP,  "SIGHUP",  0,    tcp_copy_over },
    { SIGTERM, "SIGTERM", 0,    tcp_copy_over },
    { 0,        NULL,     0,    NULL }
};
#endif

static void
usage(void)
{
    printf("tcpcopy " VERSION "\n");
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
    printf("-i <file>      set the pcap file used for tcpcopy to <file> (only valid for the\n"
           "               offline version of tcpcopy when it is configured to run at\n"
           "               enable-offline mode)\n");
    printf("-a <num>       accelerated times for offline replay\n");
    printf("-I <num>       set the threshold interval for offline replay acceleration\n"
           "               in millisecond\n");
#endif
#if (TCPCOPY_PCAP)
    printf("-i <device,>   The name of the interface to Listen on.  This is usually a driver\n"
           "               name followed by a unit number,for example eth0 for the first\n"
           "               Ethernet interface.\n");
    printf("-F <filter>    user filter\n");
#endif
#if (TCPCOPY_PCAP_SEND)
    printf("-o <device,>   The name of the interface to send.  This is usually a driver\n"
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
           "               and most connections are short. Thus, tcpcopy would perform better \n"
           "               when less copies are specified. For example, \n"
           "               './tcpcopy -x 80-192.168.0.2:8080 -n 3' would copy data flows from \n");
    printf("               port 80 on the current server, generate data stream that is three\n"
           "               times as large as the source data, and send these requests to the\n"
           "               target port 8080 on '192.168.0.2'.\n");
    printf("-f <num>       use this parameter to control the port number modification process\n"
           "               and reduce port conflications when multiple tcpcopy instances are\n"
           "               running. The value of <num> should be different for different tcpcopy\n"
           "               instances. The maximum value allowed is 1023.\n");
    printf("-m <num>       set the maximum memory allowed to use for tcpcopy in megabytes, \n"
           "               to prevent tcpcopy occupying too much memory and influencing the\n"
           "               online system. When the memory exceeds this limit, tcpcopy would quit\n"
           "               automatically. The parameter is effective only when the kernel \n"
           "               version is 2.6.32 or above. The default value is 512.\n");
    printf("-M <num>       MTU value sent to backend (default 1500)\n");
    printf("-S <num>       MSS value sent back(default 1460)\n");
    printf("-C <num>       parallel connections between tcpcopy and intercept.\n"
           "               The maximum value allowed is 16(default 3 connections since 0.8.0)\n");
#if (TCPCOPY_DR)
    printf("-s <iplist,>   real server ip addresses behind lvs\n"
           "               Format:\n"
           "               ip_addr1, ip_addr2 ...\n");
#endif
    printf("-t <num>       set the session timeout limit. If tcpcopy does not receive response\n"
           "               from the target server within the timeout limit, the session would \n"
           "               be dropped by tcpcopy. When the response from the target server is\n"
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

    opterr = 0;
    while (-1 != (c = getopt(argc, argv,
         "x:" /* <transfer,> */
         "c:" /* the localhost client ip will be changed to this ip address */
#if (TCPCOPY_OFFLINE)
         "i:" /* input pcap file */
         "a:" /* accelerated times */
         "I:" /* threshold interval time for acceleratation */
#endif
#if (TCPCOPY_PCAP)
         "i:" /* <device,> */
         "F:" /* <filter> */
#endif
#if (TCPCOPY_PCAP_SEND)
         "o:" /* <device,> */
#endif
#if (TCPCOPY_MYSQL_ADVANCED)
         "u:" /* user password pair for mysql */
#endif
         "n:" /* set the replication times */
         "f:" /* use this parameter to reduce port conflications */
         "m:" /* set the maximum memory allowed to use for tcpcopy */
         "C:" /* parallel connections between tcpcopy and intercept */
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
                clt_settings.pcap_file = optarg;
                break;
            case 'a':
                clt_settings.accelerated_times = atoi(optarg);
                break;
            case 'I':
                clt_settings.interval = atoi(optarg);
                break;
#endif
#if (TCPCOPY_PCAP_SEND)
            case 'o':
                clt_settings.output_if_name = optarg;
                break;
#endif
#if (TCPCOPY_PCAP)
            case 'i':
                clt_settings.raw_device = optarg;
                break;
            case 'F':
                clt_settings.user_filter = optarg;
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
            case 'C':
                clt_settings.par_connections = atoi(optarg);
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
                clt_settings.raw_rs_ip_list = optarg;
                break;
#endif
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
                clt_settings.percentage = atoi(optarg);
                break;
            case '?':
                switch (optopt) {    
                    case 'x':
#if (TCPCOPY_MYSQL_ADVANCED)
                    case 'u':
#endif
                        fprintf(stderr, "tcpcopy: option -%c require a string\n", 
                                optopt);
                        break;
                    case 'c':
                        fprintf(stderr, "tcpcopy: option -%c require a ip address\n", 
                                optopt);
                        break;
#if (TCPCOPY_OFFLINE)
                    case 'i':
#endif
                    case 'l':
                    case 'P':
                        fprintf(stderr, "tcpcopy: option -%c require a file name\n", 
                                optopt);
                        break;
#if (TCPCOPY_PCAP)
                    case 'i':
                        fprintf(stderr, "tcpcopy: option -%c require a device name\n",
                                optopt);
                        break;
#endif
#if (TCPCOPY_PCAP_SEND)
                    case 'o':
                        fprintf(stderr, "tcpcopy: option -%c require a device name\n",
                                optopt);
                        break;
#endif
#if (TCPCOPY_DR)
                    case 's':
                        fprintf(stderr, "tcpcopy: option -%c require an ip address list\n",
                                optopt);
                        break;
#endif

                    case 'n':
                    case 'f':
                    case 'C':
                    case 'm':
                    case 'M':
                    case 'S':
                    case 't':
                    case 'p':
                    case 'r':
                        fprintf(stderr, "tcpcopy: option -%c require a number\n",
                                optopt);
                        break;

                    default:
                        fprintf(stderr, "tcpcopy: illegal argument \"%c\"\n",
                                optopt);
                        break;
                }
                return -1;

            default:
                fprintf(stderr, "tcpcopy: illegal argument \"%c\"\n", optopt);
                return -1;
        }
    }

    return 0;
}

static void
output_for_debug(int argc, char **argv)
{
    /* print out version info */
    tc_log_info(LOG_NOTICE, 0, "tcpcopy version:%s", VERSION);
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
#if (TCPCOPY_PCAP)
    tc_log_info(LOG_NOTICE, 0, "TCPCOPY_PCAP mode");
#endif
#if (TCPCOPY_SINGLE)
    tc_log_info(LOG_NOTICE, 0, "TCPCOPY_SINGLE mode");
#endif
#if (TCPCOPY_DR)
    tc_log_info(LOG_NOTICE, 0, "TCPCOPY_DR mode");
#endif
#if (TCPCOPY_PAPER)
    tc_log_info(LOG_NOTICE, 0, "TCPCOPY_PAPER mode");
#endif
#if (TCPCOPY_UDP)
    tc_log_info(LOG_NOTICE, 0, "TCPCOPY_UDP mode");
#endif
#if (TCPCOPY_COMBINED)
    tc_log_info(LOG_NOTICE, 0, "TCPCOPY_COMBINED mode");
#endif
#if (TCPCOPY_ADVANCED)
    tc_log_info(LOG_NOTICE, 0, "TCPCOPY_ADVANCED mode");
#endif
#if (TCPCOPY_PCAP_SEND)
    tc_log_info(LOG_NOTICE, 0, "TCPCOPY_PCAP_SEND mode");
#endif
#if (HAVE_PCAP_CREATE)
    tc_log_info(LOG_NOTICE, 0, "HAVE_PCAP_CREATE is true, new pap");
#endif


}


static unsigned char 
char_to_data(const char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }

    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }

    if (ch >= 'A' && ch <= 'Z') {
        return ch - 'A' + 10;
    }

    return 0;
}

static int 
parse_ip_port_pair(char *addr, uint32_t *ip, uint16_t *port, 
        unsigned char *mac)
{
    int      i, len;
    char    *p, *seq, *before_mac, *ip_s, *port_s;
    uint16_t tmp_port;

    if ((before_mac = strchr(addr, '@')) != NULL) {
        *before_mac = '\0';
    }

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

    if (before_mac != NULL) {
        p = before_mac + 1;
        len = strlen(p);
        
        if (len < ETHER_ADDR_STR_LEN) {
            tc_log_info(LOG_WARN, 0, "mac address is too short:%d", len);
            return -1;
        }

        for (i = 0; i < ETHER_ADDR_LEN; ++i) {
            mac[i]  = char_to_data(*p++) << 4;
            mac[i] += char_to_data(*p++);
            p++;
        }   

        *before_mac = '@';
    }

    return 0;
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

    parse_ip_port_pair(addr1, &ip_port->online_ip, &ip_port->online_port,
            ip_port->src_mac);
    parse_ip_port_pair(addr2, &ip_port->target_ip, &ip_port->target_port,
            ip_port->dst_mac);

    if (clt_settings.lo_tf_ip == 0) {
        clt_settings.lo_tf_ip = ip_port->online_ip;
    }

    if (ip_port->target_ip == LOCALHOST) {
        clt_settings.target_localhost = 1;
        tc_log_info(LOG_WARN, 0, "target host is 127.0.0.1");
        tc_log_info(LOG_WARN, 0, 
                "only client requests from localhost are valid");
    }

#if (TCPCOPY_PCAP)
    if (clt_settings.user_filter == NULL && ip_port->online_ip == 0) {
        if (ip_port->online_port == ip_port->target_port) 
        {
            tc_log_info(LOG_WARN, 0, "captured port and target port are equal");
            tc_log_info(LOG_WARN, 0, 
                    "choose a different port or set filter or set device");
        }
    }
#endif

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
    memset(transfer->mappings, 0 , 
            transfer->num * sizeof(ip_port_pair_mapping_t *));

    for (i = 0; i < transfer->num; i++) {
        transfer->mappings[i] = malloc(sizeof(ip_port_pair_mapping_t));
        if (transfer->mappings[i] == NULL) {
            return -1;
        }
        memset(transfer->mappings[i], 0, sizeof(ip_port_pair_mapping_t));
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

#if (TCPCOPY_PCAP)
static void 
extract_filter()
{
    int                      i, cnt = 0;
    char                    *pt;
    ip_port_pair_mapping_t  *pair, **mappings;

    pt = clt_settings.filter;
#if (TCPCOPY_UDP)
    strcpy(pt, "udp and (");
#else
    strcpy(pt, "tcp and (");
#endif
    pt = pt + strlen(pt);
 
    mappings = clt_settings.transfer.mappings;

    for (i = 0; i < clt_settings.transfer.num; i++) {
        pair = mappings[i];
        if (pair->online_ip > 0 || pair->online_port > 0) {
            if (cnt >= MAX_FILTER_ITEMS) {
                break;
            }
            cnt++; 
            if (i > 0) {
                strcpy(pt, " or ");
            }
            pt = pt + strlen(pt);
            pt = construct_filter(DST_DIRECTION,
                    pair->online_ip, pair->online_port, pt);
        }
    }
    strcpy(pt, ")");
    if (cnt == 0) {
        tc_log_info(LOG_WARN, 0, "filter is not set");
    }
    tc_log_info(LOG_NOTICE, 0, "filter = %s", clt_settings.filter);

    return;
}
#endif

static int
set_details()
{
#if (!TCPCOPY_PCAP)
    int            rand_port;
#else
    int            len, rand_port;
#endif
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

    if (clt_settings.percentage < 0 || clt_settings.percentage > 99) {
        clt_settings.percentage = 0;
    }

    if (clt_settings.par_connections <= 0) {
        clt_settings.par_connections = 1;
    } else if (clt_settings.par_connections > MAX_CONNECTION_NUM) {
        clt_settings.par_connections = MAX_CONNECTION_NUM;
    }
    tc_log_info(LOG_NOTICE, 0, "parallel connections per target:%d",
            clt_settings.par_connections);

#if (TCPCOPY_OFFLINE)
    if (clt_settings.pcap_file == NULL) {
        tc_log_info(LOG_ERR, 0, "it must have -i argument for offline");
        fprintf(stderr, "no -i argument\n");
        return -1;
    }

    if (clt_settings.accelerated_times < 1) {
        clt_settings.accelerated_times = 1;
    }

    tc_log_info(LOG_NOTICE, 0, "accelerated %d times,interval:%llu ms",
            clt_settings.accelerated_times, clt_settings.interval);

    if (clt_settings.interval > 0) {
        clt_settings.interval = clt_settings.interval * 1000;
    }
#endif

#if (TCPCOPY_PCAP_SEND)
    if (clt_settings.output_if_name != NULL) {
        tc_log_info(LOG_NOTICE, 0, "output device:%s", 
                clt_settings.output_if_name);
    } else {
        tc_log_info(LOG_ERR, 0, "output device is null");
        return -1;
    }
#endif

#if (TCPCOPY_PCAP)
    if (clt_settings.raw_device != NULL) {
        tc_log_info(LOG_NOTICE, 0, "device:%s", clt_settings.raw_device);
        if (strcmp(clt_settings.raw_device, DEFAULT_DEVICE) == 0) {
            clt_settings.raw_device = NULL; 
        } else {
            retrieve_devices(clt_settings.raw_device, &(clt_settings.devices));
        }
    }

    if (clt_settings.user_filter != NULL) {
        tc_log_info(LOG_NOTICE, 0, "user filter:%s", clt_settings.user_filter);
        len = strlen(clt_settings.user_filter);
        if (len >= MAX_FILTER_LENGH) {
            tc_log_info(LOG_ERR, 0, "user filter is too long");
            return -1;
        }
        memcpy(clt_settings.filter, clt_settings.user_filter, len);

    } else {
        extract_filter();
    }
#endif

#if (TCPCOPY_MYSQL_ADVANCED)
    if (clt_settings.user_pwd != NULL) {
        tc_log_info(LOG_NOTICE, 0, "-u argument:%s",clt_settings.user_pwd);
        if (retrieve_mysql_user_pwd_info(clt_settings.user_pwd) == -1) {
            tc_log_info(LOG_ERR, 0, "wrong -u argument");
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
            fprintf(stderr, "failed to daemonize() in order to daemonize\n");
            return -1;
        }    
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
    clt_settings.par_connections = 3;
    clt_settings.session_timeout = DEFAULT_SESSION_TIMEOUT;
    
#if (TCPCOPY_PCAP_SEND)
    clt_settings.output_if_name = NULL;
#endif

    tc_raw_socket_out = TC_INVALID_SOCKET;

}

static int 
set_timer()
{
    if (tc_time_set_timer(TIMER_INTERVAL) == TC_ERROR) {
        tc_log_info(LOG_ERR, 0, "set timer error");
        return -1;
    }

    return 0;
}

/*
 * main entry point
 */
int
main(int argc, char **argv)
{
    int ret;

    settings_init();

#if (TCPCOPY_SIGACTION)
    if (set_signal_handler(signals) == -1) {
        return -1;
    }
#else
    signal(SIGALRM, tc_time_sig_alarm);
    signal(SIGINT,  tcp_copy_over);
    signal(SIGPIPE, tcp_copy_over);
    signal(SIGHUP,  tcp_copy_over);
    signal(SIGTERM, tcp_copy_over);
#endif

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

#if (TCPCOPY_MYSQL_ADVANCED) 
    tc_init_digests();
    if (!tc_init_sha1()) {
        return -1;
    }
#endif

    ret = tc_event_loop_init(&event_loop, MAX_FD_NUM);
    if (ret == TC_EVENT_ERROR) {
        tc_log_info(LOG_ERR, 0, "event loop init failed");
        return -1;
    }

    ret = tcp_copy_init(&event_loop);
    if (ret == TC_ERROR) {
        exit(EXIT_FAILURE);
    }

    if (set_timer() == -1) {
        return -1;
    }

    /* run now */
    tc_event_process_cycle(&event_loop);

    tcp_copy_release_resources();

    return 0;
}

