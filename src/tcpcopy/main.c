/*
 *  TCPCopy 1.0 series
 *  A request replication tool for TCP based applications 
 *  Or
 *  A TCP stream replay tool(from client side)
 *
 *  Copyright 2014 Netease, Inc.  All rights reserved.
 *  Use and distribution licensed under the BSD license.
 *  See the LICENSE file for full text.
 *
 *  Authors:
 *      Bin Wang <wangbin579@gmail.com>
 */

#include <xcopy.h>
#include <tcpcopy.h>

/* global variables for TCPCopy client */
int                tc_raw_socket_out;
tc_stat_t          tc_stat;
hash_table        *sess_table;
tc_event_loop_t    event_loop;
xcopy_clt_settings clt_settings;

#if (TC_SIGACTION)
static signal_t signals[] = {
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
#if (!TC_PCAP_SND)
    printf("-x <transfer,> use <transfer,> to specify the IPs and ports of the source and target\n"
           "               servers. Suppose 'sourceIP' and 'sourcePort' are the IP and port \n"
           "               number of the source server you want to copy from, 'targetIP' and \n");
    printf("               'targetPort' are the IP and port number of the target server you want\n"
           "               to send requests to, the format of <transfer,> could be as follows:\n"
           "               'sourceIP:sourcePort-targetIP:targetPort,...'. Most of the time,\n");
    printf("               sourceIP could be omitted and thus <transfer,> could also be:\n"
           "               'sourcePort-targetIP:targetPort,...'. As seen, the IP address and the\n"
           "               port number are segmented by ':' (colon), the sourcePort and the\n");
    printf("               targetIP are segmented by '-', and two 'transfer's are segmented by\n"
           "               ',' (comma). For example, './tcpcopy -x 80-192.168.0.2:18080' would\n"
           "               copy requests from port '80' on current server to the target port\n"
           "               '18080' of the target IP '192.168.0.2'.\n");
#else
    printf("-x <transfer,> use <transfer,> to specify the IPs, ports and MAC addresses of\n"
           "               the source and target. The format of <transfer,> could be as follow:\n");
    printf("               'sourceIP:sourcePort@sourceMac-targetIP:targetPort@targetMac,...'.\n"
           "               Most of the time, sourceIP could be omitted and thus <transfer,> could\n"
           "               also be: sourcePort@sourceMac-targetIP:targetPort@targetMac,...'.\n");
    printf("               Note that sourceMac is the MAC address of the interface where \n"
           "               packets are going out and targetMac is the next hop's MAC address.\n");
#endif
    printf("-H <ip_addr>   change the localhost IP address to the given IP address\n");
    printf("-c <ip_addr,>  change the client IP to one of IP addresses when sending to the\n"
           "               target server. For example,\n"
           "               './tcpcopy -x 8080-192.168.0.2:8080 -c 62.135.200.*' would copy\n"
           "               requests from port '8080' of current online server to the target port\n"
           "               '8080' of target server '192.168.0.2' and modify the client IP to be\n"
           "               one of net 62.135.200.0/24.\n");
#if (TC_OFFLINE)
    printf("-i <file>      set the pcap file used for tcpcopy to <file> (only valid for the\n"
           "               offline version of tcpcopy when it is configured to run at\n"
           "               enable-offline mode).\n");
    printf("-a <num>       accelerated times for offline replay\n");
    printf("-I <num>       set the threshold interval for offline replay acceleration\n"
           "               in millisecond.\n");
#endif
#if (TC_PCAP)
    printf("-i <device,>   The name of the interface to listen on. This is usually a driver\n"
           "               name followed by a unit number, for example eth0 for the first\n"
           "               Ethernet interface.\n");
    printf("-F <filter>    user filter (same as pcap filter)\n");
    printf("-B <num>       buffer size for pcap capture in megabytes(default 16M)\n");
    printf("-S <snaplen>   capture <snaplen> bytes per packet\n");
#endif
#if (TC_PCAP_SND)
    printf("-o <device,>   The name of the interface to send. This is usually a driver\n"
           "               name followed by a unit number, for example eth0 for the first\n"
           "               Ethernet interface.\n");
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
           "               automatically. The parameter is effective only when the kernel \n");
#if (TC_MILLION_SUPPORT)
    printf("               version is 2.6.32 or above. The default value is 4096.\n");
#else
    printf("               version is 2.6.32 or above. The default value is 1024.\n");
#endif
    printf("-M <num>       MTU value sent to backend (default 1500)\n");
    printf("-D <num>       MSS value sent back(default 1460)\n");
    printf("-R <num>       set default rtt value\n");
    printf("-U <num>       set user session pool size in kilobytes(default 1).\n"
           "               The maximum value allowed is 63.\n");
    printf("-C <num>       parallel connections between tcpcopy and intercept.\n"
           "               The maximum value allowed is 11(default 2 connections).\n");
    printf("-s <server,>   intercept server list\n"
           "               Format:\n"
           "               ip_addr1:port1, ip_addr2:port2, ...\n");
    printf("-t <num>       set the session timeout limit. If tcpcopy does not receive response\n"
           "               from the target server within the timeout limit, the session would \n"
           "               be dropped by tcpcopy. When the response from the target server is\n"
           "               slow or the application protocol is context based, the value should \n"
           "               be set larger. The default value is 120 seconds.\n");
    printf("-k <num>       set the session keepalive timeout limit.\n");
    printf("-l <file>      save the log information in <file>\n"
           "-r <num>       set the percentage of sessions transfered (integer range:1~100)\n"
           "-p <num>       set the target server listening port. The default value is 36524.\n");
    printf("-P <file>      save PID in <file>, only used with -d option\n");
    printf("-O             only replay full session\n");
    printf("-g             gradully replay\n");
    printf("-L             lonely for tcpcopy when intercept is closed\n");
    printf("-h             print this help and exit\n"
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
         "c:" 
#if (TC_OFFLINE)
         "i:" /* input pcap file */
         "a:" /* accelerated times */
         "I:" /* threshold interval time for acceleratation */
#endif
#if (TC_PCAP)
         "i:" /* <device,> */
         "F:" /* <filter> */
         "B:" 
#endif
#if (TC_PCAP_SND)
         "o:" /* <device,> */
#endif
         "n:" /* set the replication times */
         "f:" /* use this parameter to reduce port conflications */
         "m:" /* set the maximum memory allowed to use for tcpcopy */
         "C:" /* parallel connections between tcpcopy and intercept */
         "p:" /* target server port to listen on */
         "r:" /* percentage of sessions transfered */
         "M:" /* MTU sent to backend */
         "S:" 
         "U:" 
         "R:" 
         "D:" /* mss value sent to backend */
         "t:" /* set the session timeout limit */
         "k:" /* set the session keepalive timeout limit */
         "s:" /* real servers running intercept*/
         "l:" /* error log file */
         "P:" /* save PID in file */
         "L"  /* lonely */
         "O"  
         "g"  
         "h"  /* help, licence info */
         "v"  /* version */
         "d"  /* daemon mode */
        ))) {
        switch (c) {
            case 'x':
                clt_settings.raw_tf = optarg;
                break;
            case 'c':
                clt_settings.raw_clt_tf_ip = optarg;
                break;
            case 'H':
                clt_settings.localhost_tf_ip = inet_addr(optarg);
                break;
#if (TC_OFFLINE)
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
#if (TC_PCAP_SND)
            case 'o':
                clt_settings.output_if_name = optarg;
                break;
#endif
#if (TC_PCAP)
            case 'i':
                clt_settings.raw_device = optarg;
                break;
            case 'F':
                clt_settings.user_filter = optarg;
                break;
            case 'B':
                clt_settings.buffer_size = 1024 * 1024 * atoi(optarg);
                break;
            case 'S':
                clt_settings.snaplen = atoi(optarg);
                break;

#endif
            case 'n':
                clt_settings.replica_num = atoi(optarg);
                break;
            case 'f':
                clt_settings.factor = atoi(optarg);
                break;
            case 'm':
                clt_settings.max_rss = 1024 * atoi(optarg);
                break;
            case 'C':
                clt_settings.par_conns = atoi(optarg);
                break;
            case 'U':
                clt_settings.s_pool_size = 1024 * atoi(optarg);
                break;
            case 'l':
                clt_settings.log_path = optarg;
                break;
            case 'R':
                clt_settings.default_rtt = atoi(optarg);
                break;
            case 'M':
                clt_settings.mtu = atoi(optarg);
                break;
            case 'D':
                clt_settings.mss = atoi(optarg);
                break;
            case 's':
                clt_settings.raw_rs_list = optarg;
                break;
            case 't':
                clt_settings.sess_timeout = atoi(optarg);
                break;
            case 'k':
                clt_settings.sess_keepalive_timeout = atoi(optarg);
                break;
            case 'g':
                clt_settings.gradully = 1;
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
            case 'L':
                clt_settings.lonely = 1;
                break;
            case 'O':
                clt_settings.only_replay_full = 1;
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
                        fprintf(stderr, "tcpcopy: option -%c require a string\n", 
                                optopt);
                        break;
                    case 'c':
                        fprintf(stderr, "tcpcopy: option -%c require a ip address or a sub net\n", 
                                optopt);
                        break;
#if (TC_OFFLINE)
                    case 'i':
#endif
                    case 'l':
                    case 'P':
                        fprintf(stderr, "tcpcopy: option -%c require a file name\n", 
                                optopt);
                        break;
#if (TC_PCAP)
                    case 'i':
                        fprintf(stderr, "tcpcopy: option -%c require a device name\n",
                                optopt);
                        break;
#endif
#if (TC_PCAP_SND)
                    case 'o':
                        fprintf(stderr, "tcpcopy: option -%c require a device name\n",
                                optopt);
                        break;
#endif
                    case 's':
                        fprintf(stderr, "tcpcopy: option -%c require an ip address list\n",
                                optopt);
                        break;
                    case 'n':
                    case 'f':
                    case 'C':
#if (TC_OFFLINE)
                    case 'a':
                    case 'I':
#endif
#if (TC_PCAP)
                    case 'B':
                    case 'S':
#endif
                    case 'm':
                    case 'M':
                    case 'D':
                    case 'U':
                    case 't':
                    case 'k':
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
output_for_debug()
{
    /* print out version info */
    tc_log_info(LOG_NOTICE, 0, "tcpcopy version:%s", VERSION);
    tc_log_info(LOG_NOTICE, 0, "tcpcopy internal version:%d", 
            INTERNAL_VERSION);

    /* print out target info */
    tc_log_info(LOG_NOTICE, 0, "target:%s", clt_settings.raw_tf);

    /* print out working mode info */
#if (TC_OFFLINE)
    tc_log_info(LOG_NOTICE, 0, "TC_OFFLINE mode");
#endif
#if (TC_PCAP)
    tc_log_info(LOG_NOTICE, 0, "TC_PCAP mode");
#endif
#if (TC_SINGLE)
    tc_log_info(LOG_NOTICE, 0, "TC_SINGLE mode");
#endif
#if (TC_UDP)
    tc_log_info(LOG_NOTICE, 0, "TC_UDP mode");
#endif
#if (TC_COMBINED)
    tc_log_info(LOG_NOTICE, 0, "TC_COMBINED mode");
#endif
#if (TC_PCAP_SND)
    tc_log_info(LOG_NOTICE, 0, "TC_PCAP_SND mode");
#endif
#if (TC_MILLION_SUPPORT)
    tc_log_info(LOG_NOTICE, 0, "TC_MILLION_SUPPORT mode");
#endif
#if (TC_PLUGIN)
    tc_log_info(LOG_NOTICE, 0, "TC_PLUGIN mode");
#endif
#if (TC_PAYLOAD)
    tc_log_info(LOG_NOTICE, 0, "TC_PAYLOAD is true");
#endif
#if (TC_HAVE_EPOLL)
    tc_log_info(LOG_NOTICE, 0, "epoll mode");
#endif
#if (TC_HAVE_PF_RING)
    tc_log_info(LOG_NOTICE, 0, "TC_HAVE_PF_RING is true");
#endif
#if (TC_DETECT_MEMORY)
    tc_log_info(LOG_NOTICE, 0, "TC_DETECT_MEMORY is true");
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
parse_target(transfer_map_t *ip_port, char *addr)
{
    char   *seq, *addr1, *addr2;

    if ((seq = strchr(addr, '-')) == NULL) {
        tc_log_info(LOG_WARN, 0, "target \"%s\" is invalid", addr);
        fprintf(stderr, "target \"%s\" is invalid\n", addr);
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

    if (ip_port->target_ip == LOCALHOST) {
        clt_settings.target_localhost = 1;
        tc_log_info(LOG_WARN, 0, "target host is 127.0.0.1");
    }

#if (TC_PCAP)
    if (clt_settings.user_filter == NULL && ip_port->online_ip == 0) {
        if (ip_port->online_port == ip_port->target_port) 
        {
            tc_log_info(LOG_WARN, 0, "captured port and target port are equal");
            tc_log_info(LOG_ERR, 0, 
                    "set pcap filter to capture online inbound packets");
            fprintf(stderr, "set -F argument to capture packets\n");
            return -1;
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
retr_target_addrs(char *raw_tf, transfer_maps_t *tf)
{
    int   i;
    char *p, *seq;

    if (raw_tf == NULL) {
        tc_log_info(LOG_ERR, 0, "it must have -x argument");
        fprintf(stderr, "no -x argument\n");
        return -1;
    }

    for (tf->num = 1, p = raw_tf; *p; p++) {
        if (*p == ',') {
            tf->num++;
        }
    }

    tf->map = tc_palloc(clt_settings.pool, tf->num * sizeof(transfer_map_t *));
    if (tf->map == NULL) {
        return -1;
    }
    tc_memzero(tf->map, tf->num * sizeof(transfer_map_t *));

    for (i = 0; i < tf->num; i++) {
        tf->map[i] = tc_palloc(clt_settings.pool, sizeof(transfer_map_t));
        if (tf->map[i] == NULL) {
            return -1;
        }
        tc_memzero(tf->map[i], sizeof(transfer_map_t));
    }

    p = raw_tf;
    i = 0;
    for ( ;; ) {
        if ((seq = strchr(p, ',')) == NULL) {
            if (parse_target(tf->map[i++], p) == -1) {
                return -1;
            }
            break;
        } else {
            *seq = '\0';
            if (parse_target(tf->map[i++], p) == -1) {
                return -1;
            }

            *seq = ',';
            p = seq + 1;
        }
    }

    return 0;
}


static int retrieve_real_servers() 
{
    int          count = 0;
    char        *split, *p, *seq, *port_s;
    uint16_t     port;
    uint32_t     ip;

    p = clt_settings.raw_rs_list;

    while (true) {
        split = strchr(p, ',');
        if (split != NULL) {
            *split = '\0';
        }

        if ((seq = strchr(p, ':')) == NULL) {
            tc_log_info(LOG_NOTICE, 0, "set only ip for tcpcopy");
            port  = 0;
            ip = inet_addr(p);
        } else {
            port_s = seq + 1;
            *seq = '\0';
            ip = inet_addr(p);
            port = atoi(port_s);
            *seq = ':';
        }

        if (split != NULL) {
            *split = ',';
        }

        clt_settings.real_servers.conns[count].ip = ip;
        clt_settings.real_servers.conns[count++].port = port;

        if (count == MAX_REAL_SERVERS) {
            tc_log_info(LOG_WARN, 0, "reach the limit for real servers");
            break;
        }

        if (split == NULL) {
            break;
        } else {
            p = split + 1;
        }

    }

    clt_settings.real_servers.num = count;

    return 1;

}


#if (TC_PCAP)
static void 
extract_filter()
{
    int              i, cnt = 0;
    char            *pt;
    transfer_map_t  *pair, **map;

    pt = clt_settings.filter;
#if (TC_UDP)
    strcpy(pt, "udp and (");
#else
    strcpy(pt, "tcp and (");
#endif
    pt = pt + strlen(pt);
 
    map = clt_settings.transfer.map;

    for (i = 0; i < clt_settings.transfer.num; i++) {
        pair = map[i];
        if (pair->online_ip > 0 || pair->online_port > 0) {
            if (cnt >= MAX_FILTER_ITEMS) {
                break;
            }
            cnt++; 
            if (i > 0) {
                strcpy(pt, " or ");
            }
            pt = pt + strlen(pt);
            pt = construct_filter(DST_DIRECTION, pair->online_ip, 
                    pair->online_port, pt);
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


static bool 
check_client_ip_valid(uint32_t ip)
{
    int   i;

    for (i = 0; i < clt_settings.transfer.num; i++) {
        if (ip == clt_settings.transfer.map[i]->target_ip) {
            return false;
        }
    }

    return true;
}


static int 
retrieve_clt_tf_ips() 
{
    int          count = 0, len, i;
    char        *split, *p, tmp_ip[32], *q; 
    uint32_t     ip; 

    p = clt_settings.raw_clt_tf_ip;

    while (true) {
        split = strchr(p, ',');
        if (split != NULL) {
            *split = '\0';
        }   

        len = strlen(p);
        if (len == 0) {
            tc_log_info(LOG_WARN, 0, "ip is empty");
            break;
        }   

        if (p[len - 1] == 'x') {
            strncpy(tmp_ip, p, len -1);
            q = tmp_ip + len - 1;
            for (i = 1; i < 255; i++) {
                sprintf(q, "%d", i);
                ip = inet_addr(tmp_ip);
                tc_log_debug1(LOG_DEBUG, 0, "clt ip addr:%s", tmp_ip);
                if (check_client_ip_valid(ip)) {
                    clt_settings.clt_tf_ip[count++] = ip; 
                    if (count == M_IP_NUM) {
                        tc_log_info(LOG_WARN, 0, "reach limit for clt ips");
                        break;
                    }
                }
            }
        } else if (p[len - 1] == '*') {
            tc_log_info(LOG_ERR, 0, "%s not valid, use x instead of *", p);
            fprintf(stderr, "%s not valid, use x instead of *\n", p);
        } else {
            ip = inet_addr(p);
            if (check_client_ip_valid(ip)) {
                clt_settings.clt_tf_ip[count++] = ip; 
                if (count == M_IP_NUM) {
                    tc_log_info(LOG_WARN, 0, "reach limit for clt ips");
                    break;
                }   
            }
        }

        if (split != NULL) {
            *split = ',';
        }   

        if (count == M_IP_NUM) {
            tc_log_info(LOG_WARN, 0, "reach the limit for clt_tf_ip");
            break;
        }   

        if (split == NULL) {
            break;
        } else {
            p = split + 1;
        }   

    }   

    clt_settings.clt_tf_ip_num = count;

    return 1;
}


static void 
read_conf_file()
{
#if (TC_PLUGIN)
    tc_buf_t         b;
    tc_conf_file_t   conf_file;

    tc_memzero(&conf_file, sizeof(tc_conf_file_t));
    tc_memzero(&b, sizeof(tc_buf_t));

    clt_settings.cf = tc_palloc(clt_settings.pool, sizeof(tc_conf_t));

    conf_file.file.fd = -1;
    conf_file.line = 0;

    clt_settings.cf->conf_file = &conf_file;
    clt_settings.cf->pool = clt_settings.pool;

    clt_settings.cf->args = tc_array_create(clt_settings.pool, 10, 
            sizeof(tc_str_t));

    if (clt_settings.conf_file == NULL) {
        clt_settings.conf_file = TC_CONF_PATH;
    }

    clt_settings.conf_file = tc_conf_full_name(clt_settings.pool, TC_PREFIX, 
            clt_settings.conf_file);

    tc_conf_parse(clt_settings.plugin, clt_settings.pool, clt_settings.cf,
            clt_settings.conf_file);

    clt_settings.cf->conf_file = NULL;
#endif
}


static int
set_details()
{
    int            mtu_list[] = {576, 1492, 1500, 0};
    int            i, len, index, offset, rand_port;
    unsigned int   seed;
    unsigned char  value;
    struct timeval tp;

    for (i = tc_pagesize; i >>= 1; tc_pagesize_shift++) { /* void */ }

    /* generate a random port number for avoiding port conflicts */
    gettimeofday(&tp, NULL);
    seed = tp.tv_usec;
    rand_port = (int) ((rand_r(&seed) / (RAND_MAX + 1.0)) * 512);
    clt_settings.rand_port_shifted = rand_port;

    if (clt_settings.sess_timeout < 0) {
        clt_settings.sess_timeout = DEFAULT_SESS_TIMEOUT;
    }
    tc_log_info(LOG_NOTICE, 0, "session timeout:%d", 
            clt_settings.sess_timeout);

    if (clt_settings.sess_keepalive_timeout <= 0) {
        clt_settings.sess_keepalive_timeout = clt_settings.sess_timeout + 
            SESS_KEEPLIVE_ADD;
    }
    tc_log_info(LOG_NOTICE, 0, "keepalive timeout:%d", 
            clt_settings.sess_keepalive_timeout);

#if (!TC_UDP)
    if (clt_settings.s_pool_size == 0) {
        clt_settings.s_pool_size = TC_DEFAULT_UPOOL_SIZE;
    }
    tc_log_info(LOG_NOTICE, 0, "min sess pool size:%d", TC_MIN_SESS_POOL_SIZE);
    tc_log_info(LOG_NOTICE, 0, "sess pool size:%d", clt_settings.s_pool_size);

    if (clt_settings.s_pool_size < TC_MIN_SESS_POOL_SIZE) {
        tc_log_info(LOG_NOTICE, 0, "sess pool size is too small");
    }
#endif

    if (clt_settings.replica_num > 1) {
        tc_log_info(LOG_NOTICE, 0, "repl num:%d", clt_settings.replica_num);
    }
    
    if (clt_settings.gradully) {
        tc_log_info(LOG_NOTICE, 0, "gradully replay");
    }

    /* set the ip port pair mapping according to settings */
    if (retr_target_addrs(clt_settings.raw_tf, &clt_settings.transfer) == -1) {
        return -1;
    }

    if (clt_settings.raw_clt_tf_ip != NULL) {
        /* print out raw_clt_tf_ip */
        tc_log_info(LOG_NOTICE, 0, "raw_clt_tf_ip:%s", 
                clt_settings.raw_clt_tf_ip);
        retrieve_clt_tf_ips();
    }

    if (clt_settings.percentage > 99) {
        clt_settings.percentage = 0;
    }

#if (!TC_UDP)
    if (sizeof(tc_sess_t) > TC_UPOOL_MAXV) {
        tc_log_info(LOG_NOTICE, 0, "TC_UPOOL_MAXV is too small");
    }
#endif

    if (clt_settings.par_conns <= 0) {
        clt_settings.par_conns = 1;
    } else if (clt_settings.par_conns > MAX_CONN_NUM) {
        clt_settings.par_conns = MAX_CONN_NUM;
    }
    tc_log_info(LOG_NOTICE, 0, "parallel connections per target:%d",
            clt_settings.par_conns);

    len = sizeof(mtu_list) / sizeof(int) - 1;
    for (i = 0; i < len; i++) {
        if (mtu_list[i] == clt_settings.mtu) {
            break;
        }
    }
    if (i == len) {
        mtu_list[len++] = clt_settings.mtu;
    }
    for (i = 0; i < len; i++) {
        index = mtu_list[i] >> 3;
        offset = mtu_list[i] - (index << 3);
        value = clt_settings.candidate_mtu[index];
        value = value | (1 << offset);
        clt_settings.candidate_mtu[index] = value;
    }

#if (TC_OFFLINE)
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

#if (TC_PCAP_SND)
    if (clt_settings.output_if_name != NULL) {
        tc_log_info(LOG_NOTICE, 0, "output device:%s", 
                clt_settings.output_if_name);
    } else {
        tc_log_info(LOG_ERR, 0, "no -o argument");
        fprintf(stderr, "no -o argument\n");
        return -1;
    }
#endif

#if (TC_PCAP)
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

    if (clt_settings.snaplen > PCAP_RCV_BUF_SIZE) {
        clt_settings.snaplen = PCAP_RCV_BUF_SIZE;
    }
#endif

    /* retrieve real server ip addresses  */
    if (clt_settings.raw_rs_list != NULL) {
        tc_log_info(LOG_NOTICE, 0, "s parameter:%s", 
                clt_settings.raw_rs_list);
        retrieve_real_servers();
    } else {
        tc_log_info(LOG_WARN, 0, "no -s parameter(intercept addresses)");
        fprintf(stderr, "tcpcopy needs -s paramter(intercept addresses)\n");
        return -1;
    }

#if (TC_PLUGIN)
    /* support only one additional module*/
    clt_settings.plugin = tc_modules[0];
#endif

    read_conf_file();

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
    clt_settings.sess_keepalive_timeout = 0;
    clt_settings.par_conns = 2;
    clt_settings.sess_timeout = DEFAULT_SESS_TIMEOUT;
    clt_settings.s_pool_size = TC_DEFAULT_UPOOL_SIZE;
    
#if (TC_PCAP)
    clt_settings.snaplen = PCAP_RCV_BUF_SIZE;
    clt_settings.buffer_size = TC_PCAP_BUF_SIZE;
#endif
#if (TC_PCAP_SND)
    clt_settings.output_if_name = NULL;
#endif

    tc_pagesize = getpagesize();
    tc_cacheline_size = TC_CPU_CACHE_LINE; 

    tc_raw_socket_out = TC_INVALID_SOCK;
}


/*
 * main entry point
 */
int
main(int argc, char **argv)
{
    int ret, is_continue = 1;

    settings_init();

#if (TC_SIGACTION)
    if (set_signal_handler(signals) == -1) {
        return -1;
    }
#else
    signal(SIGINT,  tcp_copy_over);
    signal(SIGPIPE, tcp_copy_over);
    signal(SIGHUP,  tcp_copy_over);
    signal(SIGTERM, tcp_copy_over);
#endif

    tc_time_init();

    if (read_args(argc, argv) == -1) {
        return -1;
    }
    
    if (tc_log_init(clt_settings.log_path) == -1) {
        return -1;
    }

    clt_settings.pool = tc_create_pool(TC_DEFAULT_POOL_SIZE, 0, 0);

    if (clt_settings.pool == NULL) {
        return -1;
    }

    /* output debug info */
    output_for_debug();

    /* set details for running */
    if (set_details() == -1) {
        return -1;
    }

#if (TC_DIGEST)
    tc_init_digests(); 
    if (!tc_init_sha1()) {
        return -1;
    }
#endif

    tc_event_timer_init();

    ret = tc_event_loop_init(&event_loop, MAX_FD_NUM);
    if (ret == TC_EVENT_ERROR) {
        tc_log_info(LOG_ERR, 0, "event loop init failed");
        is_continue = 0;
    } 

    if (is_continue) {
        ret = tcp_copy_init(&event_loop);
        if (ret == TC_ERR) {
            is_continue = 0;
        }   
    }

    if (is_continue) {
        /* run now */
        tc_event_proc_cycle(&event_loop);
    }

    tcp_copy_release_resources();

    return 0;
}


