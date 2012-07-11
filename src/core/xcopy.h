#ifndef  _XCOPY_H_INC
#define  _XCOPY_H_INC

#define VERSION "0.5.0"

/* Set nonzero for debug */
#define DEBUG_TCPCOPY      0

/* Set nonzero for mysql skip-grant-table mode */
#define TCPCOPY_MYSQL_SKIP 0
/* Set nonzero for mysql normal mode */
#define TCPCOPY_MYSQL_NO_SKIP 0

/* 
 * If you define TCPCOPY_MYSQL_SKIP nonzero,
 * then tcpcopy works only for mysql which sets
 * skip-grant-tables
 */
#if(TCPCOPY_MYSQL_SKIP)
#define TCPCOPY_MYSQL_BASIC 1
#endif

/* 
 * If you define TCPCOPY_MYSQL_NO_SKIP nonzero,
 * then tcpcopy works only for mysql without setting 
 * skip-grant-tables
 */
#if(TCPCOPY_MYSQL_NO_SKIP)

#ifndef TCPCOPY_MYSQL_BASIC
#define TCPCOPY_MYSQL_BASIC 1
#endif

#define TCPCOPY_MYSQL_ADVANCED 1

#endif

/* Set raw socket receiving buffer size */
#define RECV_BUF_SIZE 65536
/* Default mtu for output raw socket */
#define DEFAULT_MTU   1500
/* Default listening port for intercept program */
#define SERVER_PORT   36524


#define DEFAULT_TIMEOUT 120
#define CHECK_INTERVAL  15
#define DEFAULT_SESSION_TIMEOUT 60

/* Max fd number for select */
#define MAX_FD_NUM    1024
#define MAX_FD_VALUE  (MAX_FD_NUM-1)

#define MAX_ALLOWED_IP_NUM 32

/* Constants for netlink protocol */
#define FIREWALL_GROUP  0


/* In defence of occuping too much memory */
#define MAX_MEMORY_SIZE 524288

/* Log constants */
#define LOG_STDERR            0
#define LOG_EMERG             1
#define LOG_ALERT             2
#define LOG_CRIT              3
#define LOG_ERR               4
#define LOG_WARN              5
#define LOG_NOTICE            6
#define LOG_INFO              7
#define LOG_DEBUG             8

/* The route flags */
#define  CLIENT_ADD   1
#define  CLIENT_DEL   2

/* Where is the packet from (source flag) */
#define UNKNOWN 0
#define REMOTE  1
#define LOCAL   2

/* Session constants from the client perspective */
#define SESS_CREATE    0
#define SESS_KEEPALIVE 1  /* Online is active while backend is closed */
#define SESS_REUSE     2  /* When in ab test*/

/* The results of operation*/
#define SUCCESS   0
#define FAILURE  -1

#define DISP_STOP      1
#define DISP_CONTINUE  0

/* The result of obsolete checking*/
#define OBSOLETE 1
#define CANDIDATE_OBSOLETE -1
#define NOT_YET_OBSOLETE 0

/* Mysql constants */
#if (TCPCOPY_MYSQL_BASIC)
#define COM_STMT_PREPARE 22
#define COM_QUERY 3
#endif

#if (TCPCOPY_MYSQL_ADVANCED) 
#define SEED_323_LENGTH  8
#define SCRAMBLE_LENGTH  20
#define SHA1_HASH_SIZE   20
#define MAX_PASSWORD_LEN 256
#define MAX_PAYLOAD_LEN  128
#endif

/* Bool constants*/
#if HAVE_STDBOOL_H
#include <stdbool.h>
#else
#define bool char
#define false 0
#define true 1
#endif 

enum session_status{
    CLOSED       = 0,
    SYN_SENT     = 1,
    SYN_CONFIRM  = 2,
    SEND_REQUEST = 4,
    RECV_RESP    = 8,
    SERVER_FIN   = 16,
    CLIENT_FIN   =32
};

enum packet_classification{
    CLIENT_FLAG,
    BACKEND_FLAG,
    FAKED_CLIENT_FLAG,
    TO_BAKEND_FLAG,
    UNKNOWN_FLAG
};

#include <limits.h>
#include <asm/types.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netlink.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv4/ip_queue.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>

typedef struct ip_port_pair_mapping_s
{
    /* Online ip from the client perspective */
    uint32_t online_ip;
    uint32_t target_ip;
    uint16_t online_port;
    uint16_t target_port;
}ip_port_pair_mapping_t;

typedef struct ip_port_pair_mappings_s
{
    ip_port_pair_mapping_t **mappings;
    int num;
}ip_port_pair_mappings_t;

typedef struct passed_ip_addr_s{
    /* It allows 32 ip addresses passed through server firewall */
    uint32_t ips[MAX_ALLOWED_IP_NUM];
    int num;
}passed_ip_addr_t;

/* For tcpcopy client */
typedef struct xcopy_clt_settings {
    /* Replicated number of each request */
    unsigned int  replica_num:10;
    /* Port shift factor */
    unsigned int  factor:8;
    /* MTU sent to backend */
    unsigned int  mtu:16;
    /* Daemon flag */
    unsigned int do_daemonize:1;
    /* Max memory size allowed for tcpcopy client(max size 2G) */
    unsigned int max_rss:21;
    /* 
     * Max value for session timeout
     * If it reaches this value, the session will be removed 
     */
    unsigned int session_timeout:16;
    /* Online_ip online_port target_ip target_port string */
    char *raw_transfer;
    /* Pid file */
    char *pid_file;
    /* Error log path */
    char *log_path;
    /* Random port shifted */
    uint16_t   rand_port_shifted;
    /* Server listening port */
    uint16_t   srv_port;
    /* Ip address from localhost to (localhost transfered ip) */
    uint32_t   lo_tf_ip;
#ifdef TCPCOPY_MYSQL_ADVANCED
    /* User password string for mysql */
    char *user_pwd;
#endif
    /* Transfered online_ip online_port target_ip target_port */
    ip_port_pair_mappings_t transfer;
}xcopy_clt_settings;

/* For intercept */
typedef struct xcopy_srv_settings {
    /* Raw ip list */
    char *raw_ip_list;
    /* Pid file */
    char *pid_file;
    /* Binded ip for security */
    char *binded_ip;
    /* Error log path */
    char *log_path;
    /* Hash size for kinds of table */
    size_t hash_size;
    /* TCP port number to listen on */
    uint16_t port;
    /* Daemon flag */
    unsigned int do_daemonize:1;
    /* Passed ip list */
    passed_ip_addr_t passed_ips;
}xcopy_srv_settings;

/* Global variables*/
/* For tcpcopy client*/
extern xcopy_clt_settings clt_settings;
/* For tcpcopy server(intercept program) */
extern xcopy_srv_settings srv_settings;

/* Global log level */
extern int g_log_level;

/* Global functions */
void strace_pack(int level, int flag, struct iphdr *ip_header,
        struct tcphdr *tcp_header);
int daemonize();

void log_info(int level, const char *fmt, ...);

#endif   /* ----- #ifndef _XCOPY_H_INC ----- */

