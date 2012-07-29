#ifndef  _XCOPY_H_INC
#define  _XCOPY_H_INC

#include "config.h"

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
#include <sys/syscall.h>
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

/* The route flags */
#define  CLIENT_ADD   1
#define  CLIENT_DEL   2

/* Where is the packet from (source flag) */
#define UNKNOWN 0
#define REMOTE  1
#define LOCAL   2

#define CHECK_DEST 1
#define CHECK_SRC  2

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
#if (HAVE_STDBOOL_H)
#include <stdbool.h>
#else
#define bool char
#define false 0
#define true 1
#endif /* HAVE_STDBOOL_H */ 

enum session_status{
    CLOSED       = 0,
    SYN_SENT     = 1,
    SYN_CONFIRM  = 2,
    SEND_REQ     = 4,
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

#if (TCPCOPY_OFFLINE)
#define ETHER_ADDR_LEN 0x6

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100  /* IEEE 802.1Q VLAN tagging */
#endif

#define CISCO_HDLC_LEN 4
#define SLL_HDR_LEN 16

/*  
 *  Ethernet II header
 *  Static header size: 14 bytes          
 */ 
struct ethernet_hdr {
    uint8_t ether_dhost[ETHER_ADDR_LEN];
    uint8_t ether_shost[ETHER_ADDR_LEN];
    uint16_t ether_type;                 
};
#endif /* TCPCOPY_OFFLINE */

/* Global functions */
void strace_pack(int level, int flag, struct iphdr *ip_header,
        struct tcphdr *tcp_header);
int daemonize();


typedef struct cpy_event_loop_s cpy_event_loop_t;
typedef struct cpy_event_s      cpy_event_t;

#include "link_list.h"
#include "hash.h"
#include "tc_time.h"

#include "../event/tc_event.h"
#include "../event/tc_select_module.h"
#include "../event/select_server.h"
#include "../event/select_server_wrapper.h"
#include "../log/log.h"
#include "../communication/msg.h"

#endif /* _XCOPY_H_INC */

