#ifndef  XCOPY_H_INCLUDED
#define  XCOPY_H_INCLUDED

#include "config.h"

#include <limits.h>
#include <asm/types.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>
#if (TCPCOPY_UDP)
#include <netinet/udp.h>
#endif
#if (!INTERCEPT_ADVANCED)
#if (!INTERCEPT_NFQUEUE)
#include <linux/netlink.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv4/ip_queue.h>
#else
#include <linux/netfilter.h> 
#include <libnetfilter_queue/libnetfilter_queue.h>
#endif
#endif
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
#if (TCPCOPY_OFFLINE || TCPCOPY_PCAP || TCPCOPY_PCAP_SEND)
#include <pcap.h>
#endif
#if (TCPCOPY_MYSQL_NO_SKIP)
#include <openssl/evp.h>
#endif

#if (INTERCEPT_ADVANCED)
#define TCPCOPY_DR 1
#endif

#if (TCPCOPY_OFFLINE)
#undef TCPCOPY_PCAP
#endif

/* 
 * If you define TCPCOPY_MYSQL_SKIP nonzero,
 * tcpcopy works only for mysql which sets
 * skip-grant-tables
 */
#if (TCPCOPY_MYSQL_SKIP)
#define TCPCOPY_MYSQL_BASIC 1
#endif

/* 
 * If you define TCPCOPY_MYSQL_NO_SKIP nonzero,
 * tcpcopy works only for mysql without setting 
 * skip-grant-tables
 */
#if (TCPCOPY_MYSQL_NO_SKIP)

#ifndef TCPCOPY_MYSQL_BASIC
#define TCPCOPY_MYSQL_BASIC 1
#endif

#define TCPCOPY_DIGEST 1
#define TCPCOPY_MYSQL_ADVANCED 1
#define MYSQL_SHA1 "sha1"

#endif

#define INTERNAL_EVOLUTION_VERSION 5 
#if (INTERCEPT_ADVANCED)
#define INTERNAL_VERSION (32768 + INTERNAL_EVOLUTION_VERSION)
#else
#define INTERNAL_VERSION INTERNAL_EVOLUTION_VERSION
#endif

#define COPY_FROM_IP_LAYER 0
#define COPY_FROM_LINK_LAYER 1

#define ETHER_ADDR_LEN 0x6

/* raw socket receiving buffer size */
#define IP_RECV_BUF_SIZE 65536
#define PCAP_RECV_BUF_SIZE 65535
#define MAX_FILTER_LENGH 4096 
#define M_IP_NUM 256

/* max payload size per continuous send */
#define MAX_SIZE_PER_CONTINUOUS_SEND 32768 

#define TCPCOPY_PCAP_BUF_SIZE 16777216
#define INTERCEPT_PCAP_BUF_SIZE 4194304

/* default mtu for output raw socket */
#define DEFAULT_MTU   1500
#define DEFAULT_MSS   1460
/* default listening port for intercept */
#define SERVER_PORT   36524


#if (TCPCOPY_DR)
#define MAX_REAL_SERVERS 256
#endif

#if (TCPCOPY_MYSQL_BASIC)
#define DEFAULT_TIMEOUT 1200
#else
#define DEFAULT_TIMEOUT 120
#endif

#define CHECK_INTERVAL  1
#define OUTPUT_INTERVAL  30000
#define RETRY_INTERVAL  12000
#define DEFAULT_SESSION_TIMEOUT 120
#define OFFLINE_TAIL_TIMEOUT 120 

#define MAX_WRITE_TRIES 1024
#define MAX_READ_LOG_TRIES 65536

#if (TCPCOPY_MILLION_SUPPORT)
#define SESS_KEEPLIVE_ADD 120
#else
#define SESS_KEEPLIVE_ADD 1200
#endif

#define MAX_UNSEND_THRESHOLD 32768

#define TIMEOUT_CHANGE_THRESHOLD 4096

/* max fd number for select */
#define MAX_FD_NUM    1024
#define MAX_FD_VALUE  (MAX_FD_NUM-1)
#define MAX_CONNECTION_NUM 16
#define MAX_SINGLE_CONNECTION_NUM 256

#if (TCPCOPY_SINGLE)
#undef INTERCEPT_MILLION_SUPPORT
#endif

#if (!INTERCEPT_MILLION_SUPPORT)
#define ROUTE_SLOTS 65536
#define ROUTE_ARRAY_SIZE 15
#define ROUTE_ARRAY_DEPTH 4
#define ROUTE_KEY_HIGH_MASK 0xFFFF0000
#define ROUTE_KEY_LOW_MASK 0x0000FFFF
#define ROUTE_KEY_SHIFT 16
#else
#define ROUTE_SLOTS 1048576
#define ROUTE_ARRAY_SIZE 31
#define ROUTE_ARRAY_DEPTH 5
#define ROUTE_KEY_HIGH_MASK 0xFFFFF000
#define ROUTE_KEY_LOW_MASK  0x00000FFF
#define ROUTE_KEY_SHIFT 12
#endif

#define ROUTE_ARRAY_ACTIVE_NUM_RANGE (ROUTE_ARRAY_SIZE + 1)

#if (INTERCEPT_COMBINED)
#if (TCPCOPY_MYSQL_ADVANCED) 
#define COMB_MAX_NUM 6
#else
#define COMB_MAX_NUM 16
#endif
#define COMB_LENGTH (COMB_MAX_NUM * MSG_SERVER_SIZE)
#define TIME_DRIVEN 1
#define NUM_DRIVEN 2
#endif

#define SRC_DIRECTION 0
#define DST_DIRECTION 1
#define MAX_FILTER_ITEMS 32
#define MAX_FILTER_PORTS 32
#define MAX_FILTER_IPS 32
#define MAX_DEVICE_NUM 32
#define MAX_DEVICE_NAME_LEN 32

#define MAX_ALLOWED_IP_NUM 32

/* constants for netlink protocol */
#define FIREWALL_GROUP  0

/* in defence of occuping too much memory */
#define MAX_MEMORY_SIZE 524288

/* route flags */
#define  CLIENT_ADD   1
#define  CLIENT_DEL   2

/* where is packet from (source flag) */
#define UNKNOWN 0
#define REMOTE  1
#define LOCAL   2

#define CHECK_DEST 1
#define CHECK_SRC  2

/* session constants from the client perspective */
#define SESS_CREATE    0
#define SESS_KEEPALIVE 1  /* online active while backend is closed */
#define SESS_REUSE     2  /* when in ab test */

#define DISP_STOP      1
#define DISP_CONTINUE  0

/* constants for tcp */
#define TCP_HEADER_DOFF_MIN_VALUE 5
#define TCP_HEADER_DOFF_MSS_VALUE 6
#define TCP_HEADER_DOFF_TS_VALUE 8
#define TCP_HEADER_DOFF_WS_TS_VALUE 9

/* results of obsolete checking */
#define OBSOLETE 1
#define CANDIDATE_OBSOLETE -1
#define NOT_YET_OBSOLETE 0

/* mysql constants */
#if (TCPCOPY_MYSQL_BASIC)
#define COM_STMT_PREPARE 22
#define COM_STMT_EXECUTE 23
#define COM_QUERY 3
#define MAX_SP_SIZE 1024
#endif

#if (TCPCOPY_MYSQL_ADVANCED) 
#define SEED_323_LENGTH  8
#define SCRAMBLE_LENGTH  20
#define SHA1_HASH_SIZE   20
#define MAX_PASSWORD_LEN 256
/* 
 * TODO
 * the auth_plugin_data field in Initial Handshake Packet 
 * can only carry 255 bytes max 
 */ 
#define MAX_PAYLOAD_LEN  128
#endif

#if (TCPCOPY_PAPER) 
#define RTT_INIT 0
#define RTT_FIRST_RECORED 1
#define RTT_CAL 2
#endif

typedef volatile sig_atomic_t tc_atomic_t;

typedef struct iphdr  tc_ip_header_t;
typedef struct tcphdr tc_tcp_header_t;
#if (TCPCOPY_UDP)
typedef struct udphdr tc_udp_header_t;
#endif

/* 
 * the 40 bytes available for TCP options 
 */
#define MAX_OPTION_LEN 40
#define TCPOPT_WSCALE 3

#define RESP_HEADER_SIZE (sizeof(tc_ip_header_t) + sizeof(tc_tcp_header_t) + MAX_OPTION_LEN)
#if (TCPCOPY_MYSQL_ADVANCED) 
#define RESP_MAX_USEFUL_SIZE (RESP_HEADER_SIZE + MAX_PAYLOAD_LEN)
#else
#define RESP_MAX_USEFUL_SIZE RESP_HEADER_SIZE
#endif

/* bool constants */
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
    RESERVED_CLIENT_FLAG,
    BACKEND_FLAG,
    FAKED_CLIENT_FLAG,
    TO_BAKEND_FLAG,
    UNKNOWN_FLAG
};

#define ETHER_ADDR_STR_LEN 17

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100  /* IEEE 802.1Q VLAN tagging */
#endif

#define CISCO_HDLC_LEN 4
#define SLL_HDR_LEN 16
#define ETHERNET_HDR_LEN (sizeof(struct ethernet_hdr))
#define DEFAULT_DEVICE     "any"

/*  
 *  Ethernet II header
 *  static header size: 14 bytes          
 */ 
struct ethernet_hdr {
    uint8_t  ether_dhost[ETHER_ADDR_LEN];
    uint8_t  ether_shost[ETHER_ADDR_LEN];
    uint16_t ether_type;                 
};

/* receiving buffer size for response */
#define CAPTURE_RESP_HEADER_MAX_LEN 120
#if (TCPCOPY_MYSQL_ADVANCED) 
#define CAPTURE_RESP_MAX_SIZE (CAPTURE_RESP_HEADER_MAX_LEN + MAX_PAYLOAD_LEN)
#else
#define CAPTURE_RESP_MAX_SIZE CAPTURE_RESP_HEADER_MAX_LEN
#endif
#if (TCPCOPY_PCAP)
#define RESP_RECV_BUF_SIZE (ETHERNET_HDR_LEN + CAPTURE_RESP_MAX_SIZE)
#else
#define RESP_RECV_BUF_SIZE (CAPTURE_RESP_MAX_SIZE)
#endif


#if (TCPCOPY_PCAP)
typedef struct device_s{
    char    name[MAX_DEVICE_NAME_LEN];
    pcap_t *pcap;
}device_t;

typedef struct devices_s{
    int       device_num;
    device_t  device[MAX_DEVICE_NUM];
}devices_t;
#endif

typedef struct connections_s{
    int index; 
    int num;
    int remained_num;
    int fds[MAX_CONNECTION_NUM];
}connections_t;

#if (TCPCOPY_OFFLINE)
#define TIMER_INTERVAL 1
#else
#define TIMER_INTERVAL 10
#endif

#if (INTERCEPT_COMBINED)
#define INTERCEPT_TIMER_INTERVAL 1
#else
#define INTERCEPT_TIMER_INTERVAL 100
#endif

/* global functions */
int daemonize();
static inline int before(uint32_t seq1, uint32_t seq2)
{
    return (int) ((uint32_t) (seq1-seq2)) < 0;
}

#define after(seq2, seq1) before(seq1, seq2)

#define TC_OK        0
#define TC_ERROR    -1
#define TC_ERR_EXIT  1

#define tc_cpymem(d, s, l) (((char *) memcpy(d, (void *) s, l)) + (l))
#define tc_memzero(d, l) (memset(d, 0, l))

#include <tc_link_list.h>
#include <tc_hash.h>
#include <tc_time.h>
#include <tc_signal.h>

#include <tc_event.h>
#include <tc_select_module.h>
#include <tc_log.h>
#include <tc_msg.h>
#include <tc_socket.h>
#if (TCPCOPY_DIGEST)
#include <tc_evp.h>
#endif


#endif /* XCOPY_H_INCLUDED */

