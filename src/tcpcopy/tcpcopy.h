#ifndef TCPCOPY_INCLUDED
#define TCPCOPY_INCLUDED 


#define localhost (inet_addr("127.0.0.1"))

typedef struct {
    /* online ip from the client perspective */
    uint32_t online_ip;
    uint32_t target_ip;
    uint16_t online_port;
    uint16_t target_port;
} ip_port_pair_mapping_t;


typedef struct {
    int                      num;
    ip_port_pair_mapping_t **mappings;
} ip_port_pair_mappings_t;

#if (TCPCOPY_PCAP)
typedef struct device_s{
    char    name[MAX_DEVICE_NAME_LEN];
    pcap_t *pcap;
}device_t;

typedef struct devices_s{
    int             device_num;
    device_t        device[MAX_DEVICE_NUM];
}devices_t;
#endif

#if (TCPCOPY_DR)
typedef struct real_ip_addr_s {
    uint32_t    ips[MAX_REAL_SERVERS];
    uint32_t    fds[MAX_REAL_SERVERS];
    short       active[MAX_REAL_SERVERS];
    int         num;
    int         active_num;
} real_ip_addr_t;
#endif

typedef struct xcopy_clt_settings {
    unsigned int  replica_num:10;       /* replicated number of each request */
    unsigned int  factor:8;             /* port shift factor */
    unsigned int  mtu:16;               /* MTU sent to backend */
    unsigned int  mss:16;               /* MSS sent to backend */
    unsigned int  do_daemonize:1;       /* daemon flag */
    unsigned int  max_rss:21;           /* max memory allowed for tcpcopy */

    unsigned int  percentage:7;         /* percentage of the full flow that 
                                           will be tranfered to the backend */
    unsigned int  session_timeout:16;   /* max value for session timeout.
                                           If reaching this value, the session
                                           will be removed */

    char         *raw_transfer;         /* online_ip online_port target_ip
                                           target_port string */

    char         *pid_file;             /* pid file */
    char         *log_path;             /* error log path */
#if (TCPCOPY_OFFLINE)
    char         *pcap_file;            /* pcap file */
    int           accelerated_times;    /* accelerated times */
    uint64_t      interval;             /* accelerated times */
#endif
#if (TCPCOPY_PCAP)
    char         *raw_device;
    devices_t     devices;
    char          filter[512];
#endif
#if (TCPCOPY_OFFLINE)
    pcap_t       *pcap;
    long          pcap_time;
#endif
    uint16_t      rand_port_shifted;    /* random port shifted */
    uint16_t      srv_port;             /* server listening port */
    uint32_t      lo_tf_ip;             /* ip address from localhost to
                                           (localhost transfered ip) */
#ifdef TCPCOPY_MYSQL_ADVANCED
    char             *user_pwd;         /* user password string for mysql */
#endif
#if (TCPCOPY_DR)
    char             *raw_rs_ip_list;   /* raw ip list */
    real_ip_addr_t    real_servers;     /* the real servers behind lvs */
#endif
    ip_port_pair_mappings_t transfer;   /* transfered online_ip online_port
                                           target_ip target_port */
    int           multiplex_io;
    int           sig;  
} xcopy_clt_settings;


extern int tc_raw_socket_out;
extern tc_event_loop_t event_loop;
extern xcopy_clt_settings clt_settings;

#include <tc_util.h>

#ifdef TCPCOPY_MYSQL_ADVANCED
#include <pairs.h>
#include <protocol.h>
#endif

#include <tc_manager.h>
#include <tc_session.h>
#include <tc_message_module.h>
#include <tc_packets_module.h>

#endif /* TCPCOPY_INCLUDED */
