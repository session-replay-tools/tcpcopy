#ifndef TCPCOPY_INCLUDED
#define TCPCOPY_INCLUDED 


#define LOCALHOST (inet_addr("127.0.0.1"))

typedef struct {
    /* online ip from the client perspective */
    uint32_t      online_ip;
    uint32_t      target_ip;
    uint16_t      online_port;
    uint16_t      target_port;
    unsigned char src_mac[ETHER_ADDR_LEN];
    unsigned char dst_mac[ETHER_ADDR_LEN];
} ip_port_pair_mapping_t;


typedef struct {
    int                      num;
    ip_port_pair_mapping_t **mappings;
} ip_port_pair_mappings_t;

#if (TCPCOPY_DR)
typedef struct real_ip_addr_s {
    int           num;
    int           active_num;
    short         active[MAX_REAL_SERVERS];
    uint32_t      ips[MAX_REAL_SERVERS];
    uint16_t      ports[MAX_REAL_SERVERS];
    connections_t connections[MAX_REAL_SERVERS];
} real_ip_addr_t;
#endif

typedef struct xcopy_clt_settings {
    unsigned int  replica_num:10;       /* replicated number of each request */
    unsigned int  factor:8;             /* port shift factor */
    unsigned int  mtu:16;               /* MTU sent to backend */
    unsigned int  par_connections:8;    /* parallel connections */
    unsigned int  mss:16;               /* MSS sent to backend */
    unsigned int  do_daemonize:1;       /* daemon flag */
#if (TCPCOPY_DR)
    unsigned int  lonely:1;             /* Lonely for tcpcopy */
#endif
    unsigned int  max_rss:21;           /* max memory allowed for tcpcopy */

    unsigned int  percentage:7;         /* percentage of the full flow that 
                                           will be tranfered to the backend */
    unsigned int  target_localhost:1;
    int           session_timeout;   /* max value for session timeout.
                                           If reaching this value, the session
                                           will be removed */
    int           session_keepalive_timeout;  

    char         *raw_transfer;         /* online_ip online_port target_ip
                                           target_port string */

    char         *pid_file;             /* pid file */
    char         *log_path;             /* error log path */
#if (TCPCOPY_OFFLINE)
    int           accelerated_times;    /* accelerated times */
    char         *pcap_file;            /* pcap file */
    long          pcap_time;
    pcap_t       *pcap;
    uint64_t      interval;             /* accelerated times */
#endif
#if (TCPCOPY_PCAP_SEND)
    char         *output_if_name;
#endif
#if (TCPCOPY_PCAP)
    int           buffer_size;
    char         *raw_device;
    devices_t     devices;
    char          filter[MAX_FILTER_LENGH];
    char         *user_filter;
#endif
    uint16_t      rand_port_shifted;   /* random port shifted */
    uint16_t      srv_port;            /* server listening port */
    char         *raw_clt_tf_ip;        
    uint16_t      clt_tf_ip_num;       
    uint32_t      clt_tf_ip[M_IP_NUM]; /* ip address from clt to target ip */
#ifdef TCPCOPY_MYSQL_ADVANCED
    char         *user_pwd;            /* user password string for mysql */
#endif
#if (TCPCOPY_DR)
    char         *raw_rs_list;         /* raw real server list */
    real_ip_addr_t  real_servers;      /* the intercept servers running intercept */
#endif
    ip_port_pair_mappings_t transfer;  /* transfered online_ip online_port
                                           target_ip target_port */
    int           multiplex_io;
    int           sig;  
    uint64_t      tries;  
    tc_event_t   *ev[MAX_FD_NUM];
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
