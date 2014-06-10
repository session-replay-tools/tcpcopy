#ifndef INTERCEPT_INCLUDED
#define INTERCEPT_INCLUDED

typedef struct passed_ip_addr_s {
    /* It allows 32 ip addresses passed through server firewall */
    uint32_t    ips[MAX_ALLOWED_IP_NUM];
    int         num;
} passed_ip_addr_t;

#if (INTERCEPT_ADVANCED)
typedef struct ip_port_pair_t{
    uint32_t ip;
    uint16_t port;
}ip_port_pair_t;


typedef struct ip_port_pairs_t{
    int              num;
    ip_port_pair_t **mappings;
}ip_port_pairs_t;

#endif

#if (INTERCEPT_COMBINED)
typedef struct aggregation_s{
    time_t         access_time;
    long           access_msec;
    unsigned char *cur_write;
    uint16_t       num;
    unsigned char  aggr_resp[COMB_LENGTH];
}aggregation_t;
#endif

typedef struct tunnel_basic_t{
    tc_event_t     *ev;
#if (INTERCEPT_COMBINED)
    aggregation_t  *combined;
#endif
    unsigned int    fd_valid:1;
    unsigned int    first_in:1;
    unsigned int    clt_msg_size:16; 
}tunnel_basic_t;

typedef struct xcopy_srv_settings {
#if (!INTERCEPT_ADVANCED)
    char                *raw_ip_list;    /* raw ip list */
#endif
    char                *pid_file;       /* pid file */
    char                *bound_ip;       /* bound ip for security */
    char                *log_path;       /* error log path */

#if (INTERCEPT_NFQUEUE)   
    struct nfq_handle   *nfq_handler;    /* NFQUEUE library handler */
    struct nfq_q_handle *nfq_q_handler;  /* NFQUEUE queue handler */
    int                  max_queue_len;
#endif

#if (INTERCEPT_ADVANCED)
#if (TCPCOPY_PCAP)
    char                *raw_device;
    devices_t            devices;
    char                 filter[MAX_FILTER_LENGH];
    char                *user_filter;
#endif
    char                *raw_targets;
    ip_port_pairs_t      targets;

#endif

    bool                 old;            /* old tcpcopy flag */
    size_t               hash_size;      /* hash size for kinds of table */
    uint16_t             port;           /* TCP port number to listen on */
    unsigned int         do_daemonize:1; /* daemon flag */

#if (INTERCEPT_COMBINED)
    unsigned int         cur_combined_num:5;
#endif
#if (!INTERCEPT_ADVANCED)
    passed_ip_addr_t     passed_ips;     /* passed ip list */
#endif
    tunnel_basic_t       tunnel[MAX_FD_NUM];
    int                  max_fd;
#if (TCPCOPY_SINGLE)
    time_t               accepted_tunnel_time;
    bool                 conn_protected;
    int                  s_fd_num;
    int                  s_router_fds[MAX_FD_NUM];
#endif

}xcopy_srv_settings;

extern xcopy_srv_settings srv_settings;

#include <tc_util.h>
#include <tc_combine.h>
#include <tc_delay.h>
#include <tc_server_common.h>
#include <tc_interception.h>
#include <tc_router.h>

#endif /* INTERCEPT_INCLUDED */
