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


typedef struct xcopy_srv_settings {
#if (!INTERCEPT_ADVANCED)
    char                *raw_ip_list;    /* raw ip list */
#endif
    char                *pid_file;       /* pid file */
    char                *binded_ip;      /* binded ip for security */
    char                *log_path;       /* error log path */

#if (INTERCEPT_NFQUEUE)   
    struct nfq_handle   *nfq_handler;    /* NFQUEUE library handler */
    struct nfq_q_handle *nfq_q_handler;  /* NFQUEUE queue handler */
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

    int                  timeout;
    int                  router_fd;
    size_t               hash_size;      /* hash size for kinds of table */
    uint16_t             port;           /* TCP port number to listen on */
    unsigned int         do_daemonize:1; /* daemon flag */
    passed_ip_addr_t     passed_ips;     /* passed ip list */
}xcopy_srv_settings;

extern xcopy_srv_settings srv_settings;

#include <tc_util.h>
#include <tc_combine.h>
#include <tc_delay.h>
#include <tc_interception.h>
#include <tc_router.h>

#endif /* INTERCEPT_INCLUDED */
