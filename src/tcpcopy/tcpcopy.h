#ifndef TC_INCLUDED
#define TC_INCLUDED 
#include <xcopy.h>

#define LOCALHOST (inet_addr("127.0.0.1"))

typedef struct {
    /* online ip from the client perspective */
    uint32_t      online_ip;
    uint32_t      target_ip;
    uint16_t      online_port;
    uint16_t      target_port;
    unsigned char src_mac[ETHER_ADDR_LEN];
    unsigned char dst_mac[ETHER_ADDR_LEN];
} transfer_map_t;


typedef struct {
    int              num;
    transfer_map_t **map;
} transfer_maps_t;

typedef struct real_ip_addr_s {
    int       num;
    int       active_num;
    conns_t   conns[MAX_REAL_SERVERS];
} real_ip_addr_t;

static inline transfer_map_t *
get_test_pair(transfer_maps_t *tf, uint32_t ip, uint16_t port)
{
    int              i;
    transfer_map_t  *pair, **map;

    pair = NULL;
    map  = tf->map;
    for (i = 0; i < tf->num; i++) {
        pair = map[i];
        if (pair->online_ip == 0 && port == pair->online_port) {
            return pair;
        } else if (ip == pair->online_ip && port == pair->online_port) {
            return pair;
        }
    }
    return NULL;
}

static inline int
check_pack_src(transfer_maps_t *tf, uint32_t ip, uint16_t port, int src_flag)
{
    int              i, ret;
    transfer_map_t  *pair, **map;

    ret = TC_UNKNOWN;
    map = tf->map;

    for (i = 0; i < tf->num; i++) {

        pair = map[i];
        if (src_flag == CHECK_DEST) {
            if (ip == pair->online_ip && port == pair->online_port) {
                ret = TC_CLT;
                break;
            } else if (0 == pair->online_ip && port == pair->online_port) {
                ret = TC_CLT;
                break;
            }
        } else if (src_flag == CHECK_SRC) {
            if (ip == pair->target_ip && port == pair->target_port) {
                ret = TC_BAK;
                break;
            }
        }
    }

    return ret;
}



typedef struct xcopy_clt_settings {
    unsigned int  mtu:16;               /* MTU sent to backend */
    unsigned int  mss:16;               /* MSS sent to backend */
    unsigned int  default_rtt:16;      
    unsigned int  s_pool_size:16;      
    unsigned int  par_conns:8;          /* parallel connections */
    unsigned int  factor:8;             /* port shift factor */
    unsigned int  replica_num:10;       /* replicated number of each request */
    unsigned int  only_replay_full:1;  
    unsigned int  lonely:1;             /* Lonely for tcpcopy */
    unsigned int  gradully:1;
    unsigned int  target_localhost:1;
    unsigned int  do_daemonize:1;       /* daemon flag */
    unsigned int  percentage:7;         /* percentage of the full flow that 
                                           will be tranfered to the backend */
    
    int           sess_timeout;         /* max value for session timeout.
                                           If reaching this value, the session
                                           will be removed */
    int           sess_keepalive_timeout;  

#if (TC_OFFLINE)
    int           accelerated_times;    /* accelerated times */
    pcap_t       *pcap;
    long          pcap_time;
    uint64_t      interval;            
#endif

#if (TC_PCAP)
    int           buffer_size;
    int           snaplen;
    char         *raw_device;
    devices_t     devices;
#endif
    tc_pool_t     *pool;

    transfer_maps_t    transfer;      

    char         *raw_rs_list;         /* raw real server list */
    uint64_t      tries;  
    char         *user_filter;
#if (TC_PCAP_SND)
    char         *output_if_name;
#endif
#if (TC_OFFLINE)
    char         *pcap_file;            /* pcap file */
#endif
    char         *raw_clt_tf_ip;        
    char         *pid_file;             /* pid file */
    char         *log_path;             /* error log path */
    char         *raw_tf;               /* online_ip online_port target_ip
                                           target_port string */
#if (TC_PLUGIN)
    char         *conf_file;      
    tc_conf_t    *cf;
    tc_module_t  *plugin; 
#endif

    int           sig;  
    int           multiplex_io;
    uint32_t      localhost_tf_ip;
    uint32_t      max_rss;             /* max memory allowed for tcpcopy */
    uint16_t      srv_port;            /* server listening port */
    uint16_t      rand_port_shifted;   /* random port shifted */
    uint16_t      clt_tf_ip_num;       
    uint16_t      ip_tf_cnt;

    real_ip_addr_t  real_servers;        /* the intercept servers */
    tc_event_t     *ev[MAX_FD_NUM];
    uint32_t        ip_tf[65536]; 
    uint32_t        clt_tf_ip[M_IP_NUM]; /* ip addr from clt to target ip */
    unsigned char   candidate_mtu[256];
    char            filter[MAX_FILTER_LENGH];
 } xcopy_clt_settings;


typedef struct tc_stat_s {
    uint64_t leave_cnt; 
    uint64_t time_wait_cnt; 
    uint64_t obs_cnt; 
    uint64_t clt_syn_cnt; 
    uint64_t captured_cnt; 
    uint64_t clt_cont_cnt; 
    uint64_t clt_packs_cnt; 
    uint64_t packs_sent_cnt; 
    uint64_t fin_sent_cnt; 
    uint64_t rst_sent_cnt; 
    uint64_t con_packs_sent_cnt; 
    uint64_t resp_rst_cnt; 
    uint64_t resp_fin_cnt; 
    uint64_t resp_cnt; 
    uint64_t resp_cont_cnt; 
    uint64_t conn_cnt; 
    uint64_t conn_try_cnt; 
    uint64_t retrans_succ_cnt; 
    uint64_t retrans_cnt; 
    uint64_t frag_cnt; 
    uint64_t clt_con_retrans_cnt; 
    uint64_t recon_for_closed_cnt; 
    uint64_t recon_for_no_syn_cnt; 
    time_t   start_pt; 
}tc_stat_t;

extern int tc_raw_socket_out;
extern tc_event_loop_t event_loop;
extern xcopy_clt_settings clt_settings;
extern tc_stat_t   tc_stat;
extern hash_table *sess_table;
#if (TC_PLUGIN)
extern tc_module_t  *tc_modules[];
#endif

#include <tc_util.h>

#include <tc_manager.h>
# if(TC_UDP) 
#include <tc_udp_session.h>
#else
#include <tc_session.h>
#endif
#include <tc_message_module.h>
#include <tc_packets_module.h>

#endif /* TC_INCLUDED */
