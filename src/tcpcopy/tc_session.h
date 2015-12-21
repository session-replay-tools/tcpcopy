#ifndef  TC_SESSION_INCLUDED
#define  TC_SESSION_INCLUDED

#include <xcopy.h>
#include <tcpcopy.h>

#define FFRAME_LEN (60 + ETHERNET_HDR_LEN)
#define FMIN_IP_LEN (IPH_MIN_LEN + (TCPH_DOFF_MIN_VALUE << 2))
#define FIP_TS_LEN (IPH_MIN_LEN + (TCPH_DOFF_TS_VALUE << 2))
#define FSYN_IP_LEN (IPH_MIN_LEN + (TCPH_DOFF_MSS_VALUE << 2))
#define FSYN_IP_TS_LEN (IPH_MIN_LEN + (TCPH_DOFF_WS_TS_VALUE << 2))


/* global functions */
int  tc_init_sess_table(void);
void tc_dest_sess_table(void);
void tc_save_pack(tc_sess_t *, link_list *, tc_iph_t *, tc_tcph_t *);
bool tc_proc_ingress(tc_iph_t *, tc_tcph_t *);
bool tc_proc_outgress(unsigned char *);
uint32_t get_tf_ip(uint16_t key);
bool tc_check_ingress_pack_needed(tc_iph_t *);
void tc_interval_disp(tc_event_timer_t *);
void tc_output_stat(void);


typedef struct sess_state_machine_s{
    uint32_t state:10;
    uint32_t rcv_nxt_sess:1;
    uint32_t candidate_rep_wait:1;
    uint32_t pack_lost:1;
    uint32_t conflict:1;
    uint32_t record_req_hop_seq:1;
    uint32_t recheck_hop:1;

    uint32_t renew_hop:1;
    uint32_t rcv_rep_af_hop:1;
    uint32_t recon:1;
    uint32_t record_mcon_seq:1;
    uint32_t rcv_rep_greet:1;
    uint32_t window_full:1;
    uint32_t internal_usage:1;
    uint32_t timeout:1;

    uint32_t delay_snd:1;
    uint32_t req_ack_snd:1;
    uint32_t fake_syn:1;
    uint32_t timestamp:1;
    uint32_t need_rep_greet:1;
    uint32_t already_retrans:1;
    uint32_t sess_over:1;
    uint32_t src_closed:1;

    uint32_t dst_closed:1;
    uint32_t last_ack:1;
    uint32_t set_rto:1;
    uint32_t snd_after_set_rto:1;
    uint32_t timer_type:3;
    uint32_t rtt_cal:2;
    uint32_t rep_payload_type:2;
    uint32_t rep_dup_ack_cnt:8;
#if (TC_DETECT_MEMORY)
    uint32_t active_timer_cnt:8;
    uint32_t call_sess_post_cnt:8;
#endif
}sess_state_machine_t;

typedef struct pack_info_s {
    uint32_t cont_len:16;
    uint32_t new_req_flag:1;
    uint32_t seq;
    uint32_t ack_seq;
}pack_info_t;

struct tc_sess_s {
    sess_state_machine_t sm; 

    pack_info_t cur_pack;

    /* ack sequence that is sent to backend (host byte order) */
    uint32_t target_ack_seq;
    /* next sequence that is sent to backend (host byte order) */
    uint32_t target_nxt_seq;

    /* max payload packet sequence (host byte order) */
    uint32_t max_con_seq;

    /* src or client ip address(network byte order) */
    uint32_t src_addr;
    /* dst or backend ip address(network byte order) */
    uint32_t dst_addr;
    /* online ip address(network byte order) */
    uint32_t online_addr; 
    /* src or client port(network byte order) */
    uint16_t src_port;
    /* dst or backend port(network byte order) */
    uint16_t dst_port;
    /* online port(network byte order) */
    uint16_t online_port;
    uint16_t req_ip_id;
    uint16_t wscale;
    
    uint32_t peer_window;
    uint32_t ts_ec_r;
    uint32_t ts_value;

    /* captured variables(host byte order) */
    /* only refer to online values */
    /***********************begin************************/
    /* last sequence of client content packet which has been sent */
    uint32_t req_con_snd_seq;
    uint32_t req_exp_seq;
    /* last ack sequence of client packet which is sent to bakend */
    uint32_t req_ack_snd_seq;
    /* last client content packet's ack sequence which is captured */
    uint32_t req_con_ack_seq;
    uint32_t req_con_cur_ack_seq;
    /* last syn sequence of client packet */
    uint32_t req_syn_seq;
    uint32_t req_hop_seq;
    /***********************end***************************/

    /* response variables */
    /* last acknowledgement seq from backend response (host byte order) */
    uint32_t rep_ack_seq;
    /* last seq from backend response (host byte order) */
    uint32_t rep_seq;
#if (TC_DEBUG)
    uint32_t rep_ack_seq_bf_fin;
#endif

    /* hash key for this session */
    uint64_t hash_key;

    long     rtt;
    time_t   create_time;
    /* time of sending the last content packet */
    time_t   req_snd_con_time;
    time_t   pack_lost_time;
    /* time of last receiving backend content */
    time_t   rep_rcv_con_time;

    unsigned char *frame;
    unsigned char *src_mac;
    unsigned char *dst_mac;

    link_list *slide_win_packs;
    link_node *prev_snd_node;

#if (TC_PLUGIN)
    void             *data;
#endif
    tc_event_timer_t *ev;
    tc_event_timer_t *gc_ev;
    tc_pool_t *pool;
};


#endif   /* ----- #ifndef TC_SESSION_INCLUDED ----- */

