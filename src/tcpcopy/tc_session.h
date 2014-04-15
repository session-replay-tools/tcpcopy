#ifndef  TC_SESSION_INCLUDED
#define  TC_SESSION_INCLUDED

#include <xcopy.h>
#include <tcpcopy.h>

#define IP_HEADER_LEN sizeof(tc_ip_header_t)
#define TCP_HEADER_MIN_LEN sizeof(tc_tcp_header_t)

#define FAKE_FRAME_LEN (60 + ETHERNET_HDR_LEN)
#define FAKE_MIN_IP_DATAGRAM_LEN (IP_HEADER_LEN + (TCP_HEADER_DOFF_MIN_VALUE << 2))
#define FAKE_IP_TS_DATAGRAM_LEN (IP_HEADER_LEN + (TCP_HEADER_DOFF_TS_VALUE << 2))
#define FAKE_SYN_IP_DATAGRAM_LEN (IP_HEADER_LEN + (TCP_HEADER_DOFF_MSS_VALUE << 2))
#define FAKE_SYN_IP_TS_DATAGRAM_LEN (IP_HEADER_LEN + (TCP_HEADER_DOFF_WS_TS_VALUE << 2))


/* global functions */
void init_for_sessions();
void destroy_for_sessions();
bool process_in(unsigned char *frame);
bool process_out(unsigned char *packet);
bool is_packet_needed(unsigned char *packet);
void tc_interval_dispose(tc_event_timer_t *evt);
void output_stat();

typedef struct sess_state_machine_s{
    /* session status */
    uint32_t status:8;
    uint32_t resp_slow:1;
    uint32_t recv_client_close:1;
    /* already retransmission flag */
    uint32_t vir_already_retransmit:1;
    /* just for successful retransmission statistics */
    uint32_t vir_new_retransmit:1;
    /* simultaneous closing flag */
    uint32_t simul_closing:1;
    /* reset flag either from client or from backend */
    uint32_t reset:1;
    /* seq added flag because of fin */
    uint32_t fin_add_seq:1;
    /* session over flag */
    uint32_t sess_over:1;
    /* src or client closed flag */
    uint32_t src_closed:1;
    /* dst or backend closed flag */
    uint32_t dst_closed:1;
    /* slide window full flag */
    uint32_t last_window_full:1;
    /* candidate response waiting flag */
    uint32_t candidate_response_waiting:1;
    uint32_t req_no_resp:1;
    uint32_t send_reserved_from_bak_payload:1;
    /* delay sent flag because of flow control */
    uint32_t delay_sent_flag:1;
    /* waiting previous packet flag */
    uint32_t is_waiting_previous_packet:1;
    /* This indicates if the session intercepted the syn packets from client
     * or it has faked the syn packets */
    uint32_t req_syn_ok:1;
    uint32_t record_ack_before_fin:1;
    /* flag that avoids using the first handshake ack seq */
    uint32_t req_valid_last_ack_sent:1;
    /*
     * This indicates if we intercepted the packets halfway 
     * including backend already closed
     */
    uint32_t req_halfway_intercepted:1;
    uint32_t timestamped:1;
    /* This indicates if the syn packets from backend is received */
    uint32_t resp_syn_received:1;
    /* session candidate erased flag */
    uint32_t sess_candidate_erased:1;
    /* session reused flag */
    uint32_t sess_more:1;
    /* port transfered flag */
    uint32_t port_transfered:1;
    /* if set, it will not save the packet to unack list */
    uint32_t unack_pack_omit_save_flag:1;
    /* This indicates if server sends response first */
    uint32_t resp_greet_received:1;
    /* This indicates if it needs to wait server response first */
    uint32_t need_resp_greet:1;
    /* seset packet sent flag */
    uint32_t reset_sent:1;
#if (TCPCOPY_PAPER)
    uint32_t rtt_cal:2;
#endif
#if (TCPCOPY_MYSQL_BASIC)
    /* the second auth checked flag */
    uint32_t mysql_sec_auth_checked:1;
    /* request begin flag for mysql */
    uint32_t mysql_req_begin:1;
    /* This indicates if it needs second auth */
    uint32_t mysql_sec_auth:1;
    /* This indicates if it has sent the first auth */
    uint32_t mysql_first_auth_sent:1;
    /* This indicates if the session has received login packet from client */
    uint32_t mysql_req_login_received:1;
    /* This indicates if the session has prepare statment */
    uint32_t mysql_prepare_stat:1;
    /* This indicates if the first execution is met */
    uint32_t mysql_first_execution:1;
#endif

}sess_state_machine_t;

typedef struct session_s{
    /* hash key for this session */
    uint64_t hash_key;

#if (TCPCOPY_MYSQL_BASIC)
    /* seq diff between virtual sequence and client sequence */
    uint32_t mysql_vir_req_seq_diff;
#endif

    /* src or client ip address(network byte order) */
    uint32_t src_addr;
    /* dst or backend ip address(network byte order) */
    uint32_t dst_addr;
    /* online ip address(network byte order) */
    uint32_t online_addr;
    uint32_t srv_window;
    uint32_t ts_ec_r;
    uint32_t ts_value;
    uint16_t wscale;
    /* orginal src or client port(network byte order, never changed) */
    uint16_t orig_src_port;
    /* src or client port(host byte order and  it may be changed) */
    uint16_t src_h_port;
    /* dst or backend port(network byte order) */
    uint16_t dst_port;
    /* online port(network byte order) */
    uint16_t online_port;
    /* faked src or client port(network byte order) */
    uint16_t faked_src_port;
#if (TCPCOPY_PAPER)
    /* round trip time */
    long     rtt;
    long     min_rtt;
    long     max_rtt;
    long     base_rtt;
    long     resp_unack_time;
    long     first_resp_unack_time;
    long     response_content_time;
#endif

    /* These values will be sent to backend just for cheating */
    /* Virtual acknowledgement sequence that sends to backend */
    /* (host byte order) */
    uint32_t vir_ack_seq;
    /* virtual next expected sequence (host byte order) */
    uint32_t vir_next_seq;

    /* response variables */
    /* last acknowledgement seq from backend response (host byte order) */
    uint32_t resp_last_ack_seq;
    /* last seq from backend response (host byte order) */
    uint32_t resp_last_seq;

    /* captured variables */
    /* only refer to online values */
    /***********************begin************************/
    /* last syn sequence of client packet */
    uint32_t req_last_syn_seq;
    /* last sequence of client content packet which has been sent */
    uint32_t req_last_cont_sent_seq;
    /* last ack sequence of client packet which is sent to bakend */
    uint32_t req_last_ack_sent_seq;
    uint32_t req_ack_before_fin;
    /* last client content packet's ack sequence which is captured */
    uint32_t req_cont_last_ack_seq;
    /* current client content packet's ack seq which is captured */
    uint32_t req_cont_cur_ack_seq;
    /***********************end***************************/

    /* record time */
    /* last update time */
    time_t   last_update_time;
    /* session create time */
    time_t   create_time;
    /* time of last receiving backend content */
    time_t   resp_last_recv_cont_time;
    /* time of sending the last content packet */
    time_t   req_last_send_cont_time;
    /* kinds of states of session */
    sess_state_machine_t sm; 

    /* id from client ip header */
    uint32_t req_ip_id:16;
    /*
     * The number of the response packets last received 
     * which have the same acknowledgement sequence.
     * This is for checking retransmission Required from backend
     */
    uint32_t resp_last_same_ack_num:8;
#if (TCPCOPY_MYSQL_BASIC)
    /* mysql executed times for COM_QUERY(in COM_STMT_PREPARE situation) */
    uint32_t mysql_execute_times:8;
#endif
    unsigned char *src_mac;
    unsigned char *dst_mac;

    link_list *unsend_packets;
    link_list *next_sess_packs;
    link_list *unack_packets;
#if (TCPCOPY_MYSQL_ADVANCED)
    char mysql_scramble[SCRAMBLE_LENGTH + 1];
    char mysql_seed323[SEED_323_LENGTH + 1];
    char mysql_password[MAX_PASSWORD_LEN];
#endif

}session_t;

#endif   /* ----- #ifndef TC_SESSION_INCLUDED ----- */

