#ifndef  _TCP_SESSION_H_INC
#define  _TCP_SESSION_H_INC

#include "../core/xcopy.h"
#include "../core/hash.h"

#define FAKE_IP_DATAGRAM_LEN 40
#define IP_HEADER_LEN 20

/* Global functions */
void init_for_sessions();
void destroy_for_sessions();
void process(char *packet);
bool is_packet_needed(const char *packet);

typedef struct session_s{
    /* The hash key for this session */
    uint64_t hash_key;

#if (TCPCOPY_MYSQL_BASIC)
    /* The seq diff between virtual sequence and client sequence */
    uint32_t mysql_vir_req_seq_diff;
#endif

    /* Src or client ip address(network byte order) */
    uint32_t src_addr;
    /* Dst or backend ip address(network byte order) */
    uint32_t dst_addr;
    /* Online ip address(network byte order) */
    uint32_t online_addr;
    /* Orginal src or client port(network byte order,never changed) */
    uint16_t orig_src_port;
    /* Src or client port(host byte order,it may be changed) */
    uint16_t src_h_port;
    /* Dst or backend port(network byte order) */
    uint16_t dst_port;
    /* Online port(network byte order) */
    uint16_t online_port;
    /* Faked src or client port(network byte order) */
    uint16_t faked_src_port;


    /* These values will be sent to backend just for cheating */
    /* Virtual acknowledgement sequence that sends to backend */
    /* (host by order)*/
    uint32_t vir_ack_seq;
    /* Virtual next expected sequence (host byte order) */
    uint32_t vir_next_seq;

    /* Response variables */
    /* Last acknowledgement seq from backend response (host byte order) */
    uint32_t resp_last_ack_seq;

    /* Captured variables */
    /* These variables only refer to online values*/
    /***********************begin************************/
    /*TODO Some variables may be unioned*/
    /* Last syn sequence of client packet */
    uint32_t req_last_syn_seq;
    /* Last sequence of client content packet which has been sent */
    uint32_t req_last_cont_sent_seq;
    /* Last ack sequence of client packet which is sent to bakend */
    uint32_t req_last_ack_sent_seq;
    /* Last client content packet's ack sequence which is captured */
    uint32_t req_cont_last_ack_seq;
    /* Current client content packet's ack seq which is captured */
    uint32_t req_cont_cur_ack_seq;
    /***********************end***************************/

    /* Record time */
    /* Last update time */
    time_t   last_update_time;
    /* Session create time */
    time_t   create_time;
    /* The time of last receiving backend content */
    time_t   resp_last_recv_cont_time;
    /* The time of sending the last content packet */
    time_t   req_last_send_cont_time;

    /* The session status */
    uint32_t status:8;
    /*
     * The number of the response packets last received 
     * which have the same acknowledgement sequence.
     * This is for checking retransmission Required from backend
     */
    uint32_t resp_last_same_ack_num:8;
    /* The id from client ip header */
    uint32_t req_ip_id:16;
    /* The flag indicates if the session has retransmitted or not */
    uint32_t vir_already_retransmit:1;
    /* This is for successful retransmission statistics */
    uint32_t vir_new_retransmit:1;
    /* This is the simultaneous closing flag */
    uint32_t simul_closing:1;
    /* Reset flag either from client or from backend */
    uint32_t reset:1;
    /* Seq added because of fin */
    uint32_t fin_add_seq:1;
    /* Session over flag */
    uint32_t sess_over:1;
    /* Src or client closed flag */
    uint32_t src_closed:1;
    /* Dst or backend closed flag */
    uint32_t dst_closed:1;
    /* Slide window full flag */
    uint32_t last_window_full:1;
    /* Candidate response waiting flag */
    uint32_t candidate_response_waiting:1;
    /* Waiting previous packet flag */
    uint32_t is_waiting_previous_packet:1;
    /* This indicates if the session intercepted the syn packets from client
     * or it has faked the syn packets */
    uint32_t req_syn_ok:1;
    /* This is to avoid using the first handshake ack seq */
    uint32_t req_valid_last_ack_sent:1;
    /*
     * This indicates if we intercepted the packets halfway 
     * including backend already closed
     */
    uint32_t req_halfway_intercepted:1;
    /* This indicates if the syn packets from backend is received */
    uint32_t resp_syn_received:1;
    /* Session candidate erased flag */
    uint32_t sess_candidate_erased:1;
    /* Session reused flag */
    uint32_t sess_more:1;
    /* Port transfered flag */
    uint32_t port_transfered:1;
    /* If set, it will not save the packet to unack list */
    uint32_t unack_pack_omit_save_flag:1;
    /* This indicates if server sends response first */
    uint32_t resp_greet_received:1;
    /* This indicates if it needs to wait server response first */
    uint32_t need_resp_greet:1;
    /* Reset packet sent flag */
    uint32_t reset_sent:1;
#if (TCPCOPY_MYSQL_BASIC)
    /* Mysql excuted times for COM_QUERY(in COM_STMT_PREPARE situation) */
    uint32_t mysql_excute_times:8;
    /* The number of content packets after receiving greet */
    uint32_t mysql_cont_num_aft_greet:4;
    /* Request begin flag for mysql */
    uint32_t mysql_req_begin:1;
    /* This indicates if it needs second auth */
    uint32_t mysql_sec_auth:1;
    /* This indicates if it has sent the first auth */
    uint32_t mysql_first_auth_sent:1;
    /* This indicates if the session has received login packet from client */
    uint32_t mysql_req_login_received:1;
    /* This indicates if the session has prepare statment */
    uint32_t mysql_prepare_stat:1;
    /* This indicates if the first excution is met */
    uint32_t mysql_first_excution:1;
#endif

    link_list *unsend_packets;
    link_list *next_sess_packs;
    link_list *unack_packets;
#if (TCPCOPY_MYSQL_BASIC)
    /* Mysql special packets for reconnection */
    link_list *mysql_special_packets;
#endif
#if (TCPCOPY_MYSQL_ADVANCED)
    char mysql_scramble[SCRAMBLE_LENGTH+1];
    char mysql_seed323[SEED_323_LENGTH+1];
    char mysql_password[MAX_PASSWORD_LEN];
#endif

}session_t;

#endif   /* ----- #ifndef _TCP_SESSION_H_INC ----- */

