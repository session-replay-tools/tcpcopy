#ifndef  _TCP_SESSION_H_INC
#define  _TCP_SESSION_H_INC

#include <xcopy.h>

#define FAKE_SYN_BUF_SIZE  52
#define FAKE_ACK_BUF_SIZE  40
#define FAKE_IP_HEADER_LEN 20

/*global functions*/
void process(char *packet);
bool is_packet_needed(const char *packet);

typedef struct pack_detail_s{
	/* current ip header to be processed*/
	struct iphdr  *ip_header;
	/* current tcp header to be processed*/
	struct tcphdr *tcp_header;
#if (TCPCOPY_MYSQL_BASIC)
	unsigned char *payload;
#endif
	uint16_t      size_ip;
	uint16_t      tot_len;
	uint16_t      size_tcp;
	uint16_t      cont_size;
}pack_detail_t;

typedef struct session_s{
    /*src or client ip address*/
	uint32_t src_addr;
	/*dst or backend ip address*/
	uint32_t dst_addr;
	/*online ip address*/
	uint32_t online_addr;
	/*src or client port*/
	uint16_t src_port;
	/*dst or backend port*/
	uint16_t dst_port;
	/*online port*/
	uint16_t online_port;
	/*faked src or client port*/
	uint16_t faked_src_port;

	/*virtual variables*/
	/*virtual acknowledgement sequence that sends to backend*/
	uint32_t vir_ack_seq;
	/*virtual next expected sequence*/
	uint32_t vir_next_seq;

#if (TCPCOPY_MYSQL_BASIC)
	/*the seq diff between virtual sequence and client sequence*/
	uint32_t mysql_vir_req_seq_diff;
#endif

	/*response variables*/
	/*last sequence from backend response*/
	uint32_t resp_last_seq;
	/*last acknowledgement sequence from backend response*/
	uint32_t resp_last_ack_seq;

	/*captured variables*/
	/* this variables only refer to online values*/
	/***********************begin************************/
	/*last sequence of client content packet which has been sent*/
	uint32_t req_last_cont_sent_seq;
	/*last syn sequence of client packet*/
	uint32_t req_last_syn_seq;
	/*last ack sequence of client packet which is sent to bakend*/
	uint32_t req_last_ack_sent_seq;
	/*last client content packet's ack sequence */
	uint32_t req_cont_last_ack_seq;
	/***********************end***************************/

	/*the number of client content packets*/
	uint64_t req_cont_pack_num;
	/*the number of content packets sent to backend*/
	uint64_t vir_send_cont_pack_num;
	/*the number of content packets from backend response*/
	uint64_t resp_cont_pack_num;

	/*the hash key for this session*/
	uint64_t hash_key;

	/*record time*/
	/*last update time*/
	time_t   last_update_time;
	/*session create time*/
	time_t   create_time;
	/*the time of last receiving backend content*/
	time_t   resp_last_recv_cont_time;
	/*the time of sending the last content packet*/
	time_t   req_last_send_cont_time;

	/*shared variables*/
	/*use this varible to check if the session is keepalived.
	 *it will be added until reaching the threshold */
	uint32_t req_proccessed_num:6;
	/*the size of ip header*/
	uint32_t ip_header_size:6;
	/*the size of tcp header*/
	uint32_t tcp_header_size:6;
	/*the size of packet which is equal to tot_len*/
	uint32_t packet_size:16;
	/*the payload of the tcp packet*/
	uint32_t tcp_payload_size:16;
	/*the session status*/
	uint32_t status:4;
	/*the number of expected handshake packets*/
	uint32_t expected_handshake_pack_num:8;
	/*
	 * the number of the response packets last received 
	 * which have the same acknowledgement sequence.
	 * this is for checking retransmission Required from backend
	 */
	uint32_t resp_last_same_ack_num:8;
	/*the id from client ip header*/
	uint32_t req_ip_id:16;
	/*the flag indicates if the session has retransmitted or not*/
	uint32_t vir_already_retransmit:1;
	/*this is for successful retransmission statistics*/
	uint32_t vir_new_retransmit:1;
	/*this is the simultaneous closing flag*/
	uint32_t simul_closing:1;
	/*reset flag either from client or from backend*/
	uint32_t reset:1;
	/* seq added because of fin */
	uint32_t fin_add_seq:1;
	/*session over flag*/
	uint32_t sess_over:1;
	/*src or client closed flag*/
	uint32_t src_closed:1;
	/*dst or backend closed flag*/
	uint32_t dst_closed:1;
	/*candidate response waiting flag*/
	uint32_t candidate_response_waiting:1;
	/*this indicates if the session needs to wait previous packets or not*/
	uint32_t previous_packet_waiting:1;
	/*connection keepalive flag*/
	uint32_t conn_keepalive:1;
	/*this indicates if faked rst sent to backend*/
	uint32_t faked_rst_sent:1;
	/*this indicates if the session intercepted the syn packets from client
	 * or it has faked the syn packets*/
	uint32_t req_syn_ok:1;
	/*this indicates if we intercepted the packets halfway*/
	uint32_t req_halfway_intercepted:1;
	/*this indicates if the syn packets from backend is received*/
	uint32_t resp_syn_received:1;
	/*session candidate erased flag*/
	uint32_t sess_candidate_erased:1;
	/*session reused flag*/
	uint32_t sess_more:1;
	/*the times of syn retransmission to backend*/
	uint32_t vir_syn_retrans_times:4;
	/*if set, it will not save the packet to unack list*/
	uint32_t unack_pack_omit_save_flag:1;
#if (TCPCOPY_MYSQL_BASIC)
	/*mysql excuted times for COM_QUERY(in COM_STMT_PREPARE situation)*/
	uint32_t mysql_excute_times:8;
	/*the number of greet content packets receiving from backend*/
	uint32_t mysql_cont_num_aft_greet:4;
	/*request begin flag for mysql*/
	uint32_t mysql_req_begin:1;
	/*this indicates if greeting from bakend is received*/
	uint32_t mysql_resp_greet_received:1;
	/*this indicates if it needs second auth*/
	uint32_t mysql_sec_auth:1;
	/*this indicates if it has sent the first auth*/
	uint32_t mysql_first_auth_sent:1;
	/*this indicates if the session has received login packet from client*/
	uint32_t mysql_req_login_received:1;
	/*this indicates if the session has prepare statment*/
	uint32_t mysql_prepare_stat:1;
	/*this indicates if the first excution is met*/
	uint32_t mysql_first_excution:1;
	/*mysql special packets for reconnection*/
	link_list *mysql_special_packets;
#endif

	link_list *unsend_packets;
	link_list *next_session_packets;
	link_list *unack_packets;
	link_list *lost_packets;
	link_list *handshake_packets;
#if (TCPCOPY_MYSQL_ADVANCED)
	char mysql_scramble[SCRAMBLE_LENGTH+1];
	char mysql_seed323[SEED_323_LENGTH+1];
	char mysql_password[MAX_PASSWORD_LEN];
#endif

}session_t;


/* session functions begin */
void process_recv(session_t *s);
void update_virtual_status(session_t *s);
/* session functions end */

#endif   /* ----- #ifndef _TCP_SESSION_H_INC ----- */

