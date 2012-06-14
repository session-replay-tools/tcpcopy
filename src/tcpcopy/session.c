#include "../communication/msg.h"
#include "../util/util.h"
#include "../log/log.h"
#include "session.h"

static int send_reserved_packets(session_t *s);
static int retransmit_packets(session_t *s);
static int check_dead_reqs(session_t *s);

static hash_table *sessions_table;

#if (TCPCOPY_MYSQL_BASIC)
static hash_table *mysql_table;
#endif
#if (TCPCOPY_MYSQL_ADVANCED)
static hash_table *fir_auth_pack_table;
static hash_table *sec_auth_pack_table;
#endif

/* Total client syn packets */
static uint64_t clt_syn_cnt         = 0;
/* Total client packets */
static uint64_t clt_packs_cnt       = 0;
/* Total sessions created */
static uint64_t enter_cnt           = 0;
/* Total sessions deleted */
static uint64_t leave_cnt           = 0;
/* Total obsolete sessions */
static uint64_t obs_cnt             = 0;
/* Total client packets */
static uint64_t clt_cnt             = 0;
/* Total client packets sent to backend */
static uint64_t packs_sent_cnt      = 0;
/* Total client content packets sent to backend */
static uint64_t con_packs_sent_cnt  = 0;
/* Total response packets */
static uint64_t resp_cnt            = 0;
/* Total response content packets */
static uint64_t resp_cont_cnt       = 0;
/* Total connections successfully cheated */
static uint64_t conn_cnt            = 0;
/* Total time for disposing response packets */
static double   resp_disp_t         = 0;
/* Total time for disposing client packets */
static double   clt_disp_t          = 0;
/* Last time for statistics */
static time_t   last_stat_time      = 0;
/* Start time for excuting the process function */
static time_t   start_p_time        = 0;
/* Total successful retransmission */
static uint64_t retrans_succ_cnt    = 0;
/* Total reconnections for backend */
static uint64_t recon_for_closed_cnt   = 0;
/* Total reconnections for halfway interception */
static uint64_t recon_for_no_syn_cnt   = 0;
/* Last time for checking dead sessions */
static time_t   last_ch_dead_sess_time = 0;

#if (TCPCOPY_MYSQL_BASIC)
/* Global sequence omission */
static uint32_t g_seq_omit        = 0;
/* The global first auth user packet */
static struct iphdr *fir_auth_u_p = NULL;
#endif

int create_session_table()
{
	/* Create 65536 slots for session table */
	sessions_table = hash_create(65536);
	strcpy(sessions_table->name, "session-table");
}

static void session_init(session_t *s, int keepalive)
{
	link_list *hl;
#if (TCPCOPY_MYSQL_BASIC)
	link_list *ml;
#endif 
	int       handshake_pack_num;

	if(s->unsend_packets){
		if(s->unsend_packets->size > 0){
			link_list_destory(s->unsend_packets);
		}
	}else{
		s->unsend_packets = link_list_create();
	}

	if(s->lost_packets){
		if(s->lost_packets->size > 0){
			link_list_destory(s->lost_packets);
		}
	}else{
		s->lost_packets = link_list_create();
	}

	if(s->unack_packets){
		if(s->unack_packets->size >0){
			link_list_destory(s->unack_packets);
		}
	}else{
		s->unack_packets = link_list_create();
	}

	if(!keepalive)
	{
		if(s->handshake_packets){
			if(s->handshake_packets->size > 0){
				link_list_destory(s->handshake_packets);
			}
		}else{
			s->handshake_packets = link_list_create();
		}
#if (TCPCOPY_MYSQL_BASIC)
		if(s->mysql_special_packets){
			if(s->mysql_special_packets->size > 0){
				link_list_destory(s->mysql_special_packets);
			}
		}else{
			s->mysql_special_packets = link_list_create();
		}
#endif
	}else{
		hl = s->handshake_packets;
#if (TCPCOPY_MYSQL_BASIC)
		ml = s->mysql_special_packets;
#endif		
		handshake_pack_num = s->expected_handshake_pack_num;
	}
	memset(s, 0 , sizeof(session_t));

	s->expected_handshake_pack_num = 2;
	
	s->status      = CLOSED;
	s->create_time      = time(0);
	s->last_update_time = s->create_time;
	s->resp_last_recv_cont_time = s->create_time;
	s->req_last_send_cont_time  = s->create_time;

	if(keepalive){
		s->handshake_packets = hl;
#if (TCPCOPY_MYSQL_BASIC)
		s->mysql_special_packets = ml;
#endif
		s->expected_handshake_pack_num = handshake_pack_num;
	}
#if (TCPCOPY_MYSQL_BASIC)
	s->mysql_first_excution = 1;
#endif

}

static void session_init_for_next(session_t *s)
{
	link_list   *list = s->next_session_packets;
	session_init(s, 1);

	if(NULL != list){
		s->unsend_packets = list;
	}
}

static session_t *session_create(struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
	ip_port_pair_mapping_t *test;
    session_t *s = (session_t *)malloc(sizeof(session_t));
	if(NULL == s){
		return NULL;
	}
	session_init(s, 0);
	s->src_addr    = ip_header->saddr;
	s->online_addr = ip_header->daddr;
	s->src_port    = tcp_header->source;
	s->online_port = tcp_header->source;
	test = get_test_pair(&(clt_settings.transfer), 
			s->online_addr, s->online_port);
	s->dst_addr    = test->target_ip;
	s->dst_port    = test->target_port;
	return s;
}

static session_t *session_add(uint64_t key, struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
	link_list           *list;
	p_link_node         ln;
	session_t           *s;
	s = hash_find(sessions_table, key);
	if(NULL == s){
		s = session_create(ip_header, tcp_header);
		if(NULL != s){
			hash_add(sessions_table, key, s);
		}
	}
	return s;
}

static void delete_session(session_t *s){
	if(NULL != s->unsend_packets){
		link_list_destory(s->unsend_packets);
	}
	if(NULL != s->next_session_packets){
		link_list_destory(s->next_session_packets);
	}
	if(NULL != s->unack_packets){
		link_list_destory(s->unack_packets);
	}
	if(NULL != s->lost_packets){
		link_list_destory(s->lost_packets);
	}
	if(NULL != s->handshake_packets){
		link_list_destory(s->handshake_packets);
	}
#if (TCPCOPY_MYSQL_BASIC)
	if(NULL != s->mysql_special_packets){
		link_list_destory(s->mysql_special_packets);
	}
#endif
}

static int check_session_over(session_t *s)
{
	if(s->reset){   
		return 1;
	}   
	if(s->sess_over){   
		return 1;
	}   
	return 0;
}

static uint16_t  get_pack_cont_len(struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
	uint16_t   size_ip, size_tcp, tot_len, cont_len;

	size_ip    = ip_header->ihl << 2;
	if(NULL == tcp_header){
		tcp_header = (struct tcphdr*)((char *)ip_header + size_ip);
	}
	tot_len   = ntohs(ip_header->tot_len);
	size_ip   = ip_header->ihl << 2;
	size_tcp  = tcp_header->doff << 2;
	cont_len = tot_len - size_tcp - size_ip;
	
	return cont_len;
}

static int check_overwhelming(session_t *s, const char *message, 
		int size, int max_hold_packs)
{
	if(size > max_hold_packs){
		if(!s->sess_candidate_erased){
			s->sess_candidate_erased = 1;
			log_info(LOG_WARN, "%s:candidate erased:%u,p:%u",
				message, size, s->src_port);

			return CANDIDATE_OBSOLETE;
		}
		obs_cnt++;
		log_info(LOG_WARN,":%s:too many packets:%u,p:%u",
				message, size, s->src_port);

		return OBSOLETE;
	}
	return NOT_YET_OBSOLETE;
}

/* Check if session is obsolete */
static int check_session_obsolete(session_t *s, time_t cur, time_t timeout)
{
	int      threshold = 256, result, packs_unsend;	
	double   diff = cur - s->req_last_send_cont_time;
	
	if(diff < 30){
		threshold = threshold << 3;
		if(diff < 3){
			threshold = threshold << 1;
		}
		packs_unsend = s->unsend_packets->size;
		if(packs_unsend < threshold){
			return 0;
		}else{
			log_info(LOG_WARN,"still live,but too many:%u,threshold:%u",
					s->src_port, threshold);
		}
	}
	result = check_overwhelming(s, "unsend", threshold, 
			s->unsend_packets->size);
	if(NOT_YET_OBSOLETE != result){
		return result;
	}
	result = check_overwhelming(s, "lost", threshold, 
			s->lost_packets->size);
	if(NOT_YET_OBSOLETE != result){
		return result;
	}
	result = check_overwhelming(s, "handshake", threshold, 
			s->handshake_packets->size);
	if(NOT_YET_OBSOLETE != result){
		return result;
	}
	result = check_overwhelming(s, "unack", threshold, 
			s->unack_packets->size);
	if(NOT_YET_OBSOLETE != result){
		return result;
	}
	result = check_overwhelming(s, "next session", threshold, 
			s->next_session_packets->size);
	if(NOT_YET_OBSOLETE != result){
		return result;
	}
#if (TCPCOPY_MYSQL_BASIC)
	result = check_overwhelming(s, "mysql special", threshold, 
			s->mysql_special_packets->size);
	if(NOT_YET_OBSOLETE != result){
		return result;
	}
#endif

	if(s->resp_last_recv_cont_time < timeout){
		if(!s->sess_candidate_erased){
			s->sess_candidate_erased = 1;
			return CANDIDATE_OBSOLETE;
		}
		obs_cnt++;
		log_info(LOG_INFO, "session timeout,p:%u", s->src_port);
		if(s->unsend_packets->size > 10){
			log_info(LOG_WARN,"timeout,unsend number:%u,p:%u",
					s->unsend_packets->size, s->src_port);
		}
		return OBSOLETE;
	}
}

/*
 * Clear tcp timeout sessions
 */
static int clear_timeout_sessions()
{
	/*
	 * We clear old sessions that receive no content response for 
	 * more than one minute. This may be a problem 
	 * for keepalive connections.
	 * So we adopt a naive method to distinguish between short-lived 
	 * and long-lived sessions(one connection represents one session)
	 */
	time_t      current, norm_timeout, keepalive_timeout, timeout;
	double      ratio; 
	size_t      size, i;           
	int         result;
	link_list   *list;
	p_link_node ln, tmp_ln;
	hash_node   *hn;

	current = time(0);
	norm_timeout =current -60;
	keepalive_timeout = current -120;

	ratio = 100.0*enter_cnt/(resp_cnt + 1);
	if(ratio < 5){
		norm_timeout = keepalive_timeout;
		log_info(LOG_NOTICE, "keepalive connection global");
	}

	log_info(LOG_NOTICE, "session size:%u", sessions_table->total);

	for(i = 0; i < sessions_table->size; i++){
		list = sessions_table->lists[i];
		if(!list){
			continue;
		}
	    ln   = link_list_first(list);	
		while(ln){
			hn = (hash_node *)ln->data;
			result = NOT_YET_OBSOLETE;
			if(hn->data != NULL){
				session_t *s = hn->data;
				if(s->conn_keepalive){
					timeout = keepalive_timeout;
				}else{
					timeout = norm_timeout;
				}
				result = check_session_obsolete(s, current, timeout);
				if(OBSOLETE == result){
					/* Delete session */
					delete_session(s);
					free(s);
				}
			}
			tmp_ln = ln;
			ln = link_list_get_next(list, ln);
			if(OBSOLETE == result){
				link_list_remove(list, tmp_ln);
			}
		}
	}
}

static void activate_dead_sessions()
{
	int          i;
	link_list    *list;
	p_link_node  ln;
	hash_node    *hn;

	log_info(LOG_NOTICE, "activate_dead_sessions");
	for(i = 0; i < sessions_table->size; i++)
	{
		list = sessions_table->lists[i];
	    ln   = link_list_first(list);	
		while(ln){
			hn = (hash_node *)ln->data;
			if(hn->data != NULL){
				session_t *s = hn->data;
				if(check_dead_reqs(s)){
					log_info(LOG_NOTICE,"send dead reqs from global");
					send_reserved_packets(s);
				}else{
					if(SYN_SENT == s->status && 
							s->vir_syn_retrans_times <= 3){
						/* Retransmit the syn packet */
						retransmit_packets(s);
					}
				}
			}
			ln = link_list_get_next(list, ln);
		}
	}
}

/*
 * Wrap sending ip packet function
 */
static int wrap_send_ip_packet(session_t *s, unsigned char *data)
{
	struct iphdr  *ip_header;
	struct tcphdr *tcp_header;
	uint16_t      size_ip, tot_len, cont_len;
	p_link_node   ln;
	ssize_t       send_len;
	uint32_t      tmp_req_last_cont_sent_seq;

	if(NULL != data){
		log_info(LOG_ERR, "error ip data is null");
		return 0;
	}

	ip_header  = (struct iphdr *)data;
	size_ip    = ip_header->ihl << 2;
	tcp_header = (struct tcphdr *)(data + size_ip);
    tmp_req_last_cont_sent_seq = tcp_header->seq;
	s->req_last_ack_sent_seq = ntohl(tcp_header->ack_seq);

	if(!s->unack_pack_omit_save_flag){
		ln = link_node_malloc(copy_ip_packet(ip_header));
		link_list_append(s->unack_packets, ln);
	}
	/* Set the destination ip and port*/
	ip_header->daddr = s->dst_addr;
	tcp_header->dest = s->dst_port;

	s->vir_next_seq = ntohl(tcp_header->seq);
	/* Add seq when meeting syn or fin packet */
	if(tcp_header->syn || tcp_header->fin){
		if(tcp_header->syn){
			s->status = SYN_SENT;
			s->req_last_syn_seq = tcp_header->seq;
		}else{
			s->fin_add_seq = 1;
		}
		s->vir_next_seq = s->vir_next_seq + 1;
	}
	if(tcp_header->ack){
		tcp_header->ack_seq = s->vir_ack_seq;
	}

	tot_len   = ntohs(ip_header->tot_len);
	cont_len = get_pack_cont_len(ip_header, tcp_header);
	if(cont_len > 0){
		s->req_last_send_cont_time = time(0);
		s->req_last_cont_sent_seq  = htonl(tmp_req_last_cont_sent_seq);
		s->vir_next_seq = s->vir_next_seq + cont_len;
		if(s->unack_pack_omit_save_flag){
			s->vir_new_retransmit = 1;
		}else{
			con_packs_sent_cnt++;
		}
	}

	tcp_header->check = tcpcsum((unsigned char *)ip_header,
			(unsigned short *)tcp_header, tot_len-size_ip);
	/*
	 * for linux 
	 * The two fields that are always filled in are: the IP checksum 
	 * (hopefully for us - it saves us the trouble) and the total length, 
	 * iph->tot_len, of the datagram 
	 */
	ip_header->check = csum((unsigned short *)ip_header, size_ip); 
#if (DEBUG_TCPCOPY)
	strace_pack(LOG_DEBUG, TO_BAKEND_FLAG, ip_header, tcp_header);
#endif
	packs_sent_cnt++;

	send_len = send_ip_packet(ip_header, tot_len);

	if(-1 == send_len){
		log_info(LOG_ERR,"send to back error,tot_len is:%d,cont_len:%d",
				tot_len,cont_len);
	}

	return 1;
}

/*
 * Check if the session has lost previous packets
 */
static int check_packet_lost(session_t *s, struct iphdr *ip_header, 
		struct tcphdr *tcp_header) 
{
	p_link_node  ln;
	uint32_t     cur_seq = ntohl(tcp_header->seq);
	if(cur_seq > s->vir_next_seq){
		if(send_reserved_packets(s) > 0){
			ln = link_node_malloc(copy_ip_packet(ip_header));
			ln->key = ntohl(tcp_header->seq);
			link_list_order_append(s->unsend_packets, ln);
		}else{
#if (DEBUG_TCPCOPY)
			log_info(LOG_INFO, "seq now:%u,expected seq:%u",
					cur_seq, s->vir_next_seq);
#endif
			return 1;
		}
	}
	return 0;
}

/*
 * Send reserved lost packets.
 * This is to solve the problem when packets arrive out of order
 */
static int send_reserved_lost_packets(session_t *s)
{
	int      need_more_check, loop_over = 0, need_free;
	uint16_t size_ip, cont_len;
	uint32_t cur_seq;
	unsigned char *data;
	struct iphdr  *ip_header;
	struct tcphdr *tcp_header;
	p_link_node   ln, tmp_ln;
	link_list     *list;

	if(NULL == s->lost_packets){
		log_info(LOG_WARN, "no lost packets");
	}
	log_info(LOG_NOTICE, "lost packets size:%d", list->size);

	list = s->lost_packets;
	while(!loop_over){
		need_more_check = 0;
		ln = link_list_first(list);	
		while(ln){
			data       = (unsigned char*)ln->data;
			ip_header  =(struct iphdr*)((char*)data);
			size_ip    = ip_header->ihl << 2;
			tcp_header = (struct tcphdr*)((char *)ip_header + size_ip);
			cont_len  = get_pack_cont_len(ip_header, tcp_header);
			cur_seq    = ntohl(tcp_header->seq);
			need_free  = 0;

			if(s->vir_next_seq == cur_seq){
#if (DEBUG_TCPCOPY)
				log_info(LOG_DEBUG, "send packets for lost:%u", s->src_port);
#endif
				if(cont_len > 0)
				{
					s->candidate_response_waiting = 1;
				}
				wrap_send_ip_packet(s, data);
				need_more_check = 1;
				need_free = 1;
			}else if(s->vir_next_seq > cur_seq){
				need_free = 1;
				log_info(LOG_NOTICE, "abnormal packets in lost");
			}
			if(need_free){
				tmp_ln = ln;
				ln = link_list_get_next(list, ln);
				link_list_remove(list, tmp_ln);
				free(data);
			}
		}
		if(!need_more_check){
			log_info(LOG_NOTICE, "can't send packs for lost:%u", 
					s->src_port);
			loop_over = 1;
		}
	}

	if(link_list_is_empty(list)){
		/* Still need previous packet */
		s->previous_packet_waiting = 0;
	}

	return 0;
}

/*
 * Retransmit the packets to backend
 */
static int retransmit_packets(session_t *s)
{
	unsigned char *data;
	struct iphdr  *ip_header;
	struct tcphdr *tcp_header;
	uint16_t      size_ip, cont_len;
	uint32_t      cur_seq;
	p_link_node   ln, tmp_ln;
	link_list     *list, *buffered;
	int need_pause = 0, is_success = 0;

	list = s->unack_packets;
	ln = link_list_first(list);	

	while(ln && (!need_pause)){
		data = ln->data;
		ip_header  = (struct iphdr*)((char*)data);
		size_ip    = ip_header->ihl << 2;
		tcp_header = (struct tcphdr*)((char *)ip_header + size_ip);
		if(SYN_SENT == s->status){
			s->unack_pack_omit_save_flag = 1;
			wrap_send_ip_packet(s, data);
			s->vir_syn_retrans_times++;
			break;
		}
		cont_len = get_pack_cont_len(ip_header, tcp_header);
		cur_seq   = ntohl(tcp_header->seq);  
		if(!is_success){
			if(cur_seq == s->resp_last_ack_seq){
				is_success = 1;
			}else if(cur_seq < s->resp_last_ack_seq){
				tmp_ln = ln;
				ln = link_list_get_next(list, ln);
				link_list_remove(list, tmp_ln);
				free(data);
			}else{
				log_info(LOG_NOTICE, "no retrans packs:%u", s->src_port);
				need_pause = 1;
			}
		}
		if(is_success){
			if(cur_seq < s->vir_next_seq){
				s->unack_pack_omit_save_flag = 1;
				wrap_send_ip_packet(s, data);
				tmp_ln = link_node_malloc(data);
				link_list_append(buffered, tmp_ln); 
				link_list_remove(list, ln);
			}else{
				need_pause=1;	
			}
		}
	}
	
	if(!link_list_is_empty(buffered)){
		/* Append all buffered packets to unack link list */
		ln = link_list_first(buffered);	
		while(ln){
			link_list_append(list, ln);
			ln = link_list_get_next(buffered, ln);
		}
	}

	return is_success;
}

/*
 * Update retransmission packets
 */
static void update_retransmission_packets(session_t *s)
{
	unsigned char *data;
	struct iphdr  *ip_header;
	struct tcphdr *tcp_header;
	uint16_t      size_ip;
	uint32_t      cur_seq;
	p_link_node   ln, tmp_ln;
	link_list     *list;

	list = s->unack_packets;
	ln = link_list_first(list);	

	while(ln){
		data = ln->data;
		ip_header  = (struct iphdr*)((char*)data);
		size_ip    = ip_header->ihl << 2;
		tcp_header = (struct tcphdr*)((char *)ip_header + size_ip);
		cur_seq    = ntohl(tcp_header->seq);  
		if(cur_seq < s->resp_last_ack_seq){
			tmp_ln = ln;
			ln = link_list_get_next(list, ln);
			link_list_remove(list, tmp_ln);
			free(data);
		}else{
			break;
		}
	}
	return;
}


/*
 * Check if it needs sending dead requests
 * This happens in the following situations:
 * 1)Online requests are finished completely,but test are not,
 *   therefore there are no events that trigger the session 
 * 2)...
 */
static int check_dead_reqs(session_t *s)
{
	int    packs_unsend = 0, diff, result = 0;

	packs_unsend = s->unsend_packets->size;
	diff = time(0) - s->req_last_send_cont_time;

	/* More than 2 seconds */
	if(diff > 2){
		/* If there are more than 5 packets unsend */
		if(packs_unsend > 5){
			return 1;
		}
	}
	return 0;
}

/*
 * Check if the reserved container has content left
 */
static int check_reserved_content_left(session_t *s)
{
	unsigned char *data;
	struct iphdr  *ip_header;
	struct tcphdr *tcp_header;
	p_link_node   ln, tmp_ln;
	link_list     *list;
	uint16_t      cont_len;

#if (DEBUG_TCPCOPY)
	log_info(LOG_DEBUG,"check_reserved_content_left");
#endif
	list = s->unsend_packets;
	ln = link_list_first(list);	

	while(ln){
		data = ln->data;
		ip_header  = (struct iphdr*)((char*)data);
		cont_len  = get_pack_cont_len(ip_header, NULL);
		if(cont_len>0)
		{
			return 1;
		}
		ln = link_list_get_next(list, ln);
	}
	return 0;
}

#if (TCPCOPY_MYSQL_ADVANCED)
static int mysql_dispose_auth(session_t *s, struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
	void          *value;
	char          encryption[16];
	int           ch_auth_success;
	uint64_t      key;
	unsigned char *payload;
	uint16_t      size_tcp, cont_len;

	size_tcp  = tcp_header->doff << 2;
	cont_len = get_pack_cont_len(ip_header, tcp_header);

	if(!s->mysql_first_auth_sent){

		log_info(LOG_NOTICE,"mysql login req from reserved");
		payload=(unsigned char*)((char*)tcp_header + size_tcp);
		ch_auth_success=change_client_auth_content(payload, 
				(int)cont_len, s->mysql_password, s->mysql_scramble);
		strace_pack(LOG_NOTICE, CLIENT_FLAG, ip_header, tcp_header);
		if(!ch_auth_success)
		{
			s->sess_over  = 1;
			log_info(LOG_WARN, "it is strange here,possibility");
			log_info(LOG_WARN, "1)user password pair not equal");
			log_info(LOG_WARN, "2)half-intercepted");
			return FAILURE;
		}
		s->mysql_first_auth_sent = 1;
		key = get_ip_port_value(ip_header->saddr, 
				tcp_header->source);
		value = hash_find(fir_auth_pack_table, key);
		if(value != NULL)
		{
			free(value);
			log_info(LOG_NOTICE, "free for fir auth:%llu", key);
		}
		value = (void *)copy_ip_packet(ip_header);
		hash_add(fir_auth_pack_table, key, value);
		log_info(LOG_NOTICE, "set value for fir auth:%llu",key);

	}else if(s->mysql_first_auth_sent && s->mysql_sec_auth){

		log_info(LOG_NOTICE, "sec login req from reserved");
		payload = (unsigned char*)((char*)tcp_header + size_tcp);
		memset(encryption, 0, 16);
		memset(s->mysql_seed323, 0, SEED_323_LENGTH + 1);
		memcpy(s->mysql_seed323, s->mysql_scramble, SEED_323_LENGTH);
		new_crypt(encryption, s->mysql_password, s->mysql_seed323);
		log_info(LOG_NOTICE, "change second req:%u", s->src_port);
		/* change sec auth content from client auth packets */
		change_client_second_auth_content(payload, cont_len, encryption);
		s->mysql_sec_auth = 0;
		strace_pack(LOG_NOTICE, CLIENT_FLAG, ip_header, tcp_header);
		key = get_ip_port_value(ip_header->saddr, tcp_header->source);
		value = hash_find(sec_auth_pack_table, key);
		if(value != NULL)
		{
			free(value);
			log_info(LOG_NOTICE, "free for sec auth:%llu", key);
		}
		value = (void *)copy_ip_packet(ip_header);
		hash_add(sec_auth_pack_table, key, value);
		log_info(LOG_WARN,"set sec auth packet:%llu", key);

	}

	return SUCCESS;
}
#endif

/*
 * Send reserved packets to backend
 */
static int send_reserved_packets(session_t *s)
{
	unsigned char *data;
	struct iphdr  *ip_header;
	struct tcphdr *tcp_header;
	p_link_node   ln, tmp_ln;
	link_list     *list;
	uint16_t      size_ip, cont_len;
	uint32_t      cur_ack;
	int need_pause = 0, cand_pause = 0, count = 0, omit_transfer = 0; 

#if (DEBUG_TCPCOPY)
	log_info(LOG_DEBUG,"send reserved packs, port:%u",s->src_port);
#endif

	list = s->unsend_packets;
	if(NULL == list){
		log_info(LOG_WARN, "list is null");
		return count;
	}
	ln = link_list_first(list);	

	while(ln && (!need_pause)){
		data = ln->data;
		ip_header =(struct iphdr*)((char*)data);
		size_ip   = ip_header->ihl << 2;
		tcp_header = (struct tcphdr*)((char *)ip_header + size_ip);
		cont_len = get_pack_cont_len(ip_header, tcp_header);
		if(cont_len > 0){
#if (TCPCOPY_MYSQL_BASIC)
			if(!s->mysql_resp_greet_received){
				break;
			}
#if (TCPCOPY_MYSQL_ADVANCED) 
			if(FAILURE == mysql_dispose_auth(s, ip_header, tcp_header)){
				break;
			}
#endif
#endif
			cur_ack = ntohl(tcp_header->ack_seq);
			if(cand_pause){
				if(cur_ack != s->req_last_ack_sent_seq){
					break;
				}
			}
			cand_pause   = 1;
			s->candidate_response_waiting = 1;
		}else if(tcp_header->rst){
			if(s->candidate_response_waiting){
				break;
			}
			s->reset      = 1;
			omit_transfer = 0;
			need_pause    = 1;
		}else if(tcp_header->fin){
			if(s->candidate_response_waiting){
				break;
			}
			need_pause = 1;
			if(s->req_last_ack_sent_seq == ntohl(tcp_header->ack_seq)){
				/* active close from client */
				s->src_closed = 1;
				s->status |= CLIENT_FIN;
			}else{
				/* server active close */
				omit_transfer = 1;
			}
		}else if(0 == cont_len)
		{
			/* Waiting the response pack or the sec handshake pack */
			if(s->candidate_response_waiting || SYN_CONFIRM != s->status){
				omit_transfer = 1;
			}
		}

		if(!omit_transfer){
			count++;
			wrap_send_ip_packet(s, data);
		}
		tmp_ln = ln;
		ln = link_list_get_next(list, ln);
		link_list_remove(list, tmp_ln);
		free(data);

		omit_transfer = 0;
	}

	return count;
}

/*
 * Send faked syn packet to backend.
 */
static void send_faked_syn(session_t *s, struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
	unsigned char f_s_buf[FAKE_SYN_BUF_SIZE], *data;
	struct iphdr  *f_ip_header;
	struct tcphdr *f_tcp_header;
	p_link_node   ln, tmp_ln;
#if (TCPCOPY_MYSQL_BASIC)
	struct iphdr  *fir_auth_pack, *fir_ip_header, *tmp_ip_header;
	struct tcphdr *fir_tcp_header, *tmp_tcp_header;
	uint32_t total_cont_len, base_seq;
	uint16_t size_ip, fir_cont_len, tmp_cont_len;
	link_list     *list;
#if (TCPCOPY_MYSQL_ADVANCED)
	struct iphdr  *sec_auth_packet;
	struct iphdr  *sec_ip_header;
	struct tcphdr *sec_tcp_header;
	uint16_t      sec_cont_len;
	uint64_t      key;
	void          *value;
#endif
#endif

	memset(f_s_buf,0,FAKE_SYN_BUF_SIZE);
	f_ip_header  = (struct iphdr *)f_s_buf;
	f_tcp_header = (struct tcphdr *)(f_s_buf + FAKE_IP_HEADER_LEN);
	f_ip_header->version  = 4;
	f_ip_header->ihl      = 5;
	f_ip_header->tot_len  = htons(FAKE_SYN_BUF_SIZE);
	f_ip_header->frag_off = 64; 
	f_ip_header->ttl      = 64; 
	f_ip_header->protocol = 6;
	f_ip_header->id       = htons(s->req_ip_id + 2);
	f_ip_header->saddr    = ip_header->saddr;
	f_ip_header->daddr    = ip_header->daddr;
	f_tcp_header->doff    = 8;
	f_tcp_header->source  = tcp_header->source;
	f_tcp_header->dest    = tcp_header->dest;
	f_tcp_header->syn     = 1;
	f_tcp_header->seq     = minus_one(tcp_header->seq);
	f_tcp_header->window  = 65535;
	s->vir_next_seq       = tcp_header->seq;
	ln = link_node_malloc(copy_ip_packet(f_ip_header));
	ln->key = ntohl(f_tcp_header->seq);
	link_list_order_append(s->handshake_packets, ln);
#if (TCPCOPY_MYSQL_BASIC)
	s->mysql_req_begin = 1;
	/* Use the global first auth user packet for mysql skip-grant-tables */
	fir_auth_pack = fir_auth_u_p;
#if (TCPCOPY_MYSQL_ADVANCED)
	key = get_ip_port_value(ip_header->saddr, tcp_header->source);
	value = hash_find(fir_auth_pack_table, key);
	if(NULL != value){
		/* Use the private first auth user packet */
		fir_auth_pack = (struct iphdr *)value;
	}
	value = hash_find(sec_auth_pack_table, key);
	if(NULL != value){
		sec_auth_packet = (struct iphdr *)value;
	}
#endif
	if(fir_auth_pack){
		fir_ip_header  = (struct iphdr*)copy_ip_packet(fir_auth_pack);
		fir_ip_header->saddr = f_ip_header->saddr;
		size_ip        = fir_ip_header->ihl << 2;
		fir_tcp_header = (struct tcphdr*)((char *)fir_ip_header + size_ip);
		fir_cont_len = get_pack_cont_len(fir_ip_header, fir_tcp_header);
		fir_tcp_header->source = f_tcp_header->source;
		ln = link_node_malloc(fir_ip_header);
		ln->key = ntohl(fir_tcp_header->seq);
		link_list_order_append(s->unsend_packets, ln);
		s->mysql_vir_req_seq_diff = g_seq_omit;
#if (TCPCOPY_MYSQL_ADVANCED)
		if(sec_auth_packet){
			sec_ip_header = (struct iphdr*)copy_ip_packet(sec_auth_packet);
			sec_ip_header->saddr = f_ip_header->saddr;
			size_ip   = sec_ip_header->ihl << 2;
			sec_tcp_header = (struct tcphdr*)((char *)sec_ip_header + 
					size_ip);
			sec_cont_len = get_pack_cont_len(sec_ip_header, sec_tcp_header);
			sec_tcp_header->source = f_tcp_header->source;
			ln = link_node_malloc(sec_ip_header);
			ln->key = ntohl(sec_tcp_header->seq);
			link_list_order_append(s->unsend_packets, ln);
			log_info(LOG_NOTICE, "set second auth for non-skip");
		}else{
			log_info(LOG_WARN,"no sec auth packet here");
		}
#endif

#if (TCPCOPY_MYSQL_ADVANCED)
		total_cont_len = fir_cont_len + sec_cont_len;	
#else
		total_cont_len = fir_cont_len;
#endif

		list = (link_list *)hash_find(mysql_table, s->src_port);
		if(list){
			/* calculate the total content length */
			ln = link_list_first(list);	
			while(ln){
				data = ln->data;
				tmp_ip_header = (struct iphdr *)data;
				tmp_cont_len = get_pack_cont_len(tmp_ip_header, NULL);
				total_cont_len += tmp_cont_len;
				ln = link_list_get_next(list, ln);
			}
		}

#if (DEBUG_TCPCOPY)
		log_info(LOG_INFO,"total len subtracted:%u", total_cont_len);
#endif
		f_tcp_header->seq = htonl(ntohl(f_tcp_header->seq) - total_cont_len);
		fir_tcp_header->seq = plus_one(f_tcp_header->seq);
#if (TCPCOPY_MYSQL_ADVANCED)
		if(sec_tcp_header != NULL){
			sec_tcp_header->seq = htonl(ntohl(fir_tcp_header->seq)
					+ fir_cont_len);
		}
#endif
#if (TCPCOPY_MYSQL_ADVANCED)
		base_seq = ntohl(fir_tcp_header->seq) + fir_cont_len+sec_cont_len;
#else
		base_seq = ntohl(fir_tcp_header->seq) + fir_cont_len;
#endif
		if(list){
			/* insert prepare statements */
			ln = link_list_first(list);	
			while(ln){
				data = ln->data;
				tmp_ip_header  = (struct iphdr *)data;
				tmp_ip_header  = (struct iphdr*)copy_ip_packet(tmp_ip_header);
				tmp_tcp_header = (struct tcphdr*)((char *)tmp_ip_header
						+ size_ip); 
				tmp_cont_len   = get_pack_cont_len(tmp_ip_header, 
						tmp_tcp_header);
				tmp_tcp_header->seq = htonl(base_seq);
				tmp_ln = link_node_malloc(tmp_ip_header);
				ln->key = ntohl(tmp_tcp_header->seq);
				link_list_order_append(s->unsend_packets, tmp_ln);
				base_seq += tmp_cont_len;
				ln = link_list_get_next(list, ln);
			}
		}
	}else{
		log_info(LOG_WARN,"no first auth packets here");
	}
#endif

#if (DEBUG_TCPCOPY)
	strace_pack(LOG_DEBUG, FAKED_CLIENT_FLAG, f_ip_header, f_tcp_header);
#endif
	wrap_send_ip_packet(s, f_s_buf);
	s->req_halfway_intercepted = 1;
	s->resp_syn_received = 0;
}

/*
 * Send faked syn ack packet(the third handshake packet) to back from 
 * the client packet
 */
static void send_faked_third_handshake(session_t *s, 
		struct iphdr *ip_header, struct tcphdr *tcp_header)
{
	unsigned char fake_ack_buf[FAKE_ACK_BUF_SIZE];
	struct iphdr  *f_ip_header;
	struct tcphdr *f_tcp_header;
	p_link_node   ln;

	memset(fake_ack_buf, 0, FAKE_ACK_BUF_SIZE);
	f_ip_header  = (struct iphdr *)fake_ack_buf;
	f_tcp_header = (struct tcphdr *)(fake_ack_buf + FAKE_IP_HEADER_LEN);
#if (DEBUG_TCPCOPY)
	log_info(LOG_DEBUG,"send_faked_third_handshake:%u",s->src_port);
#endif
	f_ip_header->version  = 4;
	f_ip_header->ihl      = 5;
	f_ip_header->tot_len  = htons(FAKE_ACK_BUF_SIZE);
	f_ip_header->frag_off = 64; 
	f_ip_header->ttl      = 64; 
	f_ip_header->protocol = 6;
	f_ip_header->id       = htons(s->req_ip_id + 2);
	f_ip_header->saddr    = s->src_addr;
	/* here we must recored online ip address */
	f_ip_header->daddr    = s->online_addr; 
	f_tcp_header->doff    = 5;
	f_tcp_header->source  = tcp_header->dest;
	/* here we must recored online port */
	f_tcp_header->dest    = s->online_port;
	f_tcp_header->ack     = 1;
	f_tcp_header->ack_seq = s->vir_ack_seq;
	f_tcp_header->seq     = tcp_header->ack_seq;
	f_tcp_header->window  = 65535;
	
	ln = link_node_malloc(copy_ip_packet(f_ip_header));
	ln->key = ntohl(f_tcp_header->seq);
	link_list_order_append(s->handshake_packets, ln);

#if (DEBUG_TCPCOPY)
	strace_pack(LOG_DEBUG, FAKED_CLIENT_FLAG, f_ip_header, f_tcp_header);
#endif
	wrap_send_ip_packet(s, fake_ack_buf);
}

/*
 * Send faked ack packet to backend from the backend packet
 */
static void send_faked_ack(session_t *s , struct iphdr *ip_header, 
		struct tcphdr *tcp_header, int change_seq)
{
	unsigned char fake_ack_buf[FAKE_ACK_BUF_SIZE];
	struct iphdr  *f_ip_header;
	struct tcphdr *f_tcp_header;

	memset(fake_ack_buf, 0, FAKE_ACK_BUF_SIZE);
	f_ip_header  = (struct iphdr *)fake_ack_buf;
	f_tcp_header = (struct tcphdr *)(fake_ack_buf + FAKE_IP_HEADER_LEN);
	f_ip_header->version  = 4;
	f_ip_header->ihl      = 5;
	f_ip_header->tot_len  = htons(FAKE_ACK_BUF_SIZE);
	f_ip_header->frag_off = 64; 
	f_ip_header->ttl      = 64; 
	f_ip_header->protocol = 6;
	f_ip_header->id       = htons(s->req_ip_id + 2);
	f_ip_header->saddr    = ip_header->daddr;
	f_tcp_header->doff    = 5;
	f_tcp_header->source  = tcp_header->dest;
	f_tcp_header->ack     = 1;
	f_tcp_header->ack_seq = s->vir_ack_seq;
	if(change_seq){
		f_tcp_header->seq = htonl(s->vir_next_seq);
	}else{
		f_tcp_header->seq = tcp_header->ack_seq;
	}
	f_tcp_header->window  = 65535;
	wrap_send_ip_packet(s, fake_ack_buf);
}

/*
 * Send faked reset packet to backend from the backend packet
 */
static void send_faked_rst(session_t *s, 
		struct iphdr *ip_header, struct tcphdr *tcp_header)
{

	unsigned char faked_rst_buf[FAKE_ACK_BUF_SIZE];
	struct iphdr  *f_ip_header;
	struct tcphdr *f_tcp_header;
	uint16_t cont_len, tot_len;
	uint32_t next_ack, h_next_ack, expect_h_ack;

#if (DEBUG_TCPCOPY)
	log_info(LOG_DEBUG, "send faked rst To Back:%u", s->src_port);
#endif

	memset(faked_rst_buf, 0, FAKE_ACK_BUF_SIZE);
	f_ip_header  = (struct iphdr *)faked_rst_buf;
	f_tcp_header = (struct tcphdr *)(faked_rst_buf + FAKE_IP_HEADER_LEN);
	f_ip_header->version  = 4;
	f_ip_header->ihl      = 5;
	f_ip_header->tot_len  = htons(FAKE_ACK_BUF_SIZE);
	f_ip_header->frag_off = 64; 
	f_ip_header->ttl      = 64; 
	f_ip_header->protocol = 6;
	f_ip_header->id       = htons(s->req_ip_id + 2);
	f_ip_header->saddr    = ip_header->daddr;
	f_tcp_header->doff    = 5;
	f_tcp_header->source  = tcp_header->dest;
	f_tcp_header->rst     = 1;
	f_tcp_header->ack     = 1;
	s->reset      = 1;
	tot_len       = ntohs(ip_header->tot_len);
	cont_len      = get_pack_cont_len(ip_header,tcp_header);
	expect_h_ack  = ntohl(s->vir_ack_seq);
	next_ack      = tcp_header->seq;
	h_next_ack    = ntohl(next_ack);

	/* 
	 * The following logic is just from experience.
	 * Need to be optimized
	 */
	if(cont_len > 0){   
		h_next_ack  += tot_len;
		next_ack  = htonl(h_next_ack); 
		s->vir_ack_seq = next_ack;
	}else{
		if(s->src_closed && !s->dst_closed){
			if(h_next_ack > expect_h_ack){
				log_info(LOG_NOTICE, "set ack seq larger");
				s->vir_ack_seq = next_ack;
				s->dst_closed     = 1;
			}
		}
	}
	f_tcp_header->ack_seq = s->vir_ack_seq;
	f_tcp_header->seq = tcp_header->ack_seq;
	f_tcp_header->window = 65535;
	wrap_send_ip_packet(s, faked_rst_buf);
}

/*
 * Send faked rst packet to backend from the client packet
 */
static void send_faked_rst_by_client(session_t *s,
		struct iphdr *ip_header, struct tcphdr *tcp_header)
{
	unsigned char faked_rst_buf[FAKE_ACK_BUF_SIZE];
	struct iphdr  *f_ip_header;
	struct tcphdr *f_tcp_header;
#if (DEBUG_TCPCOPY)
	log_info(LOG_DEBUG, "send faked rst To back from clt pack:%u",
			s->src_port);
#endif
	memset(faked_rst_buf, 0, FAKE_ACK_BUF_SIZE);
	f_ip_header  = (struct iphdr *)faked_rst_buf;
	f_tcp_header = (struct tcphdr *)(faked_rst_buf + FAKE_IP_HEADER_LEN);
	f_ip_header->version  = 4;
	f_ip_header->ihl      = 5;
	f_ip_header->tot_len  = htons(FAKE_ACK_BUF_SIZE);
	f_ip_header->frag_off = 64; 
	f_ip_header->ttl      = 64; 
	f_ip_header->protocol = 6;
	f_ip_header->id       = htons(s->req_ip_id + 2);
	f_ip_header->saddr    = ip_header->saddr;
	f_tcp_header->doff    = 5;
	f_tcp_header->source  = tcp_header->source;
	f_tcp_header->fin     = 1;
	f_tcp_header->rst     = 1;
	f_tcp_header->ack     = 1;
	
	f_tcp_header->ack_seq = s->vir_ack_seq;
	if(s->fin_add_seq){
		/* this is because of '++' in wrap_send_ip_packet */
		f_tcp_header->seq = htonl(s->vir_next_seq - 1); 
	}else{
		f_tcp_header->seq = htonl(s->vir_next_seq); 
	}
	f_tcp_header->window  = 65535;
	wrap_send_ip_packet(s, faked_rst_buf);
}

/*
 * Fake the first handshake packet for intercepting already 
 * connected online packets
 */
static void fake_syn(session_t *s, struct iphdr *ip_header, 
		struct tcphdr *tcp_header)
{
	int sock, result;
#if (TCPCOPY_MYSQL_BASIC)
	log_info(LOG_WARN, "fake syn for halfway:%u", s->src_port);
#else
	log_info(LOG_DEBUG, "fake syn for halfway:%u", s->src_port);
#endif
	sock = address_find_sock(tcp_header->dest);
	if(-1 == sock)
	{
		log_info(LOG_WARN, "sock invalid in fake_syn");
		strace_pack(LOG_ERR, CLIENT_FLAG, ip_header, tcp_header);
		return;
	}
	result = msg_client_send(sock,ip_header->saddr,
			tcp_header->source, CLIENT_ADD);
	if(-1 == result)
	{
		log_info(LOG_ERR, "msg client send error");
		return;
	}
	send_faked_syn(s, ip_header, tcp_header);
	s->req_syn_ok = 1;
	recon_for_no_syn_cnt++;

}

/*
 * Try to fake syn packet to backend which is already closed
 * Attension:
 *   if the server does the active close,it lets the client
 *   continually reuse the same port number at each end for successive 
 *   incarnations of the same connection
 */
void fake_syn_hardly(session_t *s)
{
	unsigned char *data, *tmp_data;
	struct iphdr  *ip_header;
	struct tcphdr *tcp_header;
	p_link_node   ln, tmp_ln;
	int      size, sock, result;
	uint16_t size_ip;
	uint16_t dest_port; 
#if (DEBUG_TCPCOPY)
	log_info(LOG_NOTICE,"fake syn hardly:%u", s->src_port);
#endif
	size = s->handshake_packets->size;
	if(size != s->expected_handshake_pack_num){
		log_info(LOG_WARN, "hand Packets size not expected:%d,exp:%d",
				size, s->expected_handshake_pack_num);
	}else{
		ln   = link_list_first(s->handshake_packets);
		data = ln->data;
		ip_header  = (struct iphdr*)data;
		tmp_data   = copy_ip_packet(ip_header);
		ip_header  = (struct iphdr*)tmp_data;
		size_ip    = ip_header->ihl << 2;
		tcp_header = (struct tcphdr*)((char *)ip_header + size_ip);
		sock = address_find_sock(tcp_header->dest);
		if(-1 == sock)
		{
			free(tmp_data);
			log_info(LOG_ERR, "sock invalid in fake_syn_hardly");
#if (DEBUG_TCPCOPY)
			strace_pack(LOG_INFO,CLIENT_FLAG,ip_header,tcp_header);
#endif
			return;
		}
		dest_port = get_port_by_rand_addition(tcp_header->source);
#if (DEBUG_TCPCOPY)
		log_info(LOG_NOTICE, "change port from %u to %u",
				ntohs(tcp_header->source), dest_port);
#endif
		tcp_header->source = htons(dest_port);
		s->faked_src_port   = tcp_header->source;

		result = msg_client_send(sock, ip_header->saddr, 
				tcp_header->source, CLIENT_ADD);
		if(-1 == result)
		{
			free(tmp_data);
			log_info(LOG_ERR,"msg client send error");
			return;
		}
		wrap_send_ip_packet(s, data);
		s->req_syn_ok = 1;
		free(tmp_data);

		/* Push the remaining packets in handshakePackets to unsend */
		ln = link_list_get_next(s->handshake_packets, ln);
		while(ln)
		{
			data       = ln->data;
			ip_header  = (struct iphdr *) data;
			size_ip    = ip_header->ihl << 2;
			tcp_header =(struct tcphdr*)((char *)ip_header + size_ip);
			tcp_header->source = s->faked_src_port;
			tmp_ln = link_node_malloc(copy_ip_packet(ip_header));
			tmp_ln->key = ntohl(tcp_header->seq);
			link_list_order_append(s->unsend_packets, tmp_ln);
			ln =link_list_get_next(s->handshake_packets, ln);
		}
		recon_for_closed_cnt++;
	}
}

#if (TCPCOPY_MYSQL_BASIC)
/*
 * Check if the packet is needed for reconnection by mysql 
 */
int mysql_check_reconnection(session_t *s, struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
	unsigned char *payload, command;
	uint16_t      size_ip, size_tcp, tot_len, cont_len;
	p_link_node   ln;
	link_list     *list;

	size_ip   = ip_header->ihl << 2;
	size_tcp  = tcp_header->doff << 2;
	tot_len = ntohs(ip_header->tot_len);
	cont_len = tot_len - size_tcp - size_ip;

	if(cont_len > 0){
		payload = (unsigned char*)((char*)tcp_header + size_tcp);
		/* Skip Packet Length */
		payload = payload + 3;
		/* Skip Packet Number */
		payload = payload + 1;
		/* Get commmand */
		command = payload[0];
		if(COM_STMT_PREPARE == command ||
				(s->mysql_prepare_stat && s->mysql_first_excution)){
			if(COM_STMT_PREPARE == command){
				s->mysql_prepare_stat = 1;
			}else{
				if(COM_QUERY == command && s->mysql_prepare_stat){
					if(s->mysql_excute_times > 0){
						s->mysql_first_excution = 0;
					}
					s->mysql_excute_times++;
				}
				if(!s->mysql_first_excution){
					return 0;
				}
			}
			ln   = link_node_malloc(copy_ip_packet(ip_header));
			ln->key = ntohl(tcp_header->seq);
			link_list_order_append(s->mysql_special_packets, ln);

#if (DEBUG_TCPCOPY)
			log_info(LOG_NOTICE, "push back necc statement:%u", s->src_port);
#endif
			list = (link_list *)hash_find(mysql_table, s->src_port);
			if(!list){
				list = link_list_create();
				if(NULL == list)
				{
					log_info(LOG_ERR, "list create err");
					return 0;
				}else{
					hash_add(mysql_table, s->src_port, list);
				}
			}
			ln   = link_node_malloc(copy_ip_packet(ip_header));
			ln->key = ntohl(tcp_header->seq);
			link_list_order_append(list, ln);
			return 1;
		}
	}
	return 0;
}

/*
 * Check if the packet is the right packet for starting a new session 
 * by mysql tcpcopy
 */
static int check_mysql_padding(struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
	unsigned char *payload, *data, command, pack_number;
	uint16_t      size_ip, size_tcp, tot_len, cont_len;

	size_ip   = ip_header->ihl << 2;
	size_tcp  = tcp_header->doff << 2;
	tot_len = ntohs(ip_header->tot_len);
	cont_len = tot_len - size_tcp - size_ip;

	if(cont_len > 0){
		payload = (unsigned char*)((char*)tcp_header + size_tcp);
		/* Skip Packet Length */
		payload = payload + 3;
		/* Get packet number */
		pack_number = payload[0];
		/* If it is the second authenticate_user,then skip it */
		if(0 != pack_number){
			return 0;
		}
		/* Skip Packet Number */
		payload = payload + 1;
		command = payload[0];
		if(COM_QUERY == command){
			return 1;
		}
	}
	return 0;
}
#endif

/*
 * Check if the packet is the right packet for noraml copying
 */
static int check_padding(struct iphdr *ip_header, struct tcphdr *tcp_header)
{
	uint16_t  cont_len;

	cont_len = get_pack_cont_len(ip_header, tcp_header);

	if( cont_len > 0){
		return 1;
	}
	return 0;

}

/* Check ack from backend */
static int check_backend_ack(session_t *s,struct iphdr *ip_header,
		 struct tcphdr *tcp_header, uint32_t ack, uint16_t cont_len)
{
	/* if ack from test server is more than what we expect */
	if(ack > s->vir_next_seq)
	{
#if (DEBUG_TCPCOPY)
		log_info(LOG_INFO, "bak ack more than vir_next_seq:%u,%u,p:%u",
				ack, s->vir_next_seq, s->src_port);
#endif
		if(!s->resp_syn_received){
#if (DEBUG_TCPCOPY)
			log_info(LOG_NOTICE,"not recv back syn,p:%u", s->src_port);
#endif
			s->reset = 1;
			return DISP_STOP;
		}
		s->vir_next_seq = ack;
	}else if(ack < s->vir_next_seq){
		/* if ack from test server is less than what we expect */
#if (DEBUG_TCPCOPY)
		log_info(LOG_INFO, "bak ack less than vir_next_seq:%u,%u, p:%u",
				ack, s->vir_next_seq, s->src_port);
#endif
		if(!s->resp_syn_received){
			send_faked_rst(s, ip_header, tcp_header);
			s->faked_rst_sent = 1;
			s->src_closed = 1;
			return DISP_STOP;
		}
		if(s->src_closed && !tcp_header->fin){
			send_faked_rst(s, ip_header, tcp_header);
			return DISP_STOP;
		}else{
			/* simulaneous close */
			if(s->src_closed && tcp_header->fin){
				s->simul_closing = 1;
			}
		}
		/* when the slide window in test server is full*/
		if(0 == tcp_header->window){
			log_info(LOG_NOTICE, "slide window is zero now");
			s->resp_last_ack_seq = ack;
			update_retransmission_packets(s);
			return DISP_STOP;
		}

		/* Check if it needs retransmission */
		if(0 == cont_len && !tcp_header->fin){
			if(s->resp_last_ack_seq != 0){
				if(ack == s->resp_last_ack_seq){
					s->resp_last_same_ack_num++;
					if(s->resp_last_same_ack_num > 1){
						/* It needs retransmission */
						log_info(LOG_WARN,"bak lost packs:%u", s->src_port);
						if(!s->vir_already_retransmit){
							if(!retransmit_packets(s)){
								/* Retransmit failure */
								send_faked_rst(s, ip_header, tcp_header);
								s->faked_rst_sent = 1;
								s->src_closed = 1;
							}
							s->vir_already_retransmit = 1;
						}else{
							log_info(LOG_WARN, "omit retransmit:%u", 
									s->src_port);
						}
						return DISP_STOP;
					}
				}else{
					s->resp_last_same_ack_num = 0;
					s->vir_already_retransmit = 0;
				}
			}
		}
	}
	return DISP_CONTINUE;
}

static void process_back_syn_pack(session_t *s, struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
	if(s->resp_syn_received){
#if (DEBUG_TCPCOPY)
		log_info(LOG_DEBUG,"recv syn from back again");
#endif
	}else{
		conn_cnt++;
		s->resp_syn_received = 1;
#if (DEBUG_TCPCOPY)
		log_info(LOG_DEBUG,"recv syn from back:%u", s->src_port);
#endif
	}
	s->vir_ack_seq = plus_one(tcp_header->seq);
	s->status = SYN_CONFIRM;
	if(s->req_halfway_intercepted){
		send_faked_third_handshake(s, ip_header, tcp_header);
		send_reserved_packets(s);
	}else{
		send_reserved_packets(s);
	}
}

static void process_back_fin_pack(session_t *s, struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
#if (DEBUG_TCPCOPY)
	log_info(LOG_INFO,"recv fin from back:%u", s->src_port);
#endif
	s->dst_closed = 1;
	s->candidate_response_waiting = 0;
	s->status  |= SERVER_FIN;
	send_faked_ack(s, ip_header, tcp_header, s->simul_closing);
	if(!s->src_closed){
		/* Send the constructed reset packet to backend */
		send_faked_rst(s, ip_header, tcp_header);
		s->faked_rst_sent  = 1;
		s->status |= CLIENT_FIN;
	}else
	{
		s->sess_over = 1;
	}

}

#if (TCPCOPY_MYSQL_BASIC)
static int mysql_process_greet(session_t *s, struct iphdr *ip_header,
		struct tcphdr *tcp_header, uint16_t cont_len, int *is_greet)
{
	int           ret; 
#if (TCPCOPY_MYSQL_ADVANCED)
	unsigned char *payload;
#endif
	if(!s->mysql_resp_greet_received){
		/* this is just a guess */
		log_info(LOG_NOTICE, "recv greeting from back");
		s->mysql_cont_num_aft_greet  = 0;
		s->mysql_resp_greet_received = 1;
		*is_greet= 1;
#if (TCPCOPY_MYSQL_ADVANCED) 
		payload =(unsigned char*)((char*)tcp_header + sizeof(struct tcphdr));
		memset(s->mysql_scramble, 0, SCRAMBLE_LENGTH + 1);
		ret = parse_handshake_init_cont(payload, cont_len, s->mysql_scramble);
		log_info(LOG_WARN, "scram:%s,p:%u", s->mysql_scramble, s->src_port);
		if(!ret){
			/* Try to print error info*/
			if(cont_len > 11){
				strace_pack(LOG_WARN, BACKEND_FLAG, 
						ip_header, tcp_header);
				log_info(LOG_WARN, "port:%u,payload:%s",
						s->src_port, (char*)(payload + 11));
			}
			s->sess_over = 1;
			return DISP_STOP;
		}
#endif
	}else{
#if (TCPCOPY_MYSQL_ADVANCED) 
		if(0 == s->mysql_cont_num_aft_greet){
			log_info(LOG_NOTICE, "check if it needs second auth");
			payload = (unsigned char*)((char*)tcp_header + 
					sizeof(struct tcphdr));
			/* 
			 * If it is the last data packet, 
			 * then it means it needs sec auth
			 */
			if(is_last_data_packet(payload)){
				strace_pack(LOG_WARN, BACKEND_FLAG,
						ip_header, tcp_header);
				log_info(LOG_WARN, "it needs sec auth:%u", s->src_port);
				s->mysql_sec_auth = 1;
			}
		}
#endif
		s->mysql_cont_num_aft_greet++;
	}
	return DISP_CONTINUE;

}
#endif

/*
 * Processing backend packets
 */
void update_virtual_status(session_t *s, struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
	uint16_t      size_ip, size_tcp, tot_len, cont_len;
	uint32_t      ack;
	time_t        current;
#if (TCPCOPY_MYSQL_BASIC)
	int           is_greet= 0; 
#endif

    resp_cnt++;
#if (DEBUG_TCPCOPY)
	strace_pack(LOG_DEBUG, BACKEND_FLAG, ip_header, tcp_header);
#endif

	/* When meeting reset, it means the session is over */
	if( tcp_header->rst){
		s->reset = 1;
#if (DEBUG_TCPCOPY)
		log_info(LOG_INFO, "reset from backend:%u", s->src_port);
#endif
		return;
	}

	/* Retrieve packet info */
	ack       = ntohl(tcp_header->ack_seq);
	tot_len   = ntohs(ip_header->tot_len);
	size_ip   = ip_header->ihl << 2;
	size_tcp  = tcp_header->doff << 2;
	cont_len = tot_len - size_tcp - size_ip;

	current=time(0);

	if(cont_len > 0){
		/* calculate the total successful retransmissson */
		if(s->vir_new_retransmit){
			retrans_succ_cnt++;
			s->vir_new_retransmit = 0;
		}
		resp_cont_cnt++;
		s->resp_last_recv_cont_time = current;
		s->vir_ack_seq = htonl(ntohl(tcp_header->seq) + cont_len + 1);
	}else{
		s->vir_ack_seq = tcp_header->ack_seq;
	}
	/* Needs to check ack */
	if(check_backend_ack(s, ip_header, tcp_header, ack,  cont_len) 
			== DISP_STOP){
		s->resp_last_ack_seq = ack;
		return;
	}
	s->resp_last_ack_seq = ack;
	/* Update session's retransmisson packets */
	update_retransmission_packets(s);

	/*
	 * Process syn, fin or ack packet here
	 */
	if( tcp_header->syn){
		/* Process syn packet */
		process_back_syn_pack(s, ip_header, tcp_header);
		return;
	}else if(tcp_header->fin){
		/* Process fin packet */
		process_back_fin_pack(s, ip_header, tcp_header);
		return;
	}else if(tcp_header->ack){
		/* Process ack packet */
		if(s->src_closed && s->dst_closed){
			s->sess_over = 1;
			return;
		}
	}

	/* We don't know if it will come here */
	if(!s->resp_syn_received)
	{
		log_info(LOG_NOTICE,"unbelievable");
		/* Try to solve backend's obstacle */
		s->vir_ack_seq = tcp_header->seq;
		send_faked_rst(s, ip_header, tcp_header);
		s->faked_rst_sent = 1;
		s->src_closed     = 1;
		return;
	}
	
	/* 
	 * it is nontrivial to check if the packet is the last packet 
	 * of the response
	 */
	if(cont_len > 0){
		if(s->src_closed){
			/* Try to solve the obstacle */ 
			send_faked_rst(s, ip_header, tcp_header);
			return;
		}
		if(!s->sess_candidate_erased){
#if (TCPCOPY_MYSQL_BASIC)
			if(DISP_STOP == mysql_process_greet(s, ip_header, 
						tcp_header, cont_len, &is_greet)){
				return;
			}
			if(s->candidate_response_waiting || is_greet){
#else
			if(s->candidate_response_waiting){
#endif
#if (DEBUG_TCPCOPY)
				log_info(LOG_DEBUG,"receive back server's resp");
#endif
				s->candidate_response_waiting = 0;
				s->status = RECV_RESP;
				send_reserved_packets(s);
				return;
			}
		}
	}else{
		/* There are no content in packet */
		if(s->src_closed && !s->dst_closed){
			send_faked_rst(s, ip_header, tcp_header);
			return;
		}
	}

	if(s->sess_candidate_erased){
		/* Do a violent close to backend */
		if(!s->src_closed){
#if (DEBUG_TCPCOPY)
			log_info(LOG_INFO,"candidate erased true:%u", s->src_port);
#endif
			/* Send the faked reset packet to backend */
			send_faked_rst(s, ip_header, tcp_header);
			s->faked_rst_sent = 1;
			s->src_closed = 1;
		}
	}
}

static int check_syn_retransmisson(session_t *s, 
		struct iphdr *ip_header, struct tcphdr *tcp_header)
{
	p_link_node ln;
	time_t      now = time(0);
	int         diff = now - s->create_time;
	if(diff > 3){
		/* retransmit the first syn packet */
		retransmit_packets(s);
		s->create_time = now;
		ln = link_node_malloc(copy_ip_packet(ip_header));
		ln->key = ntohl(tcp_header->seq);
		link_list_order_append(s->unsend_packets, ln);
		return DISP_STOP;
	}
	return DISP_CONTINUE;
}

static int process_client_rst(session_t *s, struct iphdr *ip_header,
		struct tcphdr *tcp_header)	
{
	p_link_node ln;
#if (DEBUG_TCPCOPY)
	log_info(LOG_INFO, "reset from client");
#endif
	if(s->candidate_response_waiting){
		ln = link_node_malloc(copy_ip_packet(ip_header));
		ln->key = ntohl(tcp_header->seq);
		link_list_order_append(s->unsend_packets, ln);
	}else{
		wrap_send_ip_packet(s,(unsigned char *) ip_header);
		s->reset = 1;
	}
	return DISP_CONTINUE;
}

static void process_client_syn(session_t *s, struct iphdr *ip_header,
		struct tcphdr *tcp_header)	
{
	link_list     *list;
	p_link_node   ln, tmp_ln;

	s->req_syn_ok = 1;

#if (DEBUG_TCPCOPY)
	log_info(LOG_INFO, "syn port:%u", s->src_port);
#endif

#if (TCPCOPY_MYSQL_BASIC)
	/* remove old mysql info*/
	list = (link_list *)hash_find(mysql_table, s->src_port);
	if(!list){
		ln = link_list_first(list);	
		while(ln){
			tmp_ln = ln;
			ln = link_list_get_next(list, ln);
			link_list_remove(list, tmp_ln);
			free(tmp_ln->data);
		}
	}
	hash_del(mysql_table, s->src_port);
#endif
	ln = link_node_malloc(copy_ip_packet(ip_header));
	ln->key = ntohl(tcp_header->seq);
	link_list_order_append(s->handshake_packets, ln);
	wrap_send_ip_packet(s,(unsigned char *)ip_header);

}

static int process_client_fin(session_t *s, struct iphdr *ip_header,
		struct tcphdr *tcp_header, uint16_t cont_len)	
{
	link_list     *list;
	p_link_node   ln, tmp_ln;

#if (DEBUG_TCPCOPY)
	log_info(LOG_DEBUG, "recv fin packet from clt");
#endif

	if(cont_len>0){
#if (DEBUG_TCPCOPY)
		log_info(LOG_INFO, "fin has content");
#endif
		return DISP_CONTINUE;
	}
	if(s->faked_rst_sent){
		return DISP_STOP;
	}

	/* practical experience */
	if(s->resp_last_ack_seq == tcp_header->seq){
		if(s->candidate_response_waiting){
			ln = link_node_malloc(copy_ip_packet(ip_header));
			ln->key = ntohl(tcp_header->seq);
			link_list_order_append(s->unsend_packets, ln);
		}else{
			wrap_send_ip_packet(s, (unsigned char *)ip_header);
			s->status |= CLIENT_FIN;
			s->src_closed=1;
		}
	}else{
		ln = link_node_malloc(copy_ip_packet(ip_header));
		ln->key = ntohl(tcp_header->seq);
		link_list_order_append(s->unsend_packets, ln);
		if(check_dead_reqs(s))
		{
			send_reserved_packets(s);
		}
	}
	return DISP_STOP;
}

#if (TCPCOPY_MYSQL_BASIC)
static int process_mysql_clt_half_bf_greet(session_t *s, 
		struct iphdr *ip_header, struct tcphdr *tcp_header)	
{
	p_link_node   ln;

	if(s->req_syn_ok){
		if(!s->mysql_resp_greet_received && s->req_halfway_intercepted){
			ln = link_node_malloc(copy_ip_packet(ip_header));
			ln->key = ntohl(tcp_header->seq);
			link_list_order_append(s->unsend_packets, ln);
			return DISP_STOP;
		}
	}

}

static int process_mysql_clt_auth_pack(session_t *s, 
		struct iphdr *ip_header, struct tcphdr *tcp_header, 
		uint16_t cont_len)	
{	
	unsigned char *payload;
	link_list     *list;
	p_link_node   ln;
	int           is_need_omit = 0;
	if(!s->req_halfway_intercepted)
	{
#if (TCPCOPY_MYSQL_ADVANCED)
		if(s->mysql_resp_greet_received){
			if(FAILURE == mysql_dispose_auth(s, ip_header, tcp_header)){
				return DISP_STOP;
			}
		}
#endif
#if (!TCPCOPY_MYSQL_ADVANCED)
		if(!s->mysql_req_begin)
		{
			/*
			 * Check if mysql protocol validation ends? 
			 */
			payload =(unsigned char*)((char*)tcp_header + size_tcp);
			/* Skip Packet Length */
			payload = payload + 3;
			pack_number = payload[0];
			/* If it is the second authenticate_user,then skip it */
			if(3 == pack_number)
			{
				is_need_omit = 1;
				s->mysql_req_begin = 1;
				log_info(LOG_NOTICE, "this is the sec auth packet");
			}
			if(0 == pack_number)
			{
				s->mysql_req_begin = 1;
				log_info(LOG_NOTICE, "it has no sec auth packet");
			}
		}
#else
		s->mysql_req_begin = 1;
#endif
		if(is_need_omit)
		{
			log_info(LOG_NOTICE, "omit sec validation for mysql");
			s->mysql_vir_req_seq_diff = cont_len;
			g_seq_omit = s->mysql_vir_req_seq_diff;
			return DISP_STOP;
		}
		if(!s->mysql_req_begin)
		{
			s->expected_handshake_pack_num++;
			ln = link_node_malloc(copy_ip_packet(ip_header));
			ln->key = ntohl(tcp_header->seq);
			link_list_order_append(s->handshake_packets, ln);
			if(!fir_auth_u_p){
				fir_auth_u_p = (struct iphdr*)copy_ip_packet(ip_header);
			}
			if(s->mysql_resp_greet_received){
				s->mysql_req_login_received = 1;
			}else{
				if(!s->mysql_req_login_received){
					s->mysql_req_login_received = 1;
					ln = link_node_malloc(copy_ip_packet(ip_header));
					ln->key = ntohl(tcp_header->seq);
					link_list_order_append(s->unsend_packets, ln);
					return DISP_STOP;
				}
			}
		}
		mysql_check_reconnection(s, ip_header, tcp_header);
		if(!s->mysql_resp_greet_received)
		{
			ln = link_node_malloc(copy_ip_packet(ip_header));
			ln->key = ntohl(tcp_header->seq);
			link_list_order_append(s->unsend_packets, ln);
			return DISP_STOP;
		}
	}
	return DISP_CONTINUE;
}
#endif

static int process_client_timeout(session_t *s)
{
	int    diff;
	time_t now = time(0);
	if(!s->candidate_response_waiting){
		return DISP_CONTINUE;
	}
	diff = now - s->req_last_send_cont_time;
	if(diff < 300){
		return DISP_CONTINUE;
	}
	/* 
	 * if the sesssion recv no response 
	 * for more than 5 min,then enter 
	 * the suicide process
	 */
	log_info(LOG_WARN,"300 timeout,no resp back,p:%u", s->src_port);
	if(s->unsend_packets->size > 512)
	{
		log_info(LOG_WARN, "it may lose packets,p:%u", s->src_port);
		s->sess_over = 1;
		return DISP_STOP;
	}
	return DISP_CONTINUE;
}

static void wait_for_backend_syn(session_t *s, struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{		
	p_link_node ln;
	if(!s->req_halfway_intercepted &&
			s->handshake_packets->size< s->expected_handshake_pack_num)
	{
#if (DEBUG_TCPCOPY)
		log_info(LOG_DEBUG, "buffer the handshake packet");
#endif
		ln = link_node_malloc(copy_ip_packet(ip_header));
		ln->key = ntohl(tcp_header->seq);
		link_list_order_append(s->handshake_packets, ln);
	}
	/* when clt sends multi-packs more quickly than the local network */
	ln = link_node_malloc(copy_ip_packet(ip_header));
	ln->key = ntohl(tcp_header->seq);
	link_list_order_append(s->unsend_packets, ln);
}

static void proc_clt_cont_when_bak_closed(session_t *s,
		struct iphdr *ip_header, struct tcphdr *tcp_header)
{		
	p_link_node ln;
	/* 
	 * when  the connection to the backend is closed, we 
	 * reestablish the connection and 
	 * we reserve all comming packets for later disposure
	 */
#if (TCPCOPY_MYSQL_BASIC)
	if(check_mysql_padding(ip_header, tcp_header)){
		session_init(s, 1);
		fake_syn(s, ip_header, tcp_header);
	}else{
		return;
	}
#else
	session_init(s,1);
	fake_syn_hardly(s);
#endif
	ln = link_node_malloc(copy_ip_packet(ip_header));
	ln->key = ntohl(tcp_header->seq);
	link_list_order_append(s->unsend_packets, ln);

}

/* Check the current packet will be saved or not */
static int check_pack_save_or_not(session_t *s, struct iphdr *ip_header,
		struct tcphdr *tcp_header, int *is_new_req)
{
	int         is_save = 0;
	uint32_t    tmp_last_ack, cur_seq;
	p_link_node ln;

	*is_new_req = 0;
	tmp_last_ack = s->req_cont_last_ack_seq;
	s->req_cont_last_ack_seq = ntohl(tcp_header->ack_seq);
	/*
	 * If the ack seq of the last cont packet is not equal to 
	 * it of the current content packet, then the current packet is 
	 * the packet of the new request.
	 * Attension:
	 *   the last content packet may not be sent to backend
	 */
	if(s->req_cont_last_ack_seq != tmp_last_ack){
		*is_new_req   = 1;
	}

	if(*is_new_req){
		cur_seq = ntohl(tcp_header->seq);
		is_save = check_seq_valid(cur_seq, s->req_last_cont_sent_seq);
	}else{
		if(s->unsend_packets->size > 0){
			if(check_reserved_content_left(s)){
				is_save = 1;
			}
		}
	}
	if(is_save){
		ln = link_node_malloc(copy_ip_packet(ip_header));
		ln->key = ntohl(tcp_header->seq);
		link_list_order_append(s->unsend_packets, ln);
		if(check_dead_reqs(s)){
			send_reserved_packets(s);
		}
		return DISP_STOP;
	}else{
		return DISP_CONTINUE;
	}
}

static int check_wait_prev_packet(session_t *s, 
		struct iphdr *ip_header, struct tcphdr *tcp_header)
{
	p_link_node ln;

	if(check_packet_lost(s, ip_header, tcp_header)){
		if(check_reserved_content_left(s)){
			ln = link_node_malloc(copy_ip_packet(ip_header));
			ln->key = ntohl(tcp_header->seq);
			link_list_order_append(s->unsend_packets, ln);
			return DISP_STOP;
		}
		ln = link_node_malloc(copy_ip_packet(ip_header));
		ln->key = ntohl(tcp_header->seq);
		link_list_order_append(s->lost_packets, ln);
#if (DEBUG_TCPCOPY)
		log_info(LOG_NOTICE,"lost and need previous packet");
#endif
		s->previous_packet_waiting = 1;
		return DISP_STOP;
	}
	if(s->previous_packet_waiting)
	{
		wrap_send_ip_packet(s,(unsigned char *)ip_header);
		send_reserved_lost_packets(s);
		s->candidate_response_waiting = 1;
		return DISP_STOP;
	}
	return DISP_CONTINUE;
}

static int is_continuous_packet(session_t *s, struct iphdr *ip_header,
		struct tcphdr *tcp_header, int is_new_req)
{
	uint32_t cur_seq = ntohl(tcp_header->seq);
	if(s->candidate_response_waiting){
		if(check_seq_valid(cur_seq, s->req_last_cont_sent_seq)){
			if(!is_new_req){
				wrap_send_ip_packet(s, (unsigned char *)ip_header);
#if (DEBUG_TCPCOPY)
				log_info(LOG_DEBUG, "it is a continuous req");
#endif
				return DISP_STOP;
			}
		}
	}
	return DISP_CONTINUE;
}

static int check_conn_keepalive(session_t *s)
{
	s->req_proccessed_num++;
	if(s->req_proccessed_num > 30)
	{
		s->conn_keepalive  = 1;
		s->req_proccessed_num = 0;
	}
	return s->conn_keepalive;
}

/* Process client packet info after the main processing */
static void process_client_after_main_body(session_t *s, 
		struct iphdr *ip_header, struct tcphdr *tcp_header)
{
	p_link_node ln;

	if(s->candidate_response_waiting)
	{
		ln = link_node_malloc(copy_ip_packet(ip_header));
		ln->key = ntohl(tcp_header->seq);
		link_list_order_append(s->unsend_packets, ln);
#if (DEBUG_TCPCOPY)
		log_info(LOG_DEBUG, "strange here,wait backend's response");
#endif
		if(check_dead_reqs(s)){
			send_reserved_packets(s);
		}
	}else{
		if(s->src_closed){
			ln = link_node_malloc(copy_ip_packet(ip_header));
			ln->key = ntohl(tcp_header->seq);
			link_list_order_append(s->unsend_packets, ln);
#if (DEBUG_TCPCOPY)
			log_info(LOG_DEBUG, "save client ack for server fin");
#endif
			if(check_dead_reqs(s)){
				send_reserved_packets(s);
			}
		}else{
			if(SEND_REQUEST == s->status){
				s->candidate_response_waiting = 1;
			}
			if(0 == s->unsend_packets->size){
				wrap_send_ip_packet(s, (unsigned char *)ip_header);
			}else{
				log_info(LOG_NOTICE, "strange,it comes here");
				ln = link_node_malloc(copy_ip_packet(ip_header));
				ln->key = ntohl(tcp_header->seq);
				link_list_order_append(s->unsend_packets, ln);
			}
		}
	}
}


/*
 * Processing client packets
 * TODO
 * TCP is always allowed to send 1 byte of data 
 * beyond the end of a closed window which confuses tcpcopy.
 * It will be resolved later
 * 
 */
void process_recv(session_t *s, struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
	int           diff, is_save = 0, is_new_req;
	uint16_t      cont_len;
	p_link_node   ln ;

	clt_cnt++;
	s->src_port = ntohs(tcp_header->source);
#if (DEBUG_TCPCOPY)
	strace_pack(LOG_DEBUG, CLIENT_FLAG, ip_header, tcp_header);
#endif	
	/* Change source port for multiple copying,etc */
	if(s->faked_src_port != 0){
		tcp_header->source = s->faked_src_port;
	}

#if (TCPCOPY_MYSQL_BASIC)
	/* subtract client packet's seq for mysql */
	if(s->mysql_req_begin){
		tcp_header->seq = htonl(ntohl(tcp_header->seq) - 
				s->mysql_vir_req_seq_diff);
	}
#endif

	/* If the packet is the next session's packet */
	if(s->sess_more){
		/* TODO Some statitics are not right because of this */
		ln = link_node_malloc(copy_ip_packet(ip_header));
		ln->key = ntohl(tcp_header->seq);
		link_list_order_append(s->next_session_packets, ln);
#if (DEBUG_TCPCOPY)
		log_info(LOG_INFO,"buffer for next session:%u", s->src_port);
#endif
		return;
	}

	/* Retrieve the content length of tcp payload */
	cont_len = get_pack_cont_len(ip_header, tcp_header);

	s->online_addr  = ip_header->daddr;
	s->online_port  = tcp_header->dest;
	s->req_ip_id = ip_header->id;

	/* Syn packet has been sent to back,but not recv back's syn */
	if(SYN_SENT == s->status){
		/* Check if it needs to retransmit the syn packet */
		if(DISP_STOP == check_syn_retransmisson(s, 
					ip_header, tcp_header)){
			return;
		}
		wait_for_backend_syn(s, ip_header, tcp_header);
		return;
	}

	/* Check if it needs sending rst pack to backend */
	if(s->sess_candidate_erased){
		if(!s->src_closed){
			s->src_closed=1;
		}
		send_faked_rst_by_client(s, ip_header, tcp_header);
		return;
	}

	/* Process the reset packet */
	if(tcp_header->rst){
		process_client_rst(s, ip_header, tcp_header);
		return;
	}
	/* Process the syn packet */
	if(tcp_header->syn){
		process_client_syn(s, ip_header, tcp_header);
		return;
	}
	/* Process the fin packet */
	if(tcp_header->fin)
	{
		if(DISP_STOP == process_client_fin(s, ip_header, 
					tcp_header, cont_len)){
			return;
		}
	}

	/* If not receiving syn packet */ 
	if(!s->req_syn_ok){
		s->req_halfway_intercepted=1;
		fake_syn(s, ip_header, tcp_header);
		ln = link_node_malloc(copy_ip_packet(ip_header));
		ln->key = ntohl(tcp_header->seq);
		link_list_order_append(s->unsend_packets, ln);
		return;
	}
#if (TCPCOPY_MYSQL_BASIC)
	/* process mysql client halfway packet before receiving greet */
	if(DISP_STOP == process_mysql_clt_half_bf_greet(s, 
				ip_header, tcp_header)){
		return;
	}
#endif
	if(cont_len > 0){
#if (TCPCOPY_MYSQL_BASIC)
		/* process mysql client auth packet */
		if(DISP_STOP == process_mysql_clt_auth_pack(s, ip_header, 
					tcp_header, cont_len)){
			return;
		}
#endif
		/* Check if current session is timeout */
		if(DISP_STOP == process_client_timeout(s)){
			return;
		}
		if(s->dst_closed){
			/* When backend is closed */
			proc_clt_cont_when_bak_closed(s, ip_header, tcp_header);
			return;
		}
		/* Check if it is a retransmission packet */
		if(check_retransmission(tcp_header, s->req_last_cont_sent_seq)){
#if (DEBUG_TCPCOPY)
			log_info(LOG_DEBUG," a retransmission packet from client");
#endif
			return;
		}

		/* Check if the packet is to be saved for later use */
		if(s->candidate_response_waiting){
			if(DISP_STOP == check_pack_save_or_not(s, 
						ip_header, tcp_header, &is_new_req)){
				return;
			}
		}
		/* Check if current session need to wait prevous packet */
		if(DISP_STOP == check_wait_prev_packet(s, 
					ip_header, tcp_header)){
			return;
		}
		/* Check if it is a continuous packet */
		if(DISP_STOP == is_continuous_packet(s, ip_header, 
					tcp_header, is_new_req)){
			return;
		}
		s->status = SEND_REQUEST;
		/* Check if the current session is keepalive */
		check_conn_keepalive(s);
#if (DEBUG_TCPCOPY)
		log_info(LOG_DEBUG,"a new request from client");
#endif
	}else if(!s->req_halfway_intercepted){
		/* If the 3-way handshake is not completed */
		if(s->handshake_packets->size < s->expected_handshake_pack_num){
			ln = link_node_malloc(copy_ip_packet(ip_header));
			ln->key = ntohl(tcp_header->seq);
			link_list_order_append(s->handshake_packets, ln);
		}
	}
	/* post disposure*/
	process_client_after_main_body(s, ip_header, tcp_header);
}

void restore_buffered_next_session(session_t *s)
{
    p_link_node   ln;
	unsigned char *data;
	struct iphdr  *ip_header;
	struct tcphdr *tcp_header;
	uint16_t      size_ip;

	ln     = link_list_first(s->unsend_packets);	
	data   = (unsigned char*)ln->data;
	link_list_remove(s->unsend_packets, ln);
	ip_header  =(struct iphdr*)((char*)data);
	size_ip    = ip_header->ihl << 2;
	tcp_header = (struct tcphdr*)((char *)ip_header + size_ip);

	process_recv(s, ip_header,tcp_header);

	free(data);
}

/*
 * Filter packets 
 */
int is_packet_needed(const char *packet)
{
	int           isNeeded = 0;
	struct tcphdr *tcp_header;
	struct iphdr  *ip_header;
	uint16_t      size_ip, size_tcp, tot_len;

	ip_header = (struct iphdr*)packet;

	/* check if it is a tcp packet */
	if(ip_header->protocol != IPPROTO_TCP)
	{
		return isNeeded;
	}

	size_ip   = ip_header->ihl << 2;
	tot_len =ntohs(ip_header->tot_len);
	if (size_ip < 20) {
		log_info(LOG_WARN, "Invalid IP header length: %d", size_ip);
		return isNeeded;
	}

	tcp_header = (struct tcphdr*)((char *)ip_header + size_ip);
	size_tcp   = tcp_header->doff << 2;
	if (size_tcp < 20) {
		log_info(LOG_WARN,"Invalid TCP header len: %d bytes,pack len:%d",
				size_tcp, tot_len);
		return isNeeded;
	}

	/* Here we filter the packets we do care about */
	if(check_pack_src(&(clt_settings.transfer), 
				ip_header->daddr, tcp_header->dest))
	{
		isNeeded = 1;
		if(tcp_header->syn)
		{
			clt_syn_cnt++;
		}
		clt_packs_cnt++;
	}

	return isNeeded;

}

/* Output statistics */
static void output_stat(time_t now, int run_time)
{
	double         ratio;
	last_stat_time = now;
	log_info(LOG_WARN,
			"active:%llu,total syns:%llu,rel reqs:%llu,obs del:%llu",
			enter_cnt - leave_cnt, enter_cnt, leave_cnt, obs_cnt);
	log_info(LOG_WARN,
			"total conns:%llu,total resp packs:%llu,c-resp packs:%llu",
			conn_cnt, resp_cnt, resp_cont_cnt);
	if(resp_cnt > 0)
	{
		log_info(LOG_WARN, "resp_cnt:%llu,resp_disp_t:%f,avg=%f",
				resp_cnt, resp_disp_t, resp_disp_t/resp_cnt);
	}
	log_info(LOG_WARN, "clt_cnt:%llu,clt_disp_t:%f,avg=%f",
			clt_cnt, clt_disp_t, clt_disp_t/clt_cnt);
	log_info(LOG_WARN, "send Packets:%llu,send content packets:%llu",
			packs_sent_cnt, con_packs_sent_cnt);
	log_info(LOG_NOTICE,
			"total reconnect for closed :%llu,for no syn:%llu",
			recon_for_closed_cnt, recon_for_no_syn_cnt);
	log_info(LOG_NOTICE, "total successful retransmit:%llu",
			retrans_succ_cnt);
	log_info(LOG_NOTICE, "syn total:%llu,all client packets:%llu",
			clt_syn_cnt, clt_packs_cnt);

	/* This is for checking memory leak */
	clear_timeout_sessions();

	if(run_time > 3){
		if(0 == resp_cont_cnt){
			log_info(LOG_WARN, "no responses after %d secends", 
					run_time);
		}
		if(enter_cnt > 0){
			ratio = 100*conn_cnt/enter_cnt;
			if(ratio < 80){
				log_info(LOG_WARN, 
						"many connections can't be established");
			}
		}
	}
}

/*
 * The main procedure for processing the filtered packets
 */
void process(char *packet)
{
	struct tcphdr  *tcp_header;
	struct iphdr   *ip_header;
	uint16_t       size_ip, size_tcp, tot_len;
	uint64_t       key;
	time_t         now  = time(0);
	int            diff, run_time = 0, sock, ret;
	p_link_node    ln, tmp_ln;
	session_t      *s;
	ip_port_pair_mappings_t *tf;

	if(0 == start_p_time){
		start_p_time = now;
	}else{
		run_time = now -start_p_time;
	}
	diff = now - last_stat_time;
	if(diff > 10){
		/* Output statistics */
		output_stat(now, run_time);
	}
	if(last_ch_dead_sess_time > 0){
		/* Check dead session */
		diff = now - last_ch_dead_sess_time;
		if(diff > 2){
			if(sessions_table->total > 0){
				activate_dead_sessions();
				last_ch_dead_sess_time = now;
			}
		}
	}

	ip_header  = (struct iphdr*)packet;
	size_ip    = ip_header->ihl<<2;
	tcp_header = (struct tcphdr*)((char *)ip_header + size_ip);
	tf         = &(clt_settings.transfer);

	if(check_pack_src(tf, ip_header->saddr, tcp_header->source) == REMOTE){
		/* When the packet comes from the targeted test machine */
		key = get_ip_port_value(ip_header->daddr, tcp_header->dest);
		ln  = hash_find(sessions_table, key);
		if(ln){
			s = (session_t *)ln->data;
			s->last_update_time = now;
			update_virtual_status(s, ip_header, tcp_header);
			if(check_session_over(s)){
				if(s->sess_more){
					/* Restore the next session which has the key */
					session_init_for_next(s);
					log_info(LOG_NOTICE,"init for next sess from bak");
					restore_buffered_next_session(s);
					return;
				}else{
					hash_del(sessions_table, key);
					delete_session(s);
				}
			}
		}
	}
	else if(check_pack_src(tf, ip_header->daddr, tcp_header->dest) == LOCAL){
		/* When the packet comes from client */
		last_ch_dead_sess_time = now;
		if(clt_settings.factor){
		    /* Change source port*/
			tcp_header->source = get_port_from_shift(tcp_header->source,
					clt_settings.rand_port_shifted, clt_settings.factor);
		}
		key = get_ip_port_value(ip_header->saddr, tcp_header->source);
		if(tcp_header->syn){
			s  = hash_find(sessions_table, key);
			if(s){
				/* check if it is a duplicate syn */
				diff = now - s->create_time;
				if(tcp_header->seq == s->req_last_syn_seq){
#if (DEBUG_TCPCOPY)
					log_info(LOG_INFO, "duplicate syn,time diff:%d", diff);
					strace_pack(LOG_INFO, CLIENT_FLAG, ip_header,
							tcp_header);
#endif
					return;
				}else{
					/*
					 * Buffer the next session to current session
					 * We only support one more session which has the hash
					 * key
					 */
					s->sess_more = 1;
					if(s->next_session_packets){
						if(s->next_session_packets->size > 0){
							link_list_destory(s->next_session_packets);
						}
					}else{
						s->next_session_packets = link_list_create();
					}
					ln = link_node_malloc(copy_ip_packet(ip_header));
					ln->key = ntohl(tcp_header->seq);
					link_list_order_append(s->next_session_packets, ln);
#if (DEBUG_TCPCOPY)
					log_info(LOG_INFO, "buffer the new session");
					strace_pack(LOG_INFO, CLIENT_FLAG, ip_header,
							tcp_header);
#endif
					return;
				}
			}else{
				/* Create a new session */
				s = session_add(key, ip_header, tcp_header);
				if(NULL == s){
					return;
				}
			}
			/* Find the right sock to send router info */
			sock = address_find_sock(tcp_header->dest);
			if(-1 == sock){
				log_info(LOG_ERR, "sock is invalid in process");
				strace_pack(LOG_WARN, CLIENT_FLAG, 
						ip_header, tcp_header);
				return;
			}
			ret = msg_client_send(sock, ip_header->saddr,
					tcp_header->source, CLIENT_ADD);
			if(-1 == ret){
				log_info(LOG_ERR, "msg client send error");
				return;
			}else{
				process_recv(s, ip_header, tcp_header);
			}
		}else{
			s = hash_find(sessions_table, key);
			if(s){
				process_recv(s, ip_header, tcp_header);
				s->last_update_time = now;
				if(check_session_over(s)){
					if(s->sess_more){
						session_init_for_next(s);
						log_info(LOG_NOTICE,"init for next sess from clt");
						restore_buffered_next_session(s);
						return;
					}else{
						hash_del(sessions_table, key);
						delete_session(s);
					}
				}
			}else
			{
				/* we check if we can pad tcp handshake */
				if(check_padding(ip_header, tcp_header)){
#if (TCPCOPY_MYSQL_BASIC)
					if(!check_mysql_padding(ip_header,tcp_header)){
						return;
					}
#endif
					s = session_add(key, ip_header, tcp_header);
					if(NULL == s){
						return;
					}
					process_recv(s, ip_header, tcp_header);
				}
			}
		}
	}else{
		/* We don't know where the packet comes from */
		log_info(LOG_WARN, "unknown packet");
		strace_pack(LOG_WARN, UNKNOWN_FLAG, ip_header, tcp_header);
	}
}

