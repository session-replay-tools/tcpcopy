#include <xcopy.h>

static hash_table *sessions_table;

#if (TCPCOPY_MYSQL_BASIC)
static hash_table *mysql_table;
#endif
#if (TCPCOPY_MYSQL_ADVANCED)
static hash_table *fir_auth_pack_table;
static hash_table *sec_auth_pack_table;
#endif

/* client syn count */
static uint64_t clt_syn_cnt     = 0;
static uint64_t clt_packs_cnt   = 0;
static uint64_t active_sess_cnt = 0;
static uint64_t enter_cnt       = 0;
static uint64_t leave_cnt       = 0;
static uint64_t del_obs_cnt     = 0;
static uint64_t resp_cnt        = 0;
static uint64_t req_cnt         = 0;
static uint64_t conn_cnt        = 0;
static uint64_t bak_cnt         = 0;
static uint64_t clt_cnt         = 0;
static uint64_t packs_sent_cnt  = 0;
static uint32_t g_seq_omit      = 0;
static double   bak_cnt_t       = 0;
static double   clt_cnt_t       = 0;
static time_t   last_stat_time  = 0;
static uint64_t retrans_succ_cnt   = 0;
static uint64_t con_packs_sent_cnt  = 0;
static uint64_t recon_for_closed_cnt = 0;
static uint64_t clt_con_packs_cnt     = 0;
static uint64_t recon_for_no_syn_cnt   = 0;
static time_t   last_ch_dead_sess_time  = 0;
#if (TCPCOPY_MYSQL_BASIC)
static struct iphdr *fir_auth_user_pack = NULL;
#endif

static int check_overwhelming(session_t *s, const char *message, 
		int size, int max_hold_packs)
{
	if(size > max_hold_packs)
	{
		if(!s->sess_candidate_erased)
		{
			s->sess_candidate_erased=1;
			log_info(LOG_WARN, "%s:candidate erased:%u,p:%u",
				message, size, s->src_port);

			return CANDIDATE_OBSOLETE;
		}
		del_obs_cnt++;
		active_sess_cnt--;
		leave_cnt++;
		log_info(LOG_WARN,":%s:too many packets:%u,p:%u",
				message, size, s->src_port);

		return OBSOLETE;
	}
	return NOT_YET_OBSOLETE;
}

/* check if session is obsolete */
static int check_session_obsolete(session_t *s, time_t timeout)
{
	double diff = current - s->req_last_send_cont_time;
	int    threshold = max_hold_packs, result;	
	size_t packs_unsend, req_cont_pack_num, cont_sent_num;

	if(diff < 30)
	{
		threshold = max_hold_packs << 3;
		if(diff < 3)
		{
			threshold = threshold << 1;
		}
		req_cont_pack_num = s->req_cont_pack_num;
		cont_sent_num = s->vir_send_cont_pack_num;
		if(req_cont_pack_num >= cont_sent_num)
		{
			packs_unsend = req_cont_pack_num - cont_sent_num;
		}
		if(packs_unsend < threshold)
		{
			return 0;
		}else
		{
			log_info(LOG_WARN,"still live,but too many:%u,threshold:%u",
					s->src_port,threshold);
		}
	}
	result = check_overwhelming(s, "unsend", threshold, 
			s->unsend_packets->size);
	if(NOT_YET_OBSOLETE != result)
	{
		return result;
	}
	result = check_overwhelming(s, "lost", threshold, 
			s->lost_packets->size);
	if(NOT_YET_OBSOLETE != result)
	{
		return result;
	}
	result = check_overwhelming(s, "handshake", threshold, 
			s->handshake_packets->size);
	if(NOT_YET_OBSOLETE != result)
	{
		return result;
	}
	result = check_overwhelming(s, "unack", threshold, 
			s->unack_packets->size);
	if(NOT_YET_OBSOLETE != result)
	{
		return result;
	}
	result = check_overwhelming(s, "next session", threshold, 
			s->next_session_packets->size);
	if(NOT_YET_OBSOLETE != result)
	{
		return result;
	}
#if (TCPCOPY_MYSQL_BASIC)
	result = check_overwhelming(s, "mysql special", threshold, 
			s->mysql_special_packets->size);
	if(NOT_YET_OBSOLETE != result)
	{
		return result;
	}
#endif

	if(s->resp_last_recv_cont_time < timeout)
	{
		if(!s->sess_candidate_erased)
		{
			s->sess_candidate_erased=1;
			return CANDIDATE_OBSOLETE;
		}
		del_obs_cnt++;
		active_sess_cnt--;
		leave_cnt++;
		log_info(LOG_INFO,"session timeout,p:%u",s->src_port);
		if(s->unsend_packets->size > 10)
		{
			log_info(LOG_WARN,"timeout,unsend number:%u,p:%u",
					s->unsend_packets->size, s->src_port);
		}
		return OBSOLETE;
	}
}

/*
 * clear timeout tcp sessions
 */
static int clear_timeout_sessions()
{
	/*
	 * we clear old sessions that receive no content response for 
	 * more than one minute. this may be a problem 
	 * for keepalive connections.
	 * so we adopt a naive method to distinguish between short-lived 
	 * and long-lived sessions(one connection represents one session)
	 */
	time_t      current           = time(0);
	time_t      norm_timeout      = current-60;
	time_t      keepalive_timeout = current-120;
	time_t      timeout;
	double      ratio          = 100.0*enter_cnt/(req_cnt+1);
	size_t      max_hold_packs = 200;
	size_t      size, i;           
	int         result;
	link_list   *list;
	p_link_node ln, tmp_ln;
	hash_node   *hn;
	
#if (TCPCOPY_MYSQL_BASIC)
	max_hold_packs        = 2000;
#endif
	if(ratio < 10)
	{
		norm_timeout = keepalive_timeout;
		log_info(LOG_NOTICE, "keepalive connection global");
	}

	log_info(LOG_WARN, "session size:%u", sessions_table.total);

	for(; i < sessions_table->size; i++)
	{
		list = table->lists[i];
	    ln   = link_list_first(list);	
		while(ln){
			hn = (hash_node *)ln->data;
			result = NOT_YET_OBSOLETE;
			if(hn->data != NULL){
				session_t *s = hn->data;
				if(s->conn_keepalive)
				{
					timeout=keepalive_timeout;
				}else
				{
					timeout=norm_timeout;
				}
				result = check_session_obsolete(s, timeout);
				if(OBSOLETE == result)
				{
					/* delete session*/
					delete_session(s);
					free(s);
				}
			}
			tmp_ln = ln;
			ln = link_list_get_next(list, ln);
			if(OBSOLETE == result)
			{
				link_list_remove(tmp_ln);
			}
		}
	}
}


void delete_session(session_t *s){
	if(NULL != s->unsend_packets)
	{
		link_list_destory(s->unsend_packets);
	}
	if(NULL != s->next_session_packets)
	{
		link_list_destory(s->next_session_packets);
	}
	if(NULL != s->unack_packets)
	{
		link_list_destory(s->unack_packets);
	}
	if(NULL != s->lost_packets)
	{
		link_list_destory(s->lost_packets);
	}
	if(NULL != s->handshake_packets)
	{
		link_list_destory(s->handshake_packets);
	}
#if (TCPCOPY_MYSQL_BASIC)
	if(NULL != s->mysql_special_packets)
	{
		link_list_destory(s->mysql_special_packets);
	}
#endif
}

static void send_deadly_sessions()
{
	int          i;
	link_list    *list;
	p_link_node  ln;
	hash_node    *hn;

	log_info(LOG_NOTICE,"send_deadly_sessions");
	for(; i < sessions_table->size; i++)
	{
		list = table->lists[i];
	    ln   = link_list_first(list);	
		while(ln){
			hn = (hash_node *)ln->data;
			if(hn->data != NULL){
				session_t *s = hn->data;
				if(check_dead_reqs(s))
				{
					log_info(LOG_WARN,"send dead reqs from global");
				}else
				{
					if(s->vir_syn_retrans_times <= 3)
					{
						retransmit_packets(s);
					}
				}
			}
			ln = link_list_get_next(list, ln);
		}
	}
}

/*
 * wrap sending ip packet function
 */
int wrap_send_ip_packet(session_t *s,unsigned char *data)
{
	struct iphdr  *ip_header;
	struct tcphdr *tcp_header;
	p_link_node   ln;
	uint16_t size_ip, size_tcp, tot_len, cont_len;
	ssize_t send_len;

	if(NULL != data)
	{
		log_info(LOG_ERR,"error ip data is null");
		return 0;
	}
	ip_header  = (struct iphdr *)data;
	size_ip    = ip_header->ihl << 2;
	tcp_header = (struct tcphdr *)(data + size_ip);

	if(s->unack_pack_omit_save_flag)
	{
		ln = link_node_malloc(copy_ip_packet(ip_header));
		link_list_append(s->unack_packets, ln);
	}
	/* set the destination ip and port*/
	tcp_header->dest = dst_port;
	ip_header->daddr = dst_addr;

	if(s->faked_src_port != 0)
	{
		tcp_header->source=fake_src_port;
	}
	if(tcp_header->syn)
	{
		vir_next_seq = vir_next_seq+1;
	}
	else if(tcp_header->fin)
	{
		vir_next_seq = vir_next_seq+1;
	}
	if(tcp_header->ack)
	{
		tcp_header->ack_seq = vir_ack_seq;
	}

	size_tcp = tcp_header->doff << 2;
	tot_len  = ntohs(ip_header->tot_len);
	cont_len = tot_len - size_ip - size_tcp;
	if(cont_len > 0)
	{
		s->req_last_send_cont_time = time(0);
		s->vir_next_seq=s->vir_next_seq + cont_len;
		s->vir_send_cont_pack_num++;
		if(s->unack_pack_omit_save_flag)
		{
			s->con_packs_sent_cnt++;
		}else
		{
			s->vir_new_retransmit = 1;
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
	strace_packet_info(LOG_DEBUG,SERVER_BACKEND_FLAG,ip_header,tcp_header);
#endif
	s->packs_sent_cnt++;
	send_len = send_ip_packet(ip_header,tot_len);
	if(-1 == send_len)
	{
		log_info(LOG_ERR,"send to back error,tot_len is:%d,cont_len:%d",
				tot_len,cont_len);
	}
	return 1;
}

/*
 * check if the packet has lost previous packets
 */
int check_packet_lost(session_t *s) 
{
	p_link_node  ln;
	uint32_t     cur_seq = ntohl(tcp_header->seq);
	if(cur_seq > vir_next_seq)
	{
		if(send_reserved_packets(s) > 0)
		{
			ln = link_node_malloc(copy_ip_packet(ip_header));
			link_list_append(s->unsend_packets, ln);
		}else
		{
#if (DEBUG_TCPCOPY)
			log_info(LOG_INFO, "seq now:%u,expected seq:%u",
					cur_seq, vir_next_seq);
#endif
			return 1;
		}
	}
	return 0;
}

/*
 * send reserved lost packets
 */
int send_reserved_lost_packets(session_t *s)
{
	/* 
	 * TODO 
	 * It needs sorting the lost Packets.
	 * If not sorted,the following logic will not work 
	 * for long content requests 
	 */
	uint32_t size_ip, size_tcp, pack_size, cont_size, cur_seq;
	unsigned char *data;
	struct iphdr  *ip_header;
	struct tcphdr *tcp_header;
	p_link_node ln, tmp_ln;
	link_list   *list;

	list = s->lost_packets;
	ln = link_list_first(list);	
	while(ln){
		data = ln->data;
		ip_header =(struct iphdr*)((char*)data);
		size_ip   = ip_header->ihl << 2;
		tcp_header = (struct tcphdr*)((char *)ip_header + size_ip);
		size_tcp  = tcp_header->doff << 2;
		pack_size = ntohs(ip_header->tot_len);
		cont_size = pack_size - size_tcp - size_ip;
		cur_seq   = ntohl(tcp_header->seq);

		if(s->vir_next_seq == cur_seq)
		{
			if(0 == cont_size)
			{
#if (DEBUG_TCPCOPY)
				log_info(LOG_NOTICE,"error in lost:%u", src_port);
#endif
			}else
			{
				s->candidate_response_waiting = 1;
			}
#if (DEBUG_TCPCOPY)
			log_info(LOG_DEBUG,"send packets for lost:%u", src_port);
#endif
			s->req_last_ack_seq = ntohl(tcp_header->ack_seq);
			if(cont_size > 0)
			{
				s->req_last_cont_seq = ntohl(tcp_header->seq);
			}
			wrap_send_ip_packet(s, data);
			tmp_ln = ln;
			ln = link_list_get_next(list, ln);
			link_list_remove(tmp_ln);
			free(data);
		}else
		{
			log_info(LOG_WARN,"can't send packs for lost:%u", src_port);
			/* TODO free resources */
			break;
		}
	}
	if(link_list_is_empty(list))
	{
		previous_packet_waiting = 0;
	}

	return 0;
}

/*
 * retransmit the packets to backend
 */
int retransmit_packets(session_t *s)
{
	unsigned char *data;
	struct iphdr  *ip_header;
	struct tcphdr *tcp_header;
	uint32_t size_ip, size_tcp, pack_size, cont_size, cur_seq;
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
		if(SYN_SEND == s->status)
		{
			req_last_ack_seq = ntohl(tcp_header->ack_seq);
			s->unack_pack_omit_save_flag = 1;
			wrap_send_ip_packet(s, data);
			vir_syn_retrans_times++;
			break;
		}
		size_tcp  = tcp_header->doff << 2;
		pack_size = ntohs(ip_header->tot_len);
		cont_size = pack_size - size_tcp - size_ip;
		cur_seq   = ntohl(tcp_header->seq);  
		if(!is_success){
			if(cur_seq == resp_last_ack_seq){
				is_success = 1;
			}else if(cur_seq < resp_last_ack_seq){
				tmp_ln = ln;
				ln = link_list_get_next(list, ln);
				link_list_remove(tmp_ln);
				free(data);
			}else{
				log_info(LOG_NOTICE, "no retrans packs:%u", src_port);
				need_pause = 1;
			}
		}
		if(is_success)
		{
			if(cur_seq < s->vir_next_seq)
			{
				req_last_ack_seq = ntohl(tcp_header->ack_seq);
				s->unack_pack_omit_save_flag = 1;
				wrap_send_ip_packet(s, data);
				tmp_ln = link_node_malloc(data);
				link_list_append(bufferd, tmp_ln); 
				link_list_remove(ln);
			}else
			{
				need_pause=1;	
			}
		}
	}
	
	if(!link_list_is_empty(buffered))
	{
		/* append all buffered packets to unack link list */
		ln = link_list_first(buffered);	
		while(ln){
			link_list_append(list, ln);
			ln = link_list_get_next(buffered, ln);
		}
	}

	return is_success;
}

/*
 * update retransmission packets
 */
void update_retransmission_packets(session_t *s)
{
	unsigned char *data;
	struct iphdr  *ip_header;
	struct tcphdr *tcp_header;
	uint32_t      size_ip, cur_seq;
	p_link_node   ln, tmp_ln;
	link_list     *list;

	list = s->unack_packets;
	ln = link_list_first(list);	

	while(ln)
	{
		data = ln->data;
		ip_header  = (struct iphdr*)((char*)data);
		size_ip    = ip_header->ihl << 2;
		tcp_header = (struct tcphdr*)((char *)ip_header + size_ip);
		cur_seq    = ntohl(tcp_header->seq);  
		if(cur_seq < s->resp_last_ack_seq)
		{
			tmp_ln = ln;
			ln = link_list_get_next(list, ln);
			link_list_remove(tmp_ln);
			free(data);
		}else
		{
			break;
		}
	}
	return;
}


/*
 * check if it needs sending dead requests
 * this happens in the following situations:
 * 1)online requests are finished completely,but test are not,
 *   therefore there are no events that send buffered requests
 * 2)...
 */
int check_dead_reqs(session_t *s)
{
	int    packs_unsend = 0, diff, result = 0;
	int    diff;

	if(s->req_cont_pack_num >= s->vir_send_cont_pack_num){
		packs_unsend = r->req_cont_pack_num - r->vir_send_cont_pack_num;
	}
	diff = time(0) - r->req_last_send_cont_time;

	if(diff > 2){
		if(packs_unsend > 5){
			return 1;
		}
	}
	return 0;
}

/*
 * check if the reserved container has content left
 */
int check_reserved_content_left(session_t *s)
{
	unsigned char *data;
	struct iphdr  *ip_header;
	struct tcphdr *tcp_header;
	uint32_t size_ip, size_tcp, pack_size, cont_size;
	p_link_node   ln, tmp_ln;
	link_list     *list;

#if (DEBUG_TCPCOPY)
	log_info(LOG_DEBUG,"check_reserved_content_left");
#endif
	list = s->unsend_packets;
	ln = link_list_first(list);	

	while(ln){
		data = ln->data;
		ip_header =(struct iphdr*)((char*)data);
		size_ip   = ip_header->ihl << 2;
		tcp_header = (struct tcphdr*)((char *)ip_header + size_ip);
		size_tcp  = tcp_header->doff << 2;
		pack_size = ntohs(ip_header->tot_len);
		cont_size = pack_size - size_tcp - size_ip;
		if(cont_size>0)
		{
			return 1;
		}
		ln = link_list_get_next(ln);
	}
	return 0;
}


/*
 * send reserved packets to backend
 */
int send_reserved_packets(session_t *s)
{
	int need_pause=0;
	int mayPause=0;
	unsigned char* prevPacket=NULL;
	uint32_t prePackSize=0;
	int count=0;
	bool isOmitTransfer=0;
	uint32_t curAck=0;
#if (TCPCOPY_MYSQL_ADVANCED)
	unsigned char* payload=NULL;
#endif

#if (DEBUG_TCPCOPY)
	log_info(LOG_DEBUG,"sendResPas port:%u,sent=%u,tot co reqs:%u",
	src_port,vir_send_cont_pack_num,req_cont_pack_num);
	log_info(LOG_DEBUG,"send reserved packets,port:%u",src_port);
#endif
	while(! unsend.empty()&&!need_pause)
	{
		unsigned char *data = unsend.front();
		struct iphdr *ip_header=(struct iphdr*)((char*)data);
		uint32_t size_ip = ip_header->ihl<<2;
		struct tcphdr* tcp_header = (struct tcphdr*)((char *)ip_header+size_ip);
		uint32_t size_tcp = tcp_header->doff<<2;
		uint32_t pack_size=ntohs(ip_header->tot_len);
		uint32_t cont_size=pack_size-size_tcp-size_ip;
		if(cont_size>0)
		{
#if (TCPCOPY_MYSQL_BASIC)
			if(!isGreeingReceived)
			{
				break;
			}
#if (TCPCOPY_MYSQL_ADVANCED) 
			if(!isFirstAuthSent)
			{
				if(isGreeingReceived)
				{
					log_info(LOG_WARN,"a mysql login req from reserved");
					payload=(unsigned char*)((char*)tcp_header+size_tcp);
					int result=change_client_auth_content(payload,cont_size,
							password,scrambleBuf);
					strace_packet_info(LOG_WARN,CLIENT_FLAG,
								ip_header,tcp_header);
					if(!result)
					{
						isOmitTransfer=1;
						over_flag=1;
						log_info(LOG_WARN,"it is strange here,possibility");
						log_info(LOG_WARN,"1)user password pair not equal");
						log_info(LOG_WARN,"2)half-intercepted");
						need_pause=1;
						break;
					}
					isFirstAuthSent=1;
					uint64_t value=get_ip_port_value(ip_header->saddr,
							tcp_header->source);
					AuthPackIterator iter = firAuthPackContainer.find(value);
					if(iter != firAuthPackContainer.end())
					{
						struct iphdr *packet=iter->second;
						free(packet);
						log_info(LOG_WARN,"free value for fir auth:%llu",value);
					}
					struct iphdr *packet=NULL;
					packet=(struct iphdr*)copy_ip_packet(ip_header);
					firAuthPackContainer[value]=packet;
					log_info(LOG_WARN,"set value for fir auth:%llu",value);
				}
			}else if(isFirstAuthSent&&isNeedSecondAuth)
			{
				log_info(LOG_WARN,"a mysql second login req from reserved");
				payload=(unsigned char*)((char*)tcp_header+size_tcp);
				char encryption[16];
				memset(encryption,0,16);
				memset(seed323,0,SEED_323_LENGTH+1);
				memcpy(seed323,scrambleBuf,SEED_323_LENGTH);
				new_crypt(encryption,password,seed323);
				log_info(LOG_WARN,"change second req:%u",src_port);
				change_client_second_auth_content(payload,cont_size,encryption);
				isNeedSecondAuth=0;
				strace_packet_info(LOG_WARN,CLIENT_FLAG,ip_header,
						tcp_header);
				uint64_t value=get_ip_port_value(ip_header->saddr,
						tcp_header->source);
				AuthPackIterator iter = secAuthPackContainer.find(value);
				if(iter != secAuthPackContainer.end())
				{
					struct iphdr *packet=iter->second;
					free(packet);
					log_info(LOG_WARN,"free sec auth packet from reserved:%llu",
							value);
				}
				struct iphdr *packet=NULL;
				packet=(struct iphdr*)copy_ip_packet(ip_header);
				secAuthPackContainer[value]=packet;
				log_info(LOG_WARN,"set sec auth packet:%llu",value);
			}
#endif

#endif
			curAck=ntohl(tcp_header->ack_seq);
			if(mayPause)
			{
				if(curAck!=lastAck)
				{
#if (DEBUG_TCPCOPY)
					log_info(LOG_DEBUG,"cease to send:%u",
							src_port);
#endif
					break;
				}
			}
#if (DEBUG_TCPCOPY)
			log_info(LOG_DEBUG,"set mayPause true");
#endif
			mayPause=1;
			candidate_response_waiting=1;
			isRequestBegin=1;
			isRequestComletely=0;
			req_last_cont_seq=ntohl(tcp_header->seq);
			lastAck=ntohl(tcp_header->ack_seq);
		}else if(tcp_header->rst){
			if(candidate_response_waiting)
			{
				break;
			}
			reset_flag=1;
			isOmitTransfer=0;
#if (DEBUG_TCPCOPY)
			log_info(LOG_DEBUG,"send reset packet to backend:%u",
					src_port);
#endif
			need_pause=1;
		}else if(tcp_header->fin)
		{
			if(candidate_response_waiting)
			{
				break;
			}
			need_pause=1;
			uint32_t ackFromClient=ntohl(tcp_heades->ack_seq);
			if(req_last_ack_seq==ackFromClient)
			{
				/*active close from client*/
				isClientClosed=1;
#if (DEBUG_TCPCOPY)
				log_info(LOG_NOTICE,"set cli closed flag:%u",src_port);
#endif
				virtual_status |= CLIENT_FIN;
				confirmed=1;
			}else
			{
				isOmitTransfer=1;
			}
		}else if(0==cont_size&&candidate_response_waiting)
		{
#if (DEBUG_TCPCOPY)
			log_info(LOG_DEBUG,"omit tranfer:size 0 and wait resp:%u",
					src_port);
#endif
			isOmitTransfer=1;
		}else if (0 == cont_size)
		{
			if(SYN_CONFIRM != virtual_status)
			{
#if (DEBUG_TCPCOPY)
				log_info(LOG_DEBUG,"omit tranfer:notsynack,%u",
						src_port);
#endif
				isOmitTransfer=1;
			}
			if(isRequestBegin)
			{
				isOmitTransfer=1;
				isRequestBegin=0;
				isRequestComletely=1;
			}
		}

		req_last_ack_seq=ntohl(tcp_header->ack_seq);
		if(!isOmitTransfer)
		{
			count++;
			wrap_send_ip_packet(fake_ip_addr,data,virtual_next_sequence,1);
		}
		free(data);
		unsend.pop_front();
		if(isOmitTransfer)
		{
			if(candidate_response_waiting)
			{
#if (DEBUG_TCPCOPY)
				log_info(LOG_DEBUG,"cease to send reserved packs:%u",
						src_port);
#endif
				break;
			}
		}
		isOmitTransfer=0;
	}
	return count;
}

/*
 * send faked syn packet for backend for intercepting already connected packets
 */
void session_st::sendFakedSynToBackend(struct iphdr* ip_header,
		struct tcphdr* tcp_header)
{
	isHalfWayIntercepted=1;
	isBackSynReceived=0;

	unsigned char fake_syn_buf[FAKE_SYN_BUF_SIZE];
	memset(fake_syn_buf,0,FAKE_SYN_BUF_SIZE);
	struct iphdr *f_ip_header = (struct iphdr *)fake_syn_buf;
	struct tcphdr *f_tcp_header = (struct tcphdr *)(fake_syn_buf+20);

#if (DEBUG_TCPCOPY)
	log_info(LOG_DEBUG,"sendFakedSynToBackend:%u",src_port);
	log_info(LOG_DEBUG,"unsend size:%u",unsend.size());
#endif
	f_ip_header->version = 4;
	f_ip_header->ihl = 5;
	f_ip_header->tot_len = htons(FAKE_SYN_BUF_SIZE);
	f_ip_header->frag_off = 64; 
	f_ip_header->ttl = 64; 
	f_ip_header->protocol = 6;
	f_ip_header->id= htons(client_ip_id+2);;
	f_ip_header->saddr = ip_header->saddr;
	f_ip_header->daddr = ip_header->daddr;
	f_tcp_header->doff= 8;
	f_tcp_header->source = tcp_header->source;
	f_tcp_header->dest= tcp_header->dest;
	f_tcp_header->syn=1;
	f_tcp_header->seq = minus_1(tcp_header->seq);
	f_tcp_header->window= 65535;
	virtual_next_sequence=tcp_header->seq;
	unsigned char *data=copy_ip_packet(f_ip_header);
	handshakePackets.push_back(data);
#if (TCPCOPY_MYSQL_BASIC)
	isPureRequestBegin=1;
	struct iphdr *fir_auth_packet=fir_auth_user_pack;
#if (TCPCOPY_MYSQL_ADVANCED)
	struct iphdr *sec_auth_packet=NULL;
	uint64_t value=get_ip_port_value(ip_header->saddr,
			tcp_header->source);
	AuthPackIterator authIter= firAuthPackContainer.find(value);
	if(authIter!= firAuthPackContainer.end())
	{
		fir_auth_packet=authIter->second;
	}
	AuthPackIterator secAuthIter=secAuthPackContainer.find(value);
	if(secAuthIter != secAuthPackContainer.end())
	{
		sec_auth_packet=secAuthIter->second;
	}
#endif
	if(fir_auth_packet)
	{
		struct iphdr* fir_ip_header=NULL;
		struct tcphdr* fir_tcp_header=NULL;
		fir_ip_header=(struct iphdr*)copy_ip_packet(fir_auth_packet);
		fir_ip_header->saddr=f_ip_header->saddr;
		size_t size_ip= fir_ip_header->ihl<<2;
		size_t total_len= ntohs(fir_ip_header->tot_len);
		fir_tcp_header=(struct tcphdr*)((char *)fir_ip_header+size_ip);
		size_t size_tcp= fir_tcp_header->doff<<2;
		size_t fir_cont_len=total_len-size_ip-size_tcp;
		fir_tcp_header->source=f_tcp_header->source;
		unsend.push_back((unsigned char*)fir_ip_header);
		total_seq_omit=g_seq_omit;
#if (TCPCOPY_MYSQL_ADVANCED)
		struct iphdr* sec_ip_header=NULL;
		struct tcphdr* sec_tcp_header=NULL;
		size_t sec_cont_len=0;
		if(sec_auth_packet!=NULL)
		{
			sec_ip_header=(struct iphdr*)copy_ip_packet(sec_auth_packet);
			sec_ip_header->saddr=f_ip_header->saddr;
			size_ip= sec_ip_header->ihl<<2;
			total_len= ntohs(sec_ip_header->tot_len);
			sec_tcp_header=(struct tcphdr*)((char *)sec_ip_header+size_ip);
			size_tcp= sec_tcp_header->doff<<2;
			sec_cont_len=total_len-size_ip-size_tcp;
			sec_tcp_header->source=f_tcp_header->source;
			unsend.push_back((unsigned char*)sec_ip_header);
			log_info(LOG_WARN,"set second auth for no skip");
		}else
		{
			log_info(LOG_WARN,"no sec auth packet here");
		}
#endif
#if (TCPCOPY_MYSQL_ADVANCED)
		uint32_t total_cont_len=fir_cont_len+sec_cont_len;	
#else
		uint32_t total_cont_len=fir_cont_len;
#endif
		MysqlIterator mysqlIter=mysqlContainer.find(src_port);
		dataContainer* datas=NULL;
		struct iphdr* tmp_ip_header=NULL;
		struct tcphdr* tmp_tcp_header=NULL;
		//TODO to be removed later
		if(mysqlIter!= mysqlContainer.end())
		{
			datas=mysqlIter->second;
			//check if we insert COM_STMT_PREPARE statements 
			for(dataIterator iter=datas->begin();
					iter!=datas->end();iter++)
			{
				unsigned char *data =*iter;
				tmp_ip_header=(struct iphdr *)data;
				size_ip= tmp_ip_header->ihl<<2;
				total_len= ntohs(tmp_ip_header->tot_len);
				tmp_tcp_header=(struct tcphdr*)((char *)tmp_ip_header
						+size_ip); 
				size_tcp= tmp_tcp_header->doff<<2;
				size_t tmpContentLen=total_len-size_ip-size_tcp;
				total_cont_len+=tmpContentLen;
			}
		}

#if (DEBUG_TCPCOPY)
		log_info(LOG_INFO,"total len needs to be subtracted:%u",
				total_cont_len);
#endif
		f_tcp_header->seq=htonl(ntohl(f_tcp_header->seq)-total_cont_len);
		fir_tcp_header->seq=plus_1(f_tcp_header->seq);
#if (TCPCOPY_MYSQL_ADVANCED)
		if(sec_tcp_header!=NULL)
		{
			sec_tcp_header->seq=htonl(ntohl(fir_tcp_header->seq)+fir_cont_len);
		}
#endif
#if (TCPCOPY_MYSQL_ADVANCED)
		uint32_t baseSeq=ntohl(fir_tcp_header->seq)+fir_cont_len+sec_cont_len;
#else
		uint32_t baseSeq=ntohl(fir_tcp_header->seq)+fir_cont_len;
#endif
		if(mysqlIter!= mysqlContainer.end())
		{
			datas=mysqlIter->second;
			//check if we insert COM_STMT_PREPARE statements 
			for(dataIterator iter=datas->begin();
					iter!=datas->end();iter++)
			{
				unsigned char *data =*iter;
				tmp_ip_header=(struct iphdr *)data;
				tmp_ip_header=(struct iphdr*)copy_ip_packet(tmp_ip_header);
				size_ip= tmp_ip_header->ihl<<2;
				total_len= ntohs(tmp_ip_header->tot_len);
				tmp_tcp_header=(struct tcphdr*)((char *)tmp_ip_header
						+size_ip); 
				size_tcp= tmp_tcp_header->doff<<2;
				size_t tmpContentLen=total_len-size_ip-size_tcp;
				tmp_tcp_header->seq=htonl(baseSeq);
				unsend.push_back((unsigned char*)tmp_ip_header);
				total_cont_len+=tmpContentLen;
				baseSeq+=tmpContentLen;
			}
		}
	}else
	{
		log_info(LOG_WARN,"no auth packets here");
	}
#endif

#if (DEBUG_TCPCOPY)
	outputPacket(LOG_DEBUG,FAKE_CLIENT_FLAG,f_ip_header,f_tcp_header);
	log_info(LOG_DEBUG,"send faked syn to back,client win:%u",
			f_tcp_header->window);
#endif
	wrap_send_ip_packet(fake_ip_addr,fake_syn_buf,virtual_next_sequence,1);
}

/**
 * send faked syn ack packet to backend for handshake
 */
void session_st::sendFakedSynAckToBackend(struct iphdr* ip_header,
		struct tcphdr* tcp_header)
{
	unsigned char fake_ack_buf[40];
	memset(fake_ack_buf,0,40);
	struct iphdr *f_ip_header = (struct iphdr *)fake_ack_buf;
	struct tcphdr *f_tcp_header = (struct tcphdr *)(fake_ack_buf+20);
#if (DEBUG_TCPCOPY)
	log_info(LOG_DEBUG,"sendFakedSynAckToBackend:%u",src_port);
#endif
	f_ip_header->version = 4;
	f_ip_header->ihl = 5;
	f_ip_header->tot_len = htons(40);
	f_ip_header->frag_off = 64; 
	f_ip_header->ttl = 64; 
	f_ip_header->protocol = 6;
	f_ip_header->id= htons(client_ip_id+2);;
	f_ip_header->saddr = client_ip_addr;
	f_ip_header->daddr = local_dest_ip_addr; 
	f_tcp_header->doff= 5;
	f_tcp_header->source = tcp_header->dest;
	f_tcp_header->dest= local_port;
	f_tcp_header->ack=1;
	f_tcp_header->ack_seq = virtual_next_sequence;
	f_tcp_header->seq = tcp_header->ack_seq;
	f_tcp_header->window= 65535;
	unsigned char *data=copy_ip_packet(f_ip_header);
	handshakePackets.push_back(data);
#if (DEBUG_TCPCOPY)
	outputPacket(LOG_DEBUG,FAKE_CLIENT_FLAG,f_ip_header,f_tcp_header);
#endif
	wrap_send_ip_packet(fake_ip_addr,fake_ack_buf,virtual_next_sequence,1);
}

/**
 * send faked ack packet to backend 
 */
void session_st::sendFakedAckToBackend(struct iphdr* ip_header,
		struct tcphdr* tcp_header,bool changeSeq)
{
	unsigned char fake_ack_buf[40];
	memset(fake_ack_buf,0,40);
	struct iphdr *f_ip_header = (struct iphdr *)fake_ack_buf;
	struct tcphdr *f_tcp_header = (struct tcphdr *)(fake_ack_buf+20);
	f_ip_header->version = 4;
	f_ip_header->ihl = 5;
	f_ip_header->tot_len = htons(40);
	f_ip_header->frag_off = 64; 
	f_ip_header->ttl = 64; 
	f_ip_header->protocol = 6;
	f_ip_header->id= htons(client_ip_id+2);;
	f_ip_header->saddr = ip_header->daddr;
	f_tcp_header->doff= 5;
	f_tcp_header->source = tcp_header->dest;
	f_tcp_header->ack=1;
	f_tcp_header->ack_seq = virtual_next_sequence;
	if(changeSeq)
	{
		f_tcp_header->seq = htonl(vir_next_seq);
	}else
	{
		f_tcp_header->seq = tcp_header->ack_seq;
	}
	f_tcp_header->window= 65535;
#if (DEBUG_TCPCOPY)
	log_info(LOG_INFO,"send faked ack to backend,client win:%u",
			f_tcp_header->window);
#endif
	wrap_send_ip_packet(fake_ip_addr,fake_ack_buf,virtual_next_sequence,1);
}

/**
 * send faked fin to backend according to the backend packet
 */
void session_st::sendFakedFinToBackend(struct iphdr* ip_header,
		struct tcphdr* tcp_header)
{
#if (DEBUG_TCPCOPY)
	log_info(LOG_DEBUG,"send faked fin To Back:%u",src_port);
#endif
	unsigned char fake_fin_buf[40];
	memset(fake_fin_buf,0,40);
	struct iphdr *f_ip_header = (struct iphdr *)fake_fin_buf;
	struct tcphdr *f_tcp_header = (struct tcphdr *)(fake_fin_buf+20);
	f_ip_header->version = 4;
	f_ip_header->ihl = 5;
	f_ip_header->tot_len = htons(40);
	f_ip_header->frag_off = 64; 
	f_ip_header->ttl = 64; 
	f_ip_header->protocol = 6;
	f_ip_header->id= htons(client_ip_id+2);;
	f_ip_header->saddr = ip_header->daddr;
	f_tcp_header->doff= 5;
	f_tcp_header->source = tcp_header->dest;
	f_tcp_header->rst=1;
	f_tcp_header->ack=1;
	reset_flag=1;
	uint16_t size_ip = ip_header->ihl<<2; 
	uint16_t size_tcp= tcp_header->doff<<2;
	uint16_t tot_len  = ntohs(ip_header->tot_len);
	uint16_t cont_len=tot_len-size_ip-size_tcp;
	uint32_t seq=ntohl(tcp_header->seq);
	uint32_t expectedSeq=ntohl(virtual_next_sequence);
	if(cont_len>0){   
		uint32_t next_ack= htonl(seq+cont_len); 
		f_tcp_header->ack_seq = next_ack;
	}else
	{
		if(isClientClosed&&!isTestConnClosed)
		{
			if(seq>expectedSeq)
			{
				log_info(LOG_NOTICE,"set virtual_next_sequence larger");
				virtual_next_sequence=tcp_header->seq;
				isTestConnClosed=true;
			}
			f_tcp_header->fin =0;
		}
		f_tcp_header->ack_seq = virtual_next_sequence;
	}
	f_tcp_header->seq = tcp_header->ack_seq;
	f_tcp_header->window= 65535;
	wrap_send_ip_packet(fake_ip_addr,fake_fin_buf,virtual_next_sequence,1);
}

/**
 * send faked fin to backend according to the client packet
 */
void session_st::sendFakedFinToBackByCliePack(struct iphdr* ip_header,
		struct tcphdr* tcp_header)
{
#if (DEBUG_TCPCOPY)
	log_info(LOG_DEBUG,"send faked fin To Back from cli pack:%u",
			src_port);
#endif
	unsigned char fake_fin_buf[40];
	memset(fake_fin_buf,0,40);
	struct iphdr *f_ip_header = (struct iphdr *)fake_fin_buf;
	struct tcphdr *f_tcp_header = (struct tcphdr *)(fake_fin_buf+20);
	f_ip_header->version = 4;
	f_ip_header->ihl = 5;
	f_ip_header->tot_len = htons(40);
	f_ip_header->frag_off = 64; 
	f_ip_header->ttl = 64; 
	f_ip_header->protocol = 6;
	f_ip_header->id= htons(client_ip_id+2);;
	f_ip_header->saddr = ip_header->saddr;
	f_tcp_header->doff= 5;
	f_tcp_header->source = tcp_header->source;
	f_tcp_header->fin =1;
	f_tcp_header->rst =1;
	f_tcp_header->ack=1;
	
	f_tcp_header->ack_seq = virtual_next_sequence;
	if(isClientClosed)
	{
		f_tcp_header->seq =htonl(vir_next_seq-1); 
	}else
	{
		f_tcp_header->seq =htonl(vir_next_seq); 
	}
	f_tcp_header->window= 65535;
	wrap_send_ip_packet(fake_ip_addr,fake_fin_buf,virtual_next_sequence,1);
}

/**
 * establish a connection for intercepting already connected packets
 */
void session_st::establishConnectionForNoSynPackets(struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
#if (TCPCOPY_MYSQL_BASIC)
	log_info(LOG_WARN,"establish conn for already connected:%u",
			src_port);
#else
	log_info(LOG_DEBUG,"establish conn for already connected:%u",
			src_port);
#endif
	int sock=address_find_sock(tcp_header->dest);
	if(-1 == sock)
	{
		log_info(LOG_WARN,"sock invalid in est Conn for NoSynPacks");
		outputPacket(LOG_WARN,CLIENT_FLAG,ip_header,tcp_header);
		return;
	}
	int result=msg_copyer_send(sock,ip_header->saddr,
			tcp_header->source,CLIENT_ADD);
	if(-1 == result)
	{
		log_info(LOG_ERR,"msg copyer send error");
		return;
	}
	sendFakedSynToBackend(ip_header,tcp_header);
	isSynIntercepted=1;
	recon_for_no_syn_cnt++;

}

/**
 * establish a connection for already closed connection
 * Attension:
 *   if the server does the active close,it lets a client and server 
 *   continually reuse the same port number at each end for successive 
 *   incarnations of the same connection
 */
void session_st::establishConnectionForClosedConn()
{
#if (DEBUG_TCPCOPY)
	log_info(LOG_INFO,"reestablish connection for keepalive:%u",
			src_port);
#endif
	size_t size=handshakePackets.size();
	if(size!=handshakeExpectedPackets)
	{
		log_info(LOG_WARN,"hand Packets size not expected:%u,exp:%u",
				size,handshakeExpectedPackets);
	}else
	{
		unsigned char *data = handshakePackets.front();
		struct iphdr *ip_header = (struct iphdr*)data;
		unsigned char* tmpData=copy_ip_packet(ip_header);
		ip_header=(struct iphdr*)tmpData;
		size_t size_ip = ip_header->ihl<<2;
		struct tcphdr *tcp_header = (struct tcphdr*)((char *)ip_header+size_ip);
		int sock=address_find_sock(local_port);
		if(-1 == sock)
		{
			free(tmpData);
			log_info(LOG_WARN,"sock invalid estConnForClosedConn");
#if (DEBUG_TCPCOPY)
			outputPacket(LOG_INFO,CLIENT_FLAG,ip_header,tcp_header);
#endif
			return;
		}
		if(0 == fake_ip_addr)
		{
			client_ip_addr=ip_header->saddr;
		}else
		{
#if (DEBUG_TCPCOPY)
			log_info(LOG_DEBUG,"erase fake_ip_addr");
#endif
			trueIPContainer.erase(get_ip_port_value(fake_ip_addr,
						tcp_header->source));
		}
		fake_ip_addr=ip_header->saddr;
		uint16_t tmp_port_addition=getPortRandomAddition();
		uint16_t transfered_port=ntohs(tcp_header->source);
		if(transfered_port<=(65535-tmp_port_addition))
		{
			transfered_port=transfered_port+tmp_port_addition;
		}else
		{
			transfered_port=32768+tmp_port_addition;
		}
		tcp_header->source=htons(transfered_port);
		fake_src_port=htons(transfered_port);
#if (TCPCOPY_MYSQL_ADVANCED)
		log_info(LOG_WARN,"change port");
#endif
#if (DEBUG_TCPCOPY)
		log_info(LOG_INFO,"change port,add port:%u",tmp_port_addition);
#endif
		uint64_t key=get_ip_port_value(fake_ip_addr,tcp_header->source);
		trueIPContainer[key]=client_ip_addr;

		ip_header->saddr=fake_ip_addr;
		int result=msg_copyer_send(sock,ip_header->saddr,
				tcp_header->source,CLIENT_ADD);
		if(-1 == result)
		{
			free(tmpData);
			log_info(LOG_ERR,"msg copyer send error");
			return;
		}
		wrap_send_ip_packet(fake_ip_addr,data,virtual_next_sequence,1);
		isSynIntercepted=1;
		free(tmpData);
		//push remaining packets in handshakePackets to unsend
		int i=0;
		for(dataIterator iter=handshakePackets.begin();
				iter!=handshakePackets.end();iter++)
		{
			if(i>0)
			{
				unsigned char *data =*iter;
				ip_header=(struct iphdr *)data;
				ip_header->saddr=fake_ip_addr;
				size_ip = ip_header->ihl<<2;
				tcp_header=(struct tcphdr*)((char *)ip_header+size_ip);
				tcp_header->source=fake_src_port;
				unsend.push_back(copy_ip_packet(ip_header));
			}
			i++;
		}
		recon_for_closed_cnt++;
	}
}

/**
 * check if the packet is needed for reconnection by mysql tcpcopy
 */
bool session_st::checkMysqlPacketNeededForReconnection(struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
	uint32_t size_ip = ip_header->ihl<<2;
	uint32_t size_tcp = tcp_header->doff<<2;
	uint32_t pack_size=ntohs(ip_header->tot_len);
	uint32_t cont_size=pack_size-size_tcp-size_ip;

	if(cont_size>0)
	{
		unsigned char* payload;
		payload=(unsigned char*)((char*)tcp_header+size_tcp);
		//skip  Packet Length
		payload=payload+3;
		//skip  Packet Number
		payload=payload+1;
		unsigned char command=payload[0];
		if(COM_STMT_PREPARE == command||
				(hasPrepareStat&&isExcuteForTheFirstTime))
		{
			if(COM_STMT_PREPARE == command)
			{
				hasPrepareStat=1;
			}else
			{
				if(COM_QUERY == command&&hasPrepareStat)
				{
					if(numberOfExcutes>0)
					{
						isExcuteForTheFirstTime=0;
					}
					numberOfExcutes++;
				}
				if(!isExcuteForTheFirstTime)
				{
					return false;
				}
			}
			unsigned char *data=copy_ip_packet(ip_header);
			mysqlSpecialPackets.push_back(data);
#if (DEBUG_TCPCOPY)
			log_info(LOG_WARN,"push back necc statement:%u",
					src_port);
#endif
			MysqlIterator iter=mysqlContainer.find(src_port);
			dataContainer* datas=NULL;
			if(iter!= mysqlContainer.end())
			{
				datas=iter->second;
			}else
			{
				datas=new dataContainer();
				mysqlContainer[src_port]=datas;
			}
			data=copy_ip_packet(ip_header);
			datas->push_back(data);

			return true;
		}
	}
	return false;
}

/**
 * check if the packet is the right packet for  starting a new session 
 * by mysql tcpcopy
 */
static bool checkPacketPaddingForMysql(struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
	uint32_t size_ip = ip_header->ihl<<2;
	uint32_t size_tcp = tcp_header->doff<<2;
	uint32_t pack_size=ntohs(ip_header->tot_len);
	uint32_t cont_size=pack_size-size_tcp-size_ip;

	if(cont_size>0)
	{
		unsigned char* payload;
		payload=(unsigned char*)((char*)tcp_header+size_tcp);
		//skip  Packet Length
		payload=payload+3;
		unsigned char packetNumber=payload[0];
		//if it is the second authenticate_user,then skip it
		if(0!=packetNumber)
		{
			return false;
		}
		//skip Packet Number
		payload=payload+1;
		unsigned char command=payload[0];
		if(COM_QUERY == command)
		{
#if (DEBUG_TCPCOPY)
			log_info(LOG_DEBUG,"this is query command");
#endif
			return true;
		}
	}
	return false;
}

/**
 * check if the packet is the right packet for noraml tcpcopy
 */
static bool checkPacketPadding(struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
	uint32_t size_ip = ip_header->ihl<<2;
	uint32_t size_tcp = tcp_header->doff<<2;
	uint32_t pack_size=ntohs(ip_header->tot_len);
	uint32_t cont_size=pack_size-size_tcp-size_ip;

	if(cont_size>0)
	{
		return true;
	}
	return false;

}

/**
 * processing backend packets
 */
void session_st::update_virtual_status(struct iphdr *ip_header,
		struct tcphdr* tcp_header)
{
#if (DEBUG_TCPCOPY)
	outputPacket(LOG_DEBUG,BACKEND_FLAG,ip_header,tcp_header);
#endif
	if( tcp_header->rst)
	{
		reset_flag = true;
#if (DEBUG_TCPCOPY)
		log_info(LOG_INFO,"reset from backend:%u",src_port);
#endif
		return;
	}
	virtual_ack = tcp_header->ack_seq;
	uint32_t ack=ntohl(tcp_header->ack_seq);
	uint32_t tot_len = ntohs(ip_header->tot_len);
	uint32_t size_ip = ip_header->ihl<<2;
	uint32_t size_tcp = tcp_header->doff<<2;
	uint32_t cont_size=tot_len-size_tcp-size_ip;
	time_t current=time(0);
#if (TCPCOPY_MYSQL_ADVANCED)
	unsigned char* payload=NULL;
#endif
	if(cont_size>0)
	{
		if(isNewRetransmit)
		{
			retrans_succ_cnt++;
			isNewRetransmit=0;
		}
		respContentPackets++;
		lastRecvRespContentTime=current;
	}
	if(ack > vir_next_seq)
	{
#if (DEBUG_TCPCOPY)
		log_info(LOG_INFO,"ack back more than vir_next_seq:%u,%u,p:%u",
				ack,vir_next_seq,src_port);
#endif
		if(!isBackSynReceived)
		{
#if (DEBUG_TCPCOPY)
			log_info(LOG_INFO,"not recv back syn,p:%u",src_port);
#endif
			reset_flag = true;
			return;
		}
		vir_next_seq=ack;
	}else if(ack <vir_next_seq)
	{
#if (DEBUG_TCPCOPY)
		log_info(LOG_INFO,"ack back less than vir_next_seq:%u,%u, p:%u",
				ack,vir_next_seq,src_port);
#endif
		if(!isBackSynReceived)
		{
			virtual_next_sequence =tcp_header->seq;
			sendFakedFinToBackend(ip_header,tcp_header);
			isFakedSendingFinToBackend=1;
			isClientClosed=1;
			return;
		}
		if(isClientClosed&&!tcp_header->fin)
		{
			sendFakedFinToBackend(ip_header,tcp_header);
			return;
		}else
		{
			/* simulaneous close*/
			if(isClientClosed&&tcp_header->fin)
			{
				simulClosing=1;
			}
		}
		uint16_t window=tcp_header->window;
		if(0==window)
		{
			log_info(LOG_NOTICE,"slide window is zero now");
			resp_last_ack_seq=ack;
			update_retransmission_packets();
			/*slide window is full*/
			return;
		}

		if(0 == cont_size&&!tcp_header->fin)
		{
			if(resp_last_ack_seq!=0)
			{
				if(ack==resp_last_ack_seq)
				{
					lastSameAckTotal++;
					if(lastSameAckTotal>1)
					{
						/* it needs retransmission*/
						log_info(LOG_WARN,"backend lost packets:%u",
								src_port);
						if(!alreadyRetransmit)
						{
							if(!retransmitPacket())
							{
								sendFakedFinToBackend(ip_header,tcp_header);
								isFakedSendingFinToBackend=1;
								isClientClosed=1;
							}
							alreadyRetransmit=1;
						}else
						{
							log_info(LOG_WARN,"omit retransmit:%u",
								src_port);
						}
						return;
					}
				}else
				{
					lastSameAckTotal=0;
					alreadyRetransmit=0;
#if (DEBUG_TCPCOPY)
					log_info(LOG_DEBUG,"ack is not equal to last ack");
#endif
				}
			}else
			{
#if (DEBUG_TCPCOPY)
				log_info(LOG_DEBUG,"lastSameAckTotal is zero");
#endif
			}
		}
	}
	resp_last_ack_seq=ack;
	update_retransmission_packets();

	if( tcp_header->syn)
	{
		if(isBackSynReceived)
		{
#if (DEBUG_TCPCOPY)
			log_info(LOG_DEBUG,"recv syn from back again");
#endif
		}else
		{
			conn_cnt++;
			isBackSynReceived=1;
#if (DEBUG_TCPCOPY)
			log_info(LOG_DEBUG,"recv syn from back:%u",
					src_port);
#endif
		}
		virtual_next_sequence = plus_1(tcp_header->seq);
		virtual_status = SYN_CONFIRM;
		if(isHalfWayIntercepted)
		{
			sendFakedSynAckToBackend(ip_header,tcp_header);
			send_reserved_packets();
		}else
		{
			send_reserved_packets();
		}
		lastRespPacketSize=tot_len;
		return;
	}
	else if(tcp_header->fin)
	{
#if (DEBUG_TCPCOPY)
		log_info(LOG_INFO,"recv fin from back:%u",src_port);
#endif
		isTestConnClosed=1;
		candidate_response_waiting=0;
		response_waiting=0;
		virtual_status  |= SERVER_FIN;
		if(cont_size>0)
		{
			virtual_next_sequence=htonl(ntohl(tcp_header->seq)+cont_size+1);
		}else
		{
			virtual_next_sequence = plus_1(tcp_header->seq);
		}
		sendFakedAckToBackend(ip_header,tcp_header,simulClosing);
		if(!isClientClosed)
		{
			/* send constructed server fin to the backend */
			sendFakedFinToBackend(ip_header,tcp_header);
			isFakedSendingFinToBackend=1;
			virtual_status |= CLIENT_FIN;
			confirmed=1;
		}else
		{
			over_flag=1;
		}
		return;
	}else if(tcp_header->ack)
	{
		if(isClientClosed&&isTestConnClosed)
		{
			over_flag=1;
			return;
		}
		if(candidate_response_waiting)
		{
			if(!response_waiting)
			{
				req_cnt++;
			}
			response_waiting=1;
		}
		
	}
	if(!isBackSynReceived)
	{
		virtual_next_sequence =tcp_header->seq;;
		sendFakedFinToBackend(ip_header,tcp_header);
		isFakedSendingFinToBackend=1;
		isClientClosed=1;
		return;
	}
	uint32_t next_seq = htonl(ntohl(tcp_header->seq)+cont_size);
	bool isGreetReceivedPacket=0; 
	
#if (DEBUG_TCPCOPY)
	log_info(LOG_DEBUG,"cont size:%d",cont_size);
#endif
	//it is nontrivial to check if the packet is the last packet of response
	//the following is not 100 percent right here
	if(cont_size>0)
	{
		virtual_next_sequence =next_seq;
		if(isClientClosed)
		{
			sendFakedFinToBackend(ip_header,tcp_header);
			return;
		}

		if(!sess_candidate_erased)
		{
#if (TCPCOPY_MYSQL_BASIC)
			if(!isGreeingReceived)
			{
#if (DEBUG_TCPCOPY)
				log_info(LOG_INFO,"recv greeting from back");
#endif
				contPacketsFromGreet=0;
				isGreeingReceived=1;
				isGreetReceivedPacket=1;
#if (TCPCOPY_MYSQL_ADVANCED) 
				payload=(unsigned char*)((char*)tcp_header+
						sizeof(struct tcphdr));
				memset(scrambleBuf,0,SCRAMBLE_LENGTH+1);
				int result=parse_handshake_init_content(payload,
						cont_size,scrambleBuf);
				log_info(LOG_WARN,"scramble:%s,p:%u",
						scrambleBuf,src_port);
				if(!result)
				{
					if(cont_size>11)
					{
						strace_packet_info(LOG_WARN,BACKEND_FLAG,
								ip_header,tcp_header);
						log_info(LOG_WARN,"port:%u,payload:%s",
								src_port,(char*)(payload+11));
					}
					over_flag=1;
					return;
				}
#endif
			}else{
#if (TCPCOPY_MYSQL_ADVANCED) 
				if(0==contPacketsFromGreet)
				{
#if (DEBUG_TCPCOPY)
					log_info(LOG_INFO,"check if needs second auth");
#endif
					payload=(unsigned char*)((char*)tcp_header+
							sizeof(struct tcphdr));
					if(isLastDataPacket(payload))
					{
						strace_packet_info(LOG_WARN,BACKEND_FLAG,
								ip_header,tcp_header);
						log_info(LOG_WARN,"it needs second auth:%u",
								src_port);
						isNeedSecondAuth=1;
					}
				}
#endif
				contPacketsFromGreet++;
			}
#endif

			{
#if (DEBUG_TCPCOPY)
				log_info(LOG_DEBUG,"receive from backend");
#endif
#if (!TCPCOPY_MYSQL_BASIC)
				sendFakedAckToBackend(ip_header,tcp_header,true);
#endif
				if(candidate_response_waiting||isGreetReceivedPacket)
				{
#if (DEBUG_TCPCOPY)
					log_info(LOG_DEBUG,"receive back server's resp");
#endif
					resp_cnt++;
					candidate_response_waiting=0;
					response_waiting=0;
					virtual_next_sequence =next_seq;
					virtual_status = SEND_RESPONSE_CONFIRM;
					responseReceived++;
					send_reserved_packets();
					lastRespPacketSize=tot_len;
					return;
				}
			}
		}
	}else
	{
		if(isClientClosed&&!isTestConnClosed)
		{
			sendFakedFinToBackend(ip_header,tcp_header);
		}
	}
	virtual_next_sequence= next_seq;
	if(sess_candidate_erased)
	{
		if(!isClientClosed)
		{
#if (DEBUG_TCPCOPY)
			log_info(LOG_INFO,"candidate erased true:%u",
					src_port);
#endif
			/* send constructed server fin to the backend */
			sendFakedFinToBackend(ip_header,tcp_header);
			isFakedSendingFinToBackend=1;
			isClientClosed=1;
#if (DEBUG_TCPCOPY)
			log_info(LOG_INFO,"set client closed flag:%u",
					src_port);
#endif
		}
	}
	lastRespPacketSize=tot_len;

}

/**
 * processing client packets
 * TODO
 * TCP is always allowed to send 1 byte of data 
 * beyond the end of a closed window which confuses tcpcopy
 * It will be resolved later
 * 
 */
void session_st::process_recv(struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
#if (DEBUG_TCPCOPY)
	outputPacket(LOG_DEBUG,CLIENT_FLAG,ip_header,tcp_header);
#endif	
	if(SYN_SEND==virtual_status)
	{
		time_t now=time(0);
		int diff=now-createTime;
		if(diff>3)
		{
			//retransmit the first syn packet 
			retransmitPacket();
			createTime=now;
		}
	}
	if(hasMoreNewSession)
	{
		nextSessionBuffer.push_back(copy_ip_packet(ip_header));

#if (DEBUG_TCPCOPY)
		log_info(LOG_INFO,"buffer the packet for next session:%u",src_port);
#endif
		return;
	}

	uint16_t tot_len = ntohs(ip_header->tot_len);
	uint32_t size_ip = ip_header->ihl<<2;
	uint32_t size_tcp = tcp_header->doff<<2;
	uint32_t cont_size=tot_len-size_tcp-size_ip;
#if (TCPCOPY_MYSQL_BASIC)
	unsigned char* payload=NULL;
#endif
	if(cont_size>0)
	{
		clt_con_packs_cnt++;
	}
	//check if it needs sending fin to backend
	if(sess_candidate_erased)
	{
		if(!isClientClosed)
		{
			sendFakedFinToBackByCliePack(ip_header,tcp_header);
			isClientClosed=1;
#if (DEBUG_TCPCOPY)
			log_info(LOG_INFO,"set client closed flag:%u",
					src_port);
#endif
		}else
		{
			sendFakedFinToBackByCliePack(ip_header,tcp_header);
		}
		return;
	}
	local_dest_ip_addr=ip_header->daddr;
	if(0 == fake_ip_addr)
	{
		client_ip_addr=ip_header->saddr;
	}
	if(isPureRequestBegin)
	{
		uint32_t seq=ntohl(tcp_header->seq)-total_seq_omit;
		tcp_header->seq=htonl(seq);
	}
	tcp_header->window=65535;
	client_ip_id = ip_header->id;

	if(fake_ip_addr!=0||fake_src_port!=0)
	{
		ip_header->saddr=fake_ip_addr;
		tcp_header->seq=htonl(vir_next_seq);
		tcp_header->source=fake_src_port;
	}
	//processing the reset packet
	if(tcp_header->rst)
	{
		isClientReset=1;
#if (DEBUG_TCPCOPY)
		log_info(LOG_INFO,"reset from client");
#endif
		if(candidate_response_waiting)
		{
#if (DEBUG_TCPCOPY)
			log_info(LOG_INFO,"push reset pack from cli");
#endif
			unsend.push_back(copy_ip_packet(ip_header));
		}else
		{
			wrap_send_ip_packet(fake_ip_addr,(unsigned char *) ip_header,
					virtual_next_sequence,1);
			reset_flag = 1;
		}
		return;
	}
	/* processing the syn packet */
	if(tcp_header->syn)
	{
		isSynIntercepted=1;
		src_port=ntohs(tcp_header->source);
#if (DEBUG_TCPCOPY)
		log_info(LOG_INFO,"syn port:%u",src_port);
#endif
#if (TCPCOPY_MYSQL_BASIC)
		/* remove old mysql info*/
		MysqlIterator iter=mysqlContainer.find(src_port);
		dataContainer* datas=NULL;
		if(iter!= mysqlContainer.end())
		{
			datas=iter->second;
			for(dataIterator subIter=datas->begin();
					subIter!=datas->end();)
			{
				free(*(subIter++));
			}
			mysqlContainer.erase(iter);
			delete(datas);
#if (DEBUG_TCPCOPY)
			log_info(LOG_INFO,"remove old mysql info");
#endif
		}
#endif
		unsigned char *data=copy_ip_packet(ip_header);
		handshakePackets.push_back(data);
		wrap_send_ip_packet(fake_ip_addr,(unsigned char *)ip_header,
				virtual_next_sequence,1);
		return;
	}
	if(0 == src_port)
	{
		src_port=ntohs(tcp_header->source);
	}
	/* processing the fin packet */
	if(tcp_header->fin)
	{
#if (DEBUG_TCPCOPY)
		log_info(LOG_DEBUG,"recv fin packet from cli");
#endif
		if(cont_size>0)
		{
#if (DEBUG_TCPCOPY)
			log_info(LOG_INFO,"fin has content");
#endif
		}else
		{
			if(isFakedSendingFinToBackend)
			{
				return;
			}
			/* client sends fin ,and the server acks it */
			if(virtual_ack == tcp_header->seq)
			{
				if(candidate_response_waiting)
				{
#if (DEBUG_TCPCOPY)
					log_info(LOG_DEBUG,"push back packet");
#endif
					unsend.push_back(copy_ip_packet(ip_header));
				}else
				{
					while(! unsend.empty())
					{
						unsigned char *data = unsend.front();
						free(data);
						unsend.pop_front();
					}
					wrap_send_ip_packet(fake_ip_addr,(unsigned char *)ip_header,
							virtual_next_sequence,1);
					virtual_status |= CLIENT_FIN;
					confirmed=1;
					isClientClosed=1;
#if (DEBUG_TCPCOPY)
					log_info(LOG_INFO,"set client closed flag:%u",
							src_port);
#endif
				}
			}
			else
			{
#if (DEBUG_TCPCOPY)
				log_info(LOG_DEBUG,"push back packet");
#endif
				unsend.push_back(copy_ip_packet(ip_header));
				if(check_dead_reqs())
				{
					send_reserved_packets();
				}
			}
			return;
		}
	}


	uint32_t tmpLastAck=lastAck;
	bool isNewRequest=0;
	bool isNeedOmit=0;
	if(!isSynIntercepted)
	{
		isHalfWayIntercepted=1;
	}
#if (TCPCOPY_MYSQL_BASIC)
	if(isSynIntercepted)
	{
		if(!isGreeingReceived&&isHalfWayIntercepted)
		{
			if(cont_size>0)
			{
				req_cont_pack_num++;
			}
#if (DEBUG_TCPCOPY)
			log_info(LOG_DEBUG,"push back pack for half");
#endif
			unsend.push_back(copy_ip_packet(ip_header));
			return;
		}
		if(0==cont_size&&!isGreeingReceived)
		{
#if (DEBUG_TCPCOPY)
			log_info(LOG_DEBUG,"push back ack for not recv greet");
#endif
			unsend.push_back(copy_ip_packet(ip_header));
			return;
		}
	}
#endif
	if(cont_size>0)
	{
		req_cont_pack_num++;
#if (TCPCOPY_MYSQL_BASIC)
		if(!isHalfWayIntercepted)
		{
#if (TCPCOPY_MYSQL_ADVANCED)
			if(!isFirstAuthSent)
			{
				if(isGreeingReceived)
				{
					log_info(LOG_WARN,"a mysql login request from main");
					payload=(unsigned char*)((char*)tcp_header+size_tcp);
					int result=change_client_auth_content(payload,cont_size,
							scrambleBuf,password);
					strace_packet_info(LOG_WARN,CLIENT_FLAG,
							ip_header,tcp_header);
					log_info(LOG_WARN,"password:%s,p:%u",password,src_port);
					if(!result)
					{
						log_info(LOG_WARN,"it should never reach here");
						log_info(LOG_WARN,"it is strange here,possibility");
						log_info(LOG_WARN,"1)user password pair not equal");
						log_info(LOG_WARN,"2)half-intercepted");
						over_flag=1;
						return;
					}
					isFirstAuthSent=1;

					uint64_t value=get_ip_port_value(ip_header->saddr,
							tcp_header->source);
					AuthPackIterator iter = firAuthPackContainer.find(value);
					if(iter != firAuthPackContainer.end())
					{
						struct iphdr *packet=iter->second;
						free(packet);
						log_info(LOG_WARN,"free value for fir auth:%llu",value);
					}
					struct iphdr *packet=NULL;
					packet=(struct iphdr*)copy_ip_packet(ip_header);
					firAuthPackContainer[value]=packet;
					log_info(LOG_WARN,"set value for fir auth:%llu",value);

				}
			}else if(isFirstAuthSent&&isNeedSecondAuth)
			{
				log_info(LOG_WARN,"a mysql second login req from reserved:%u",
						src_port);
				payload=(unsigned char*)((char*)tcp_header+size_tcp);
				char encryption[16];
				memset(encryption,0,16);
				memset(seed323,0,SEED_323_LENGTH+1);
				memcpy(seed323,scrambleBuf,SEED_323_LENGTH);
				new_crypt(encryption,password,seed323);
				log_info(LOG_WARN,"change second request:%u",src_port);
				change_client_second_auth_content(payload,cont_size,encryption);
				isNeedSecondAuth=0;
				strace_packet_info(LOG_WARN,CLIENT_FLAG,ip_header,
						tcp_header);
				uint64_t value=get_ip_port_value(ip_header->saddr,
						tcp_header->source);
				AuthPackIterator iter = secAuthPackContainer.find(value);
				if(iter != secAuthPackContainer.end())
				{
					struct iphdr *packet=iter->second;
					free(packet);
					log_info(LOG_WARN,"free sec auth packet from main:%llu",
							value);
				}
				struct iphdr *packet=NULL;
				packet=(struct iphdr*)copy_ip_packet(ip_header);
				secAuthPackContainer[value]=packet;
				log_info(LOG_WARN,"set sec auth packet from main:%llu",value);
			}
#endif
#if (!TCPCOPY_MYSQL_ADVANCED)
			if(!isPureRequestBegin)
			{
				//check if mysql protocol validation ends?
				payload=(unsigned char*)((char*)tcp_header+size_tcp);
				//skip  Packet Length
				payload=payload+3;
				unsigned char packetNumber=payload[0];
				//if it is the second authenticate_user,then skip it
				if(3==packetNumber)
				{
					isNeedOmit=1;
					isPureRequestBegin=1;
#if (DEBUG_TCPCOPY)
					log_info(LOG_INFO,"this is the sec auth packet");
#endif
				}
				if(0==packetNumber)
				{
					isPureRequestBegin=1;
#if (DEBUG_TCPCOPY)
					log_info(LOG_INFO,"it has no sec auth packet");
#endif
				}
			}
#else
			isPureRequestBegin=1;
#endif
			if(isNeedOmit)
			{
				log_info(LOG_NOTICE,"omit sec validation for mysql");
				total_seq_omit=cont_size;
				g_seq_omit=total_seq_omit;
				req_cont_pack_num--;
				return;
			}
			if(!isPureRequestBegin)
			{
				handshakeExpectedPackets++;
				unsigned char *data=copy_ip_packet(ip_header);
				handshakePackets.push_back(data);

				if(!fir_auth_user_pack)
				{
					fir_auth_user_pack=(struct iphdr*)copy_ip_packet(ip_header);
#if (DEBUG_TCPCOPY)
					log_info(LOG_INFO,"set global fir auth packet");
#endif
				}
				if(isGreeingReceived)
				{
					isLoginReceived=1;
					loginCanSendFlag=1;
				}else
				{
					if(!isLoginReceived)
					{
						isLoginReceived=1;
#if (DEBUG_TCPCOPY)
						log_info(LOG_DEBUG,"push back mysql login req");
#endif
						unsend.push_back(copy_ip_packet(ip_header));
						return;
					}
				}
			}
			checkMysqlPacketNeededForReconnection(ip_header,tcp_header);
			if(!isGreeingReceived)
			{
#if (DEBUG_TCPCOPY)
				log_info(LOG_DEBUG,"push back client packs for mysql");
#endif
				unsend.push_back(copy_ip_packet(ip_header));
				return;
			}
		}
#endif
		if(candidate_response_waiting)
		{
			double diff=time(0)-req_last_send_cont_time;
			if(diff>300)
			{	
				//if the sesssion recv no response for more than 5 min
				//then enter the suicide process
				logLevel=LOG_DEBUG;
				log_info(LOG_WARN,"no res back,req:%u,res:%u,p:%u",
						req_cont_pack_num,respContentPackets,src_port);
				if(req_cont_pack_num>vir_send_cont_pack_num)
				{
					size_t diffReqCont=req_cont_pack_num-vir_send_cont_pack_num;
					if(diffReqCont>200)
					{
						log_info(LOG_WARN,"lost packets:%u,p:%u",
								diffReqCont,src_port);
						over_flag=1;
						return;
					}
				}
			}
		}
	}
	/* data packet or the third packet */
	if(virtual_status ==SYN_SEND)
	{
		if(!isSynIntercepted)
		{
			establishConnectionForNoSynPackets(ip_header,tcp_header);
			unsend.push_back(copy_ip_packet(ip_header));
			return;
		}
		if(!isHalfWayIntercepted&&
				handshakePackets.size()<handshakeExpectedPackets)
		{
#if (DEBUG_TCPCOPY)
			log_info(LOG_DEBUG,"buffer the handshake packet");
#endif
			unsigned char *data=copy_ip_packet(ip_header);
			handshakePackets.push_back(data);
		}
		//when client sends multi-packets more quickly than the local network
		unsend.push_back(copy_ip_packet(ip_header));
#if (DEBUG_TCPCOPY)
		log_info(LOG_DEBUG,"SYN_SEND push back the packet from cli");
#endif
	}
	else
	{
		if(tcp_header->ack)
		{
			isRequestComletely=1;
			isRequestBegin=0;
		}

		if(cont_size>0)
		{
			lastAck=ntohl(tcp_header->ack_seq);
			if(lastAck!=tmpLastAck)
			{
				isNewRequest=1;
				isRequestComletely=0;
				isRequestBegin=1;
			}
#if (DEBUG_TCPCOPY)
			log_info(LOG_DEBUG,"it is a request from client");
#endif
			if(isTestConnClosed)
			{
				//if the connection to the backend is closed,then we 
				//reestablish the connection and 
				//we reserve all comming packets for later disposure
#if (TCPCOPY_MYSQL_BASIC)
				if(checkPacketPaddingForMysql(ip_header,tcp_header))
				{
#if (DEBUG_TCPCOPY)
					log_info(LOG_WARN,"init session");
#endif
					initSessionForKeepalive();
					establishConnectionForNoSynPackets(ip_header,
							tcp_header);
					unsend.push_back(copy_ip_packet(ip_header));
				}
#else
#if (DEBUG_TCPCOPY)
				log_info(LOG_INFO,"init session");
#endif
				initSessionForKeepalive();
				establishConnectionForClosedConn();
				unsend.push_back(copy_ip_packet(ip_header));
#endif
				return;
			}
			if(!isSynIntercepted)
			{
				establishConnectionForNoSynPackets(ip_header,tcp_header);
				unsend.push_back(copy_ip_packet(ip_header));
				return;
			}
			if(checkRetransmission(tcp_header,req_last_cont_seq))
			{
				req_cont_pack_num--;
#if (DEBUG_TCPCOPY)
				log_info(LOG_DEBUG,"it is a retransmit from client");
#endif
				return;
			}else
			{
				if(candidate_response_waiting)
				{
					bool savePacket=0;
					if(isNewRequest&&checkTcpSeg(tcp_header,req_last_cont_seq))
					{
						savePacket=1;
					}else
					{
						size_t baseConPackets=req_cont_pack_num-1;
						if(vir_send_cont_pack_num<baseConPackets)
						{
#if (DEBUG_TCPCOPY)
							log_info(LOG_INFO,
									"it has reserved cont packs:%u,%u",
									vir_send_cont_pack_num,baseConPackets);
#endif
							if(check_reserved_content_left())
							{
#if (DEBUG_TCPCOPY)
								log_info(LOG_INFO,"save pack");
#endif
								savePacket=1;
							}
						}
					}
					if(savePacket)
					{
#if (DEBUG_TCPCOPY)
						log_info(LOG_DEBUG,"push back the packet");
#endif
						unsend.push_back(copy_ip_packet(ip_header));
						if(check_dead_reqs())
						{
							send_reserved_packets();
						}
						return;
					}
				}
				if(!response_waiting)
				{
					if(checkPacketLost(ip_header,tcp_header,vir_next_seq))
					{
						if(check_reserved_content_left())
						{
#if (DEBUG_TCPCOPY)
							log_info(LOG_DEBUG,"push back the pack");
#endif
							unsend.push_back(copy_ip_packet(ip_header));
							return;
						}
						lostPackets.push_back(copy_ip_packet(ip_header));
#if (DEBUG_TCPCOPY)
						log_info(LOG_DEBUG,"lost and need prev pack");
#endif
						previous_packet_waiting=1;
						return;
					}
					if(previous_packet_waiting)
					{
						//we do not support session when  two packets are 
						//lost and retransmitted
						req_last_ack_seq=ntohl(tcp_header->ack_seq);
						wrap_send_ip_packet(fake_ip_addr,
								(unsigned char *)ip_header,
								virtual_next_sequence,1);
						sendReservedLostPackets();
						candidate_response_waiting=1;
						return;
					}
				}
				virtual_status=SEND_REQUEST;
				if(candidate_response_waiting&&checkTcpSeg(tcp_header,req_last_cont_seq)&&
						!isNewRequest)
				{
					isSegContinue=1;
					req_last_ack_seq=ntohl(tcp_header->ack_seq);
					wrap_send_ip_packet(fake_ip_addr,
							(unsigned char *)ip_header,virtual_next_sequence,1);
#if (DEBUG_TCPCOPY)
					log_info(LOG_DEBUG,"it is a continuous req");
#endif
				}
				req_last_cont_seq=ntohl(tcp_header->seq);
				if(isSegContinue)
				{
					isSegContinue=0;
					return;
				}else
				{
					requestProcessed++;
					if(requestProcessed>30)
					{
						isKeepalive=1;
					}
#if (DEBUG_TCPCOPY)
					log_info(LOG_DEBUG,"a new request from client");
#endif
				}
			}
		}else
		{
			if(handshakePackets.size()<handshakeExpectedPackets)
			{
				unsigned char *data=copy_ip_packet(ip_header);
				handshakePackets.push_back(data);
			}
		}
		if(candidate_response_waiting)
		{
			unsend.push_back(copy_ip_packet(ip_header));
#if (DEBUG_TCPCOPY)
			log_info(LOG_DEBUG,"wait backent server's response");
#endif
			if(check_dead_reqs())
			{
				send_reserved_packets();
			}
		}else
		{
			if(isClientClosed)
			{
				unsend.push_back(copy_ip_packet(ip_header));
#if (DEBUG_TCPCOPY)
				log_info(LOG_DEBUG,"save ack for server fin");
#endif
				if(check_dead_reqs())
				{
					send_reserved_packets();
				}
			}else
			{
				if(SEND_REQUEST==virtual_status)
				{
					candidate_response_waiting=1;
				}
				if(!isResponseCompletely)
				{
					req_last_ack_seq=ntohl(tcp_header->ack_seq);
					wrap_send_ip_packet(fake_ip_addr,
							(unsigned char *)ip_header,virtual_next_sequence,1);
				}
			}
		}
	}
}

void session_st::restoreBufferedSession()
{
	unsigned char *data = unsend.front();
	unsend.pop_front();
	struct iphdr *ip_header=(struct iphdr*)((char*)data);
	uint32_t size_ip = ip_header->ihl<<2;
	struct tcphdr* tcp_header = (struct tcphdr*)((char *)ip_header+size_ip);
	process_recv(ip_header,tcp_header);
	free(data);
}

/**
 * filter packets 
 */
bool isPacketNeeded(const char *packet)
{
	bool isNeeded=0;
	struct tcphdr *tcp_header;
	struct iphdr *ip_header;
	uint32_t size_ip;
	uint32_t size_tcp;

	ip_header = (struct iphdr*)packet;
	//check if it is a tcp packet
	if(ip_header->protocol != IPPROTO_TCP)
	{
		return isNeeded;
	}

	size_ip = ip_header->ihl<<2;
	uint32_t pack_size=ntohs(ip_header->tot_len);
	if (size_ip < 20) {
		log_info(LOG_WARN,"Invalid IP header length: %d", size_ip);
		return isNeeded;
	}
	tcp_header = (struct tcphdr*)((char *)ip_header+size_ip);
	size_tcp = tcp_header->doff<<2;
	if (size_tcp < 20) {
		log_info(LOG_WARN,"Invalid TCP header length: %d bytes,packet len:%d",
				size_tcp,pack_size);
		return isNeeded;
	}
	if(pack_size>RECV_BUF_SIZE)
	{
		strace_packet_info(LOG_NOTICE,CLIENT_FLAG,ip_header,
							tcp_header);
		log_info(LOG_WARN,"packet sizeis wrong:%u",pack_size);
		return isNeeded;
	}
	//here we filter the packets we do care about
	{
		//because it may use several virtual ip addresses 
		if(checkLocalIPValid(ip_header->daddr) && 
				(tcp_header->dest==local_port))
		{
			isNeeded=1;
			if(tcp_header->syn)
			{
				clt_syn_cnt++;
			}
			clt_packs_cnt++;
		}
	}
	return isNeeded;
}

/**
 * the main procedure for processing the filtered packets
 */
void process(char *packet)
{
	struct tcphdr *tcp_header=NULL;
	struct iphdr *ip_header=NULL;
	uint32_t size_ip;
	time_t now=time(0);
	double diff=now-last_stat_time;
	if(diff > 10)
	{
		last_stat_time=now;
		//this is for checking memory leak
		log_info(LOG_WARN,
				"active_sess_cnt:%llu,total syns:%llu,rel reqs:%llu,obs del:%llu",
				active_sess_cnt,enter_cnt,leave_cnt,del_obs_cnt);
		log_info(LOG_WARN,"total conns:%llu,total reqs:%llu,total resps:%llu",
				conn_cnt,req_cnt,resp_cnt);
		if(bak_cnt>0)
		{
			log_info(LOG_WARN,"bak_cnt:%llu,bak_cnt_t:%f,avg=%f",
					bak_cnt,bak_cnt_t,bak_cnt_t/bak_cnt);
		}
		log_info(LOG_WARN,"clt_cnt:%llu,clt_cnt_t:%f,avg=%f",
				clt_cnt,clt_cnt_t,clt_cnt_t/clt_cnt);
		log_info(LOG_WARN,"send Packets:%llu,send content packets:%llu",
				packs_sent_cnt,con_packs_sent_cnt);
		log_info(LOG_WARN,"total cont Packs from cli:%llu",clt_con_packs_cnt);
		clear_timeout_sessions();
		double ratio=0;
		if(enter_cnt>0)
		{
			ratio=100.0*conn_cnt/enter_cnt;
		}else
		{
			ratio=100.0*conn_cnt/(enter_cnt+1);
		}

		log_info(LOG_NOTICE,"total reconnect for closed :%llu,for no syn:%llu",
				recon_for_closed_cnt,recon_for_no_syn_cnt);
		log_info(LOG_NOTICE,"total successful retransmit:%llu",
				retrans_succ_cnt);
		log_info(LOG_NOTICE,"syn total:%llu,all client packets:%llu",
				clt_syn_cnt,clt_packs_cnt);
		if(enter_cnt>100&&ratio<80)
		{
			log_info(LOG_WARN,"many connections can't be established");
		}
	}
	if(last_ch_dead_sess_time>0)
	{
		double diff=now-last_ch_dead_sess_time;
		if(diff>2)
		{
			if(sessions.size()>0)
			{
				send_deadly_sessions();
				last_ch_dead_sess_time=now;
			}
		}
	}

	ip_header = (struct iphdr*)packet;
	size_ip = ip_header->ihl<<2;
	tcp_header = (struct tcphdr*)((char *)ip_header+size_ip);

	if((ip_header->saddr==remote_ip) && (tcp_header->source==remote_port) )
	{
		//when the packet comes from the targeted test machine
		uint32_t clientIP=ip_header->daddr;
		uint64_t key=get_ip_port_value(ip_header->daddr,tcp_header->dest);
		{
			//try to find session through fake ip
			IPIterator ipIter=trueIPContainer.find(key);
			if(ipIter!= trueIPContainer.end())
			{
				clientIP=ipIter->second;
			}
		}
		SessIterator iter = sessions.find(get_ip_port_value(clientIP,
					tcp_header->dest));
		if(iter != sessions.end())
		{
			iter->second.confirmed=0;
			iter->second.lastUpdateTime=now;
			struct timeval start=getTime();
			bak_cnt++;
			iter->second.update_virtual_status(ip_header,tcp_header);
			struct timeval end=getTime();
			bak_cnt_t+=end.tv_sec-start.tv_sec;
			bak_cnt_t+=(end.tv_usec-start.tv_usec)/1000000.0;
			if( iter->second.is_over())
			{
				if(iter->second.hasMoreNewSession)
				{
					iter->second.initForNextSession();
					log_info(LOG_NOTICE,"init for next session from backend");
					iter->second.restoreBufferedSession();
					return;
				}else
				{
					active_sess_cnt--;
					leave_cnt++;
					sessions.erase(iter);
				}
			}
		}else
		{
			//it may happen when the last packet comes from backend
		}
	}
	else if(checkLocalIPValid(ip_header->daddr) && 
			(tcp_header->dest==local_port))
	{
		//when the packet comes from client
		last_ch_dead_sess_time=now;
		if(port_shift_factor)
		{
			uint16_t tmp_port_addition=(2048<<port_shift_factor)+rand_shift_port;
			uint16_t transfered_port=ntohs(tcp_header->source);
			if(transfered_port<=(65535-tmp_port_addition))
			{
				transfered_port=transfered_port+tmp_port_addition;
			}else
			{
				transfered_port=1024+tmp_port_addition;
			}
			tcp_header->source=htons(transfered_port);
		}
		uint64_t value=get_ip_port_value(ip_header->saddr,tcp_header->source);
		if(tcp_header->syn)
		{
			enter_cnt++;
			SessIterator iter = sessions.find(value);
			if(iter != sessions.end())
			{
				//check if it is a duplicate syn
				int diff=now-iter->second.createTime;
				if(tcp_header->seq==iter->second.synSeq)
				{
					enter_cnt--;
#if (DEBUG_TCPCOPY)
					log_info(LOG_INFO,"duplicate syn,time diff:%d",diff);
					strace_packet_info(LOG_INFO,CLIENT_FLAG,ip_header,
							tcp_header);
#endif
					return;
				}else
				{
					//buffer the next session to current session
					iter->second.hasMoreNewSession=1;
					iter->second.nextSessionBuffer.push_back
						(copy_ip_packet(ip_header));
#if (DEBUG_TCPCOPY)
					log_info(LOG_INFO,"buffer the new session");
					strace_packet_info(LOG_INFO,CLIENT_FLAG,ip_header,
							tcp_header);
#endif
					return;
				}
			}else
			{
				active_sess_cnt++;
			}
			int sock=address_find_sock(tcp_header->dest);
			if(-1 == sock)
			{
				log_info(LOG_WARN,"sock is invalid in process");
				strace_packet_info(LOG_WARN,CLIENT_FLAG,ip_header,tcp_header);
				return;
			}
			int result=msg_copyer_send(sock,ip_header->saddr,
					tcp_header->source,CLIENT_ADD);
			if(-1 == result)
			{
				log_info(LOG_ERR,"msg coper send error");
				return;
			}else
			{
				struct timeval start=getTime();
				clt_cnt++;
				sessions[value].process_recv(ip_header,tcp_header);
				struct timeval end=getTime();
				clt_cnt_t+=end.tv_sec-start.tv_sec;
				clt_cnt_t+=(end.tv_usec-start.tv_usec)/1000000.0;
				iter = sessions.find(value);
				iter->second.synSeq=tcp_header->seq;
			}
		}
		else
		{
			SessIterator iter = sessions.find(value);
			if(iter != sessions.end())
			{
				iter->second.confirmed=0;
				struct timeval start=getTime();
				clt_cnt++;
				iter->second.process_recv(ip_header,tcp_header);
				struct timeval end=getTime();
				clt_cnt_t+=end.tv_sec-start.tv_sec;
				clt_cnt_t+=(end.tv_usec-start.tv_usec)/1000000.0;
				iter->second.lastUpdateTime=now;
				if( (iter->second.is_over()))
				{
					if(iter->second.hasMoreNewSession)
					{
						iter->second.initForNextSession();
						log_info(LOG_NOTICE,"init for next session from client");
						iter->second.restoreBufferedSession();
						return;
					}else
					{
						active_sess_cnt--;
						leave_cnt++;
						sessions.erase(iter);
					}
				}
			}else
			{
				//we check if we can pad tcp handshake for this request
				if(checkPacketPadding(ip_header,tcp_header))
				{
					active_sess_cnt++;
#if (TCPCOPY_MYSQL_BASIC)
					if(checkPacketPaddingForMysql(ip_header,tcp_header))
					{
						struct timeval start=getTime();
						clt_cnt++;
						sessions[value].process_recv(ip_header,tcp_header);
						struct timeval end=getTime();
						clt_cnt_t+=end.tv_sec-start.tv_sec;
						clt_cnt_t+=(end.tv_usec-start.tv_usec)/1000000.0;
					}
#else
					struct timeval start=getTime();
					clt_cnt++;
					sessions[value].process_recv(ip_header,tcp_header);
					struct timeval end=getTime();
					clt_cnt_t+=end.tv_sec-start.tv_sec;
					clt_cnt_t+=(end.tv_usec-start.tv_usec)/1000000.0;

#endif
				}
			}
		}
	}else
	{
		//we don't know where the packet comes from
		log_info(LOG_WARN,"unknown packet");
		strace_packet_info(LOG_WARN,UNKNOWN_FLAG,ip_header,tcp_header);
	}
}

