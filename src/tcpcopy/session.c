#include "../communication/msg.h"
#include "../util/util.h"
#include "../log/log.h"
#include "send.h"
#include "address.h"
#include "session.h"
#if (TCPCOPY_MYSQL_ADVANCED)
#include "../mysql/protocol.h"
#endif

static hash_table *sessions_table;
static hash_table *tf_port_table;

#if (TCPCOPY_MYSQL_BASIC)
static hash_table *mysql_table;
#endif
#if (TCPCOPY_MYSQL_ADVANCED)
static hash_table *fir_auth_pack_table;
static hash_table *sec_auth_pack_table;
#endif

/* Total sessions deleted */
static uint64_t leave_cnt            = 0;
/* Total obsolete sessions */
static uint64_t obs_cnt              = 0;
/* Total client syn packets */
static uint64_t clt_syn_cnt          = 0;
/* Total client content packets */
static uint64_t clt_cont_cnt         = 0;
/* Total client packets */
static uint64_t clt_packs_cnt        = 0;
/* Total client packets sent to backend */
static uint64_t packs_sent_cnt       = 0;
/* Total client content packets sent to backend */
static uint64_t con_packs_sent_cnt   = 0;
/* Total response packets */
static uint64_t resp_cnt             = 0;
/* Total response content packets */
static uint64_t resp_cont_cnt        = 0;
/* Total connections successfully cheated */
static uint64_t conn_cnt             = 0;
/* Total successful retransmission */
static uint64_t retrans_succ_cnt     = 0;
/* Total reconnections for backend */
static uint64_t recon_for_closed_cnt = 0;
/* Total reconnections for halfway interception */
static uint64_t recon_for_no_syn_cnt = 0;
/* Last time for statistics */
static time_t   last_stat_time       = 0;
/* Start time for excuting the process function */
static time_t   start_p_time         = 0;
#if (TCPCOPY_MYSQL_BASIC)
/* Global sequence omission */
static uint32_t g_seq_omit           = 0;
/* The global first auth user packet */
static struct iphdr *fir_auth_u_p    = NULL;
#endif

static bool check_session_over(session_t *s)
{
    if(s->reset){   
        return true;
    }   
    if(s->sess_over){   
        return true;
    }   
    return false;
}

static bool trim_packet(session_t *s, struct iphdr *ip_header, 
        struct tcphdr *tcp_header, uint32_t diff)
{
    uint16_t      size_ip, size_tcp, tot_len, cont_len;
    unsigned char *payload;

    size_ip   = ip_header->ihl << 2;
    tot_len   = ntohs(ip_header->tot_len);
    size_ip   = ip_header->ihl << 2;
    size_tcp  = tcp_header->doff << 2;
    cont_len  = tot_len - size_tcp - size_ip;
    if(cont_len <= diff){
        return false;
    }

    ip_header->tot_len = htons(tot_len- diff);
    tcp_header->seq    = htonl(s->vir_next_seq);
    payload = (unsigned char*)((char*)tcp_header + size_tcp);
    memmove(payload, payload + diff, cont_len - diff);
#if (DEBUG_TCPCOPY)
    log_info(LOG_NOTICE, "trim packet:%u", s->src_h_port);
#endif

    return true;
}

static uint16_t  get_pack_cont_len(struct iphdr *ip_header,
        struct tcphdr *tcp_header)
{
    uint16_t  size_ip, size_tcp, tot_len, cont_len;

    size_ip   = ip_header->ihl << 2;
    if(NULL == tcp_header){
        tcp_header = (struct tcphdr*)((char *)ip_header + size_ip);
    }
    tot_len   = ntohs(ip_header->tot_len);
    size_ip   = ip_header->ihl << 2;
    size_tcp  = tcp_header->doff << 2;
    cont_len  = tot_len - size_tcp - size_ip;
    
    return cont_len;
}


/*
 * Wrap sending ip packet function
 */
static void wrap_send_ip_packet(session_t *s, unsigned char *data, 
        bool client)
{
    struct iphdr  *ip_header;
    struct tcphdr *tcp_header;
    uint16_t      size_ip, tot_len, cont_len;
    p_link_node   ln;
    ssize_t       send_len;

    if(NULL == data){
        log_info(LOG_ERR, "error ip data is null");
        return;
    }

    ip_header  = (struct iphdr *)data;
    size_ip    = ip_header->ihl << 2;
    tcp_header = (struct tcphdr *)(data + size_ip);

    if(client){
        s->req_last_ack_sent_seq = ntohl(tcp_header->ack_seq);
    }
    if(!s->unack_pack_omit_save_flag){
        ln = link_node_malloc(copy_ip_packet(ip_header));
        link_list_append(s->unack_packets, ln);
    }
    /* Set the destination ip and port*/
    ip_header->daddr = s->dst_addr;
    tcp_header->dest = s->dst_port;
    s->vir_next_seq  = ntohl(tcp_header->seq);
    s->req_valid_last_ack_sent = 1;
    /* Add virtual next seq when meeting syn or fin packet */
    if(tcp_header->syn || tcp_header->fin){
        if(tcp_header->syn){
            s->req_valid_last_ack_sent = 0;
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

    tot_len  = ntohs(ip_header->tot_len);
    cont_len = get_pack_cont_len(ip_header, tcp_header);
    if(cont_len > 0){
        s->status = SEND_REQUEST;
        s->req_last_send_cont_time = time(0);
        s->req_last_cont_sent_seq  = htonl(tcp_header->seq);
        s->vir_next_seq = s->vir_next_seq + cont_len;
        if(s->unack_pack_omit_save_flag){
            /*It means that this packet is a retransmission packet */
            s->vir_new_retransmit = 1;
        }else{
            con_packs_sent_cnt++;
        }
    }

    tcp_header->check = 0;
    tcp_header->check = tcpcsum((unsigned char *)ip_header,
            (unsigned short *)tcp_header, (int)(tot_len - size_ip));
    /*
     * For linux 
     * The two fields that are always filled in are: the IP checksum 
     * (hopefully for us - it saves us the trouble) and the total length, 
     * iph->tot_len, of the datagram 
     */
    ip_header->check = 0;
    ip_header->check = csum((unsigned short *)ip_header, size_ip); 
#if (DEBUG_TCPCOPY)
    strace_pack(LOG_DEBUG, TO_BAKEND_FLAG, ip_header, tcp_header);
#endif
    packs_sent_cnt++;

    s->req_ip_id = ntohs(ip_header->id);
    s->unack_pack_omit_save_flag = 0;

    send_len = send_ip_packet(ip_header, tot_len);
    if(-1 == send_len){
        strace_pack(LOG_WARN, TO_BAKEND_FLAG, ip_header, tcp_header);
        log_info(LOG_ERR, "send to back error,tot_len is:%d,cont_len:%d",
                tot_len,cont_len);
    }
}

static void fill_protocol_common_header(struct iphdr *ip_header, 
        struct tcphdr *tcp_header)
{
    /* IPv4 */
    ip_header->version  = 4;
    /* The header length is the number of 32-bit words in the header */
    ip_header->ihl      = IP_HEADER_LEN/4;
    /*
     * The total length field is the total length of 
     * the IP datagram in bytes.
     * Default:FAKE_IP_DATAGRAM_LEN
     */
    ip_header->tot_len  = htons(FAKE_IP_DATAGRAM_LEN);
    /* Don't Fragment */
    ip_header->frag_off = htons(0x4000); 
    /* 
     * Sets an upper limit on the number of routers through 
     * which a datagram can pass
     */
    ip_header->ttl      = 64; 
    /* TCP packet */
    ip_header->protocol = IPPROTO_TCP;
    /* The TCP header length(the number of 32-bit words in the header) */
    tcp_header->doff    = 5;
    /* Window size(you may feel strange here) */
    tcp_header->window  = 65535;
}

/*
 * Send faked rst packet to backend passively
 */
static void send_faked_passive_rst(session_t *s)
{
    unsigned char faked_rst_buf[FAKE_IP_DATAGRAM_LEN];
    struct iphdr  *f_ip_header;
    struct tcphdr *f_tcp_header;
#if (DEBUG_TCPCOPY)
    log_info(LOG_DEBUG, "send_faked_passive_rst:%u", s->src_h_port);
#endif
    memset(faked_rst_buf, 0, FAKE_IP_DATAGRAM_LEN);
    f_ip_header  = (struct iphdr *)faked_rst_buf;
    f_tcp_header = (struct tcphdr *)(faked_rst_buf + IP_HEADER_LEN);
    fill_protocol_common_header(f_ip_header, f_tcp_header);
    f_ip_header->id       = htons(++s->req_ip_id);
    f_ip_header->saddr    = s->src_addr;
    f_tcp_header->source  = htons(s->src_h_port);
    f_tcp_header->rst     = 1;
    f_tcp_header->ack     = 1;
    
    f_tcp_header->ack_seq = s->vir_ack_seq;
    if(s->fin_add_seq){
        /* This is because of '++' in wrap_send_ip_packet */
        f_tcp_header->seq = htonl(s->vir_next_seq - 1); 
    }else{
        f_tcp_header->seq = htonl(s->vir_next_seq); 
    }
    s->unack_pack_omit_save_flag = 1;
    wrap_send_ip_packet(s, faked_rst_buf, true);
}

static bool send_router_info(uint32_t listening_port, 
        uint32_t client_ip, uint16_t client_port, uint16_t type)
{
    int sock = address_find_sock(listening_port);
    if(-1 == sock){
        log_info(LOG_WARN, "sock invalid:%u", ntohs(listening_port));
        return false;
    }
    if(-1 == msg_client_send(sock, client_ip, client_port, type)){
        log_info(LOG_ERR, "msg client send error:%u", ntohs(client_port));
        return false;
    }
    return true;
}

static void session_rel_dynamic_mem(session_t *s)
{
    uint64_t key;
    leave_cnt++;
    if(!check_session_over(s)){
        /* Send the last rst packet to backend */
        send_faked_passive_rst(s);
        send_router_info(s->online_port, s->src_addr,
                htons(s->src_h_port), CLIENT_DEL);
        s->sess_over = 1;
    }
    if(s->port_transfered){
        key = get_key(s->src_addr, s->faked_src_port);
        if(!hash_del(tf_port_table, key)){
            log_info(LOG_WARN, "no hash item for port transfer");
        }
        s->port_transfered = 0;
    }
    if(NULL != s->unsend_packets){
        link_list_clear(s->unsend_packets);
        free(s->unsend_packets);
        s->unsend_packets = NULL;
    }
    if(NULL != s->next_sess_packs){
        link_list_clear(s->next_sess_packs);
        free(s->next_sess_packs);
        s->next_sess_packs = NULL;
    }
    if(NULL != s->unack_packets){
        link_list_clear(s->unack_packets);
        free(s->unack_packets);
        s->unack_packets = NULL;
    }
#if (TCPCOPY_MYSQL_BASIC)
    if(NULL != s->mysql_special_packets){
        link_list_clear(s->mysql_special_packets);
        free(s->mysql_special_packets);
        s->mysql_special_packets = NULL;
    }
#endif
}

void init_for_sessions()
{
    /* Create 65536 slots for session table */
    sessions_table = hash_create(65536);
    strcpy(sessions_table->name, "session-table");
    tf_port_table = hash_create(65536);
    strcpy(tf_port_table->name, "transfer port table");
}

void destroy_for_sessions()
{
    size_t      i;           
    link_list   *list;
    p_link_node ln, tmp_ln;
    hash_node   *hn;
    session_t   *s;

    if(NULL == sessions_table){
        return;
    }
    /* Free session table */
    for(i = 0; i < sessions_table->size; i++){
        list = sessions_table->lists[i];
        ln   = link_list_first(list);   
        while(ln){
            tmp_ln = link_list_get_next(list, ln);
            hn = (hash_node *)ln->data;
            if(hn->data != NULL){
                s = hn->data;
                /* Delete session */
                session_rel_dynamic_mem(s);
                if(!hash_del(sessions_table, s->hash_key)){
                    log_info(LOG_ERR, "wrong del");
                }
                free(s);
            }
            ln = tmp_ln;
        }
        free(list);
    }
    free(sessions_table->lists);
    free(sessions_table);
    sessions_table = NULL;
    /* Free transfer port table */
    for(i = 0; i < tf_port_table->size; i++){
        list = tf_port_table->lists[i];
        link_list_clear(list);
        free(list);
    }
    free(tf_port_table->lists);
    free(tf_port_table);
    tf_port_table = NULL;
}

static void session_init(session_t *s, int flag)
{
    if(s->unsend_packets){
        if(s->unsend_packets->size > 0){
            link_list_clear(s->unsend_packets);
        }
        if(SESS_REUSE == flag){
            if(s->next_sess_packs != NULL){
                free(s->unsend_packets);
                s->unsend_packets = NULL;
            }
        }
    }else{
        s->unsend_packets = link_list_create();
    }

    if(s->unack_packets){
        if(s->unack_packets->size > 0){
            link_list_clear(s->unack_packets);
        }
    }else{
        s->unack_packets = link_list_create();
    }

#if (TCPCOPY_MYSQL_BASIC)
    if(SESS_CREATE == flag){
        s->mysql_special_packets = link_list_create();
    }else{
        if(s->mysql_special_packets){
            if(s->mysql_special_packets->size > 0){
                link_list_clear(s->mysql_special_packets);
            }
        }else{
            s->mysql_special_packets = link_list_create();
        }
    }
#endif

    s->status  = CLOSED;
    s->create_time      = time(0);
    s->last_update_time = s->create_time;
    s->resp_last_recv_cont_time = s->create_time;
    s->req_last_send_cont_time  = s->create_time;

    if(SESS_CREATE != flag){
        s->resp_last_same_ack_num = 0;
        s->vir_already_retransmit = 0;
        s->reset_sent = 0;
        s->vir_new_retransmit = 0;
        s->simul_closing = 0;
        s->reset = 0;
        s->fin_add_seq = 0;
        s->sess_over   = 0;
        s->src_closed  = 0;
        s->dst_closed  = 0;
        s->req_valid_last_ack_sent = 0;
        s->candidate_response_waiting = 0;
        s->is_waiting_previous_packet = 0;
        s->req_syn_ok = 0;
        s->req_halfway_intercepted = 0;
        s->resp_syn_received = 0;
        s->sess_candidate_erased = 0;
        s->sess_more = 0;
        s->port_transfered = 0;
        s->unack_pack_omit_save_flag = 0;
        s->resp_greet_received = 0;
        s->need_resp_greet = 0;
#if (TCPCOPY_MYSQL_BASIC)
        s->mysql_excute_times = 0;
        s->mysql_req_begin = 0;
        s->mysql_sec_auth = 0;
        s->mysql_first_auth_sent = 0;
        s->mysql_req_login_received = 0;
        s->mysql_prepare_stat = 0;
#endif
#if (TCPCOPY_MYSQL_ADVANCED) 
        s->mysql_cont_num_aft_greet = 0;
#endif
    }
#if (TCPCOPY_MYSQL_BASIC)
    s->mysql_first_excution = 1;
#endif
}

/*
 * We only support one more session which has the same hash key
 */
static void session_init_for_next(session_t *s)
{
    uint64_t    key;
    link_list   *list = s->next_sess_packs;
    if(s->port_transfered){
        key = get_key(s->src_addr, s->faked_src_port);
        if(!hash_del(tf_port_table, key)){
            log_info(LOG_WARN, "no hash item for port transfer");
        }
    }

    session_init(s, SESS_REUSE);

    if(NULL != list){
        s->unsend_packets  = list;
        s->next_sess_packs = NULL;
    }else{
        s->unsend_packets = link_list_create();
    }
}

static session_t *session_create(struct iphdr *ip_header,
        struct tcphdr *tcp_header)
{
    ip_port_pair_mapping_t *test;
    session_t *s = (session_t *)calloc(1, sizeof(session_t));
    if(NULL == s){
        return NULL;
    }
    session_init(s, SESS_CREATE);
    s->src_addr      = ip_header->saddr;
    s->online_addr   = ip_header->daddr;
    s->orig_src_port = tcp_header->source;
    s->src_h_port    = ntohs(tcp_header->source);
    s->online_port   = tcp_header->source;
    test = get_test_pair(&(clt_settings.transfer), 
            s->online_addr, s->online_port);
    s->dst_addr      = test->target_ip;
    s->dst_port      = test->target_port;
    return s;
}

static session_t *session_add(uint64_t key, struct iphdr *ip_header,
        struct tcphdr *tcp_header)
{
    session_t *s = session_create(ip_header, tcp_header);
    if(NULL != s){
        s->hash_key = key;
        if(!hash_add(sessions_table, key, s)){
            log_info(LOG_ERR, "session item already exist");
        }
    }
    return s;
}


static void save_packet(link_list *list, struct iphdr *ip_header,
        struct tcphdr *tcp_header)
{
    p_link_node ln = link_node_malloc(copy_ip_packet(ip_header));
    ln->key = ntohl(tcp_header->seq);
    link_list_append_by_order(list, ln);
#if (DEBUG_TCPCOPY)
    log_info(LOG_NOTICE, "save packet");
#endif
}

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
    uint32_t      cur_ack, cur_seq, diff;
    int           count = 0; 
    bool need_pause = false, cand_pause = false, omit_transfer = false; 

#if (DEBUG_TCPCOPY)
    log_info(LOG_DEBUG, "send reserved packs,size:%u, port:%u",
            s->unsend_packets->size, s->src_h_port);
#endif

    if(SYN_CONFIRM > s->status){
        return count;
    }
    list = s->unsend_packets;
    if(NULL == list){
        log_info(LOG_WARN, "list is null");
        return count;
    }
    ln = link_list_first(list); 

    while(ln && (!need_pause)){
        data = ln->data;
        ip_header  =(struct iphdr*)((char*)data);
        size_ip    = ip_header->ihl << 2;
        tcp_header = (struct tcphdr*)((char *)ip_header + size_ip);
        cur_seq    = ntohl(tcp_header->seq);
        if(cur_seq > s->vir_next_seq){
            /* We need to wait for previous packet */
#if (DEBUG_TCPCOPY)
            log_info(LOG_NOTICE, "we need to wait previous pack");
#endif
            s->is_waiting_previous_packet = 1;
            s->candidate_response_waiting = 0;
            break;
        }else if(cur_seq < s->vir_next_seq){
            cont_len   = get_pack_cont_len(ip_header, tcp_header);
            if(cont_len > 0){
                /* Special disposure here */
#if (DEBUG_TCPCOPY)
                log_info(LOG_NOTICE, "reserved strange:%u", s->src_h_port);
#endif
                diff = s->vir_next_seq - cur_seq;
                if(!trim_packet(s, ip_header, tcp_header, diff)){
                    omit_transfer = true;
                }
            }else{
                tcp_header->seq = htonl(s->vir_next_seq);
            }
        }
        cont_len   = get_pack_cont_len(ip_header, tcp_header);
        if(!omit_transfer && cont_len > 0){
            if(s->need_resp_greet&&!s->resp_greet_received){
                break;
            }
#if (TCPCOPY_MYSQL_ADVANCED) 
            if(FAILURE == mysql_dispose_auth(s, ip_header, tcp_header)){
                break;
            }
#endif
            cur_ack = ntohl(tcp_header->ack_seq);
            if(cand_pause){
                if(cur_ack != s->req_last_ack_sent_seq){
                    break;
                }
            }
            cand_pause = true;
            s->candidate_response_waiting = 1;
        }else if(tcp_header->rst){
            if(s->candidate_response_waiting){
                break;
            }
            s->reset      = 1;
            omit_transfer = false;
            need_pause    = true;
        }else if(tcp_header->fin){
            if(s->candidate_response_waiting){
                break;
            }
            need_pause = true;
            if(s->req_last_ack_sent_seq == ntohl(tcp_header->ack_seq)){
                /* Active close from client */
                s->src_closed = 1;
                s->status |= CLIENT_FIN;
            }else{
                /* Server active close */
                omit_transfer = true;
            }
        }else if(0 == cont_len){
            /* Waiting the response pack or the sec handshake pack */
            if(s->candidate_response_waiting || SYN_CONFIRM != s->status){
                omit_transfer = true;
            }
        }
        if(!omit_transfer){
            count++;
            if(s->sess_candidate_erased){
                s->sess_candidate_erased = 0;
            }
            wrap_send_ip_packet(s, data, true);
        }
        tmp_ln = ln;
        ln = link_list_get_next(list, ln);
        link_list_remove(list, tmp_ln);
        free(data);
        free(tmp_ln);

        omit_transfer = false;
    }

    return count;
}

static int check_overwhelming(session_t *s, const char *message, 
        int max_hold_packs, int size)
{
    if(size > max_hold_packs){
        if(!s->sess_candidate_erased){
            s->sess_candidate_erased = 1;
            log_info(LOG_WARN, "%s:candidate erased:%u,p:%u",
                message, size, s->src_h_port);
            return CANDIDATE_OBSOLETE;
        }
        obs_cnt++;
        log_info(LOG_WARN, "%s:too many packets:%u,p:%u",
                message, size, s->src_h_port);
        return OBSOLETE;
    }
    return NOT_YET_OBSOLETE;
}

/*
 * This happens in uploading large file situations
 */
static bool is_session_dead(session_t *s)
{
    int    packs_unsend, diff;

    packs_unsend = s->unsend_packets->size;
    diff = time(0) - s->req_last_send_cont_time;

    /* More than 2 seconds */
    if(diff > 2){
        /* If there are more than 5 packets unsend */
        if(packs_unsend > 5){
            return true;
        }
    }
    return false;
}

static void activate_dead_sessions()
{
    int          i;
    link_list    *list;
    p_link_node  ln;
    hash_node    *hn;
    session_t    *s;

    log_info(LOG_NOTICE, "activate_dead_sessions");
    for(i = 0; i < sessions_table->size; i++){
        list = sessions_table->lists[i];
        ln   = link_list_first(list);   
        while(ln){
            hn = (hash_node *)ln->data;
            if(hn->data != NULL){
                s = hn->data;
                if(s->sess_over){
                    log_info(LOG_NOTICE, "already del:%u", s->src_h_port);
                }
                if(is_session_dead(s)){
                    send_reserved_packets(s);
                }
            }
            ln = link_list_get_next(list, ln);
        }
    }
}

/* Check if session is obsolete */
static int check_session_obsolete(session_t *s, time_t cur, 
        time_t threshold_time)
{
    int threshold = 256, result, diff;  
    
    /* If not receiving response for a long time */
    if(s->resp_last_recv_cont_time < threshold_time){
        obs_cnt++;
#if (DEBUG_TCPCOPY)
        log_info(LOG_NOTICE, "timeout,unsend number:%u,p:%u",
                s->unsend_packets->size, s->src_h_port);
#endif
        return OBSOLETE;
    }
    diff = cur - s->req_last_send_cont_time;
    /* Check if the session is idle for a long time */
    if(diff < 30){
        threshold = threshold << 2;
        if(diff < 3){
            /* If it is idle for less than 3 seconds */
            threshold = threshold << 2;
        }
        if(s->last_window_full){
            /* If slide window is full */
            threshold = threshold << 2;
        }
    }

    result = check_overwhelming(s, "unsend", threshold, 
            s->unsend_packets->size);
    if(NOT_YET_OBSOLETE != result){
        return result;
    }
    result = check_overwhelming(s, "unack", threshold, 
            s->unack_packets->size);
    if(NOT_YET_OBSOLETE != result){
        return result;
    }
    if(s->next_sess_packs){
        result = check_overwhelming(s, "next session", threshold, 
                s->next_sess_packs->size);
        if(NOT_YET_OBSOLETE != result){
            return result;
        }
    }
#if (TCPCOPY_MYSQL_BASIC)
    result = check_overwhelming(s, "mysql special", threshold, 
            s->mysql_special_packets->size);
    if(NOT_YET_OBSOLETE != result){
        return result;
    }
#endif
    return NOT_YET_OBSOLETE;
}

/*
 * Clear TCP timeout sessions
 */
static void clear_timeout_sessions()
{
    time_t      current, threshold_time;
    size_t      i;           
    int         result;
    link_list   *list;
    p_link_node ln, tmp_ln;
    hash_node   *hn;
    session_t   *s;

    current = time(0);
    threshold_time = current - clt_settings.session_timeout;

    log_info(LOG_NOTICE, "session size:%u", sessions_table->total);

    for(i = 0; i < sessions_table->size; i++){
        list = sessions_table->lists[i];
        if(!list){
            log_info(LOG_WARN, "list is null in sess table");
            continue;
        }
        ln   = link_list_first(list);   
        while(ln){
            tmp_ln = link_list_get_next(list, ln);
            hn = (hash_node *)ln->data;
            if(hn->data != NULL){
                s = hn->data;
                if(s->sess_over){
                    log_info(LOG_WARN, "wrong,del:%u", s->src_h_port);
                }
                result = check_session_obsolete(s, current, threshold_time);
                if(OBSOLETE == result){
                    /* Release memory for session internals */
                    session_rel_dynamic_mem(s);
                    /* Remove session from table */
                    if(!hash_del(sessions_table, s->hash_key)){
                        log_info(LOG_ERR, "wrong del:%u", s->src_h_port);
                    }
                    free(s);
                }
            }
            ln = tmp_ln;
        }
    }
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
    uint32_t      cur_seq, expected_seq;
    p_link_node   ln, tmp_ln;
    link_list     *list;
    bool need_pause = false, is_success = false;

    expected_seq = s->vir_next_seq;
    list = s->unack_packets;
    ln = link_list_first(list); 

    while(ln && (!need_pause)){
        data = ln->data;
        ip_header  = (struct iphdr *)((char *)data);
        size_ip    = ip_header->ihl << 2;
        tcp_header = (struct tcphdr *)((char *)ip_header + size_ip);
        if(SYN_SENT == s->status){
            /* Don't retransmit the first handshake packet */
            break;
        }
        cont_len = get_pack_cont_len(ip_header, tcp_header);
        cur_seq  = ntohl(tcp_header->seq);  
        if(!is_success){
            if(cur_seq == s->resp_last_ack_seq){
                is_success = true;
            }else if(cur_seq < s->resp_last_ack_seq){
                tmp_ln = ln;
                ln = link_list_get_next(list, ln);
                link_list_remove(list, tmp_ln);
                free(data);
                free(tmp_ln);
            }else{
                log_info(LOG_NOTICE, "no retrans packs:%u", s->src_h_port);
                need_pause = true;
            }
        }
        if(is_success){
            /* Retransmit until vir_next_seq*/
            if(cur_seq < expected_seq){
                s->unack_pack_omit_save_flag = 1;
#if (DEBUG_TCPCOPY)
                log_info(LOG_NOTICE, "retransmit packs:%u", s->src_h_port);
#endif
                wrap_send_ip_packet(s, data, true);
                ln = link_list_get_next(list, ln);
            }else{
                need_pause = true;  
            }
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
        data       = ln->data;
        ip_header  = (struct iphdr*)((char*)data);
        size_ip    = ip_header->ihl << 2;
        tcp_header = (struct tcphdr*)((char *)ip_header + size_ip);
        cur_seq    = ntohl(tcp_header->seq);  
        if(cur_seq < s->resp_last_ack_seq){
            tmp_ln = ln;
            ln = link_list_get_next(list, ln);
            link_list_remove(list, tmp_ln);
            free(data);
            free(tmp_ln);
        }else{
            break;
        }
    }
    return;
}

/*
 * Check if the reserved container has content left
 */
static bool check_reserved_content_left(session_t *s)
{
    unsigned char *data;
    struct iphdr  *ip_header;
    p_link_node   ln;
    link_list     *list;
    uint16_t      cont_len;

#if (DEBUG_TCPCOPY)
    log_info(LOG_DEBUG, "check_reserved_content_left");
#endif
    list = s->unsend_packets;
    ln = link_list_first(list); 

    while(ln){
        data = ln->data;
        ip_header = (struct iphdr*)((char*)data);
        cont_len  = get_pack_cont_len(ip_header, NULL);
        if(cont_len > 0){
            return true;
        }
        ln = link_list_get_next(list, ln);
    }
    return false;
}

#if (TCPCOPY_MYSQL_ADVANCED)
static int mysql_dispose_auth(session_t *s, struct iphdr *ip_header,
        struct tcphdr *tcp_header)
{
    void          *value;
    char          encryption[16];
    int           ch_auth_success;
    unsigned char *payload;
    uint16_t      size_tcp, cont_len;

    size_tcp = tcp_header->doff << 2;
    cont_len = get_pack_cont_len(ip_header, tcp_header);

    if(!s->mysql_first_auth_sent){
        log_info(LOG_NOTICE, "mysql login req from reserved");
        payload = (unsigned char*)((char*)tcp_header + size_tcp);
        ch_auth_success = change_client_auth_content(payload, 
                (int)cont_len, s->mysql_password, s->mysql_scramble);
        strace_pack(LOG_NOTICE, CLIENT_FLAG, ip_header, tcp_header);
        if(!ch_auth_success){
            s->sess_over  = 1;
            log_info(LOG_WARN, "it is strange here,possibility");
            log_info(LOG_WARN, "1)user password pair not equal");
            log_info(LOG_WARN, "2)half-intercepted");
            return FAILURE;
        }
        s->mysql_first_auth_sent = 1;
        value = hash_find(fir_auth_pack_table, s->hash_key);
        if(value != NULL){
            free(value);
            log_info(LOG_NOTICE, "free for fir auth:%llu", s->hash_key);
        }
        value = (void *)copy_ip_packet(ip_header);
        hash_add(fir_auth_pack_table, s->hash_key, value);
        log_info(LOG_NOTICE, "set value for fir auth:%llu", s->hash_key);
    }else if(s->mysql_first_auth_sent && s->mysql_sec_auth){
        log_info(LOG_NOTICE, "sec login req from reserved");
        payload = (unsigned char*)((char*)tcp_header + size_tcp);
        memset(encryption, 0, 16);
        memset(s->mysql_seed323, 0, SEED_323_LENGTH + 1);
        memcpy(s->mysql_seed323, s->mysql_scramble, SEED_323_LENGTH);
        new_crypt(encryption, s->mysql_password, s->mysql_seed323);
        log_info(LOG_NOTICE, "change second req:%u", s->src_h_port);
        /* Change sec auth content from client auth packets */
        change_client_second_auth_content(payload, cont_len, encryption);
        s->mysql_sec_auth = 0;
        strace_pack(LOG_NOTICE, CLIENT_FLAG, ip_header, tcp_header);
        value = hash_find(sec_auth_pack_table, s->hash_key);
        if(value != NULL){
            free(value);
            log_info(LOG_NOTICE, "free for sec auth:%llu", s->hash_key);
        }
        value = (void *)copy_ip_packet(ip_header);
        hash_add(sec_auth_pack_table, s->hash_key, value);
        log_info(LOG_WARN, "set sec auth packet:%llu", s->hash_key);

    }

    return SUCCESS;
}
#endif

#if (TCPCOPY_MYSQL_BASIC)
static void mysql_prepare_for_new_session(session_t *s,
        struct iphdr *ip_header, struct tcphdr *tcp_header)
{
    struct iphdr  *fir_auth_pack, *fir_ip_header, *tmp_ip_header;
    struct tcphdr *fir_tcp_header, *tmp_tcp_header;
    uint32_t      total_cont_len, base_seq;
    uint16_t      size_ip, fir_cont_len, tmp_cont_len;
    link_list     *list;
    p_link_node   ln;
#if (TCPCOPY_MYSQL_ADVANCED)
    struct iphdr  *sec_auth_packet, *sec_ip_header;
    struct tcphdr *sec_tcp_header;
    uint16_t      sec_cont_len;
    uint64_t      key;
    void          *value;
#endif
    s->mysql_req_begin = 1;
    /* Use the global first auth user packet for mysql skip-grant-tables */
    fir_auth_pack = fir_auth_u_p;
#if (TCPCOPY_MYSQL_ADVANCED)
    key = get_key(ip_header->saddr, tcp_header->source);
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
    if(!fir_auth_pack){
        log_info(LOG_WARN, "no first auth packets here");
        return;
    }
    fir_ip_header  = (struct iphdr*)copy_ip_packet(fir_auth_pack);
    fir_ip_header->saddr = ip_header->saddr;
    size_ip        = fir_ip_header->ihl << 2;
    fir_tcp_header = (struct tcphdr*)((char *)fir_ip_header + size_ip);
    fir_cont_len = get_pack_cont_len(fir_ip_header, fir_tcp_header);
    fir_tcp_header->source = tcp_header->source;
    /* Save packet to unsend */
    save_packet(s->unsend_packets, fir_ip_header, fir_tcp_header);
    s->mysql_vir_req_seq_diff = g_seq_omit;
#if (TCPCOPY_MYSQL_ADVANCED)
    if(sec_auth_packet){
        sec_ip_header = (struct iphdr*)copy_ip_packet(sec_auth_packet);
        sec_ip_header->saddr = ip_header->saddr;
        size_ip   = sec_ip_header->ihl << 2;
        sec_tcp_header = (struct tcphdr*)((char *)sec_ip_header + size_ip);
        sec_cont_len = get_pack_cont_len(sec_ip_header, sec_tcp_header);
        sec_tcp_header->source = tcp_header->source;
        save_packet(s->unsend_packets, sec_ip_header, sec_tcp_header);
        log_info(LOG_NOTICE, "set second auth for non-skip");
    }else{
        log_info(LOG_WARN, "no sec auth packet here");
    }
#endif

#if (TCPCOPY_MYSQL_ADVANCED)
    total_cont_len = fir_cont_len + sec_cont_len;   
#else
    total_cont_len = fir_cont_len;
#endif

    list = (link_list *)hash_find(mysql_table, s->src_h_port);
    if(list){
        /* Calculate the total content length */
        ln = link_list_first(list); 
        while(ln){
            tmp_ip_header = (struct iphdr *)(ln->data);
            tmp_cont_len = get_pack_cont_len(tmp_ip_header, NULL);
            total_cont_len += tmp_cont_len;
            ln = link_list_get_next(list, ln);
        }
    }

#if (DEBUG_TCPCOPY)
    log_info(LOG_INFO, "total len subtracted:%u", total_cont_len);
#endif
    /* Rearrange seq */
    tcp_header->seq = htonl(ntohl(tcp_header->seq) - total_cont_len);
    fir_tcp_header->seq = htonl(ntohl(tcp_header->seq) + 1);
#if (TCPCOPY_MYSQL_ADVANCED)
    if(sec_tcp_header != NULL){
        sec_tcp_header->seq = htonl(ntohl(fir_tcp_header->seq) 
                + fir_cont_len);
    }
#endif
#if (TCPCOPY_MYSQL_ADVANCED)
    base_seq = ntohl(fir_tcp_header->seq) + fir_cont_len + sec_cont_len;
#else
    base_seq = ntohl(fir_tcp_header->seq) + fir_cont_len;
#endif
    if(list){
        /* Insert prepare statements */
        ln = link_list_first(list); 
        while(ln){
            tmp_ip_header  = (struct iphdr *)(ln->data);
            tmp_ip_header  = (struct iphdr*)copy_ip_packet(tmp_ip_header);
            tmp_tcp_header = (struct tcphdr*)((char *)tmp_ip_header 
                    + size_ip); 
            tmp_cont_len   = get_pack_cont_len(tmp_ip_header, tmp_tcp_header);
            tmp_tcp_header->seq = htonl(base_seq);
            save_packet(s->unsend_packets, tmp_ip_header, tmp_tcp_header);
            base_seq += tmp_cont_len;
            ln = link_list_get_next(list, ln);
        }
    }
}
#endif

/*
 * Send faked syn packet to backend.
 */
static void send_faked_syn(session_t *s, struct iphdr *ip_header,
        struct tcphdr *tcp_header)
{
    unsigned char f_s_buf[FAKE_IP_DATAGRAM_LEN];
    struct iphdr  *f_ip_header;
    struct tcphdr *f_tcp_header;

    memset(f_s_buf, 0, FAKE_IP_DATAGRAM_LEN);
    f_ip_header  = (struct iphdr *)f_s_buf;
    f_tcp_header = (struct tcphdr *)(f_s_buf + IP_HEADER_LEN);
    fill_protocol_common_header(f_ip_header, f_tcp_header);

    s->req_ip_id = ntohs(ip_header->id);
    /* 
     * The identification field uniquely identifies 
     * each datagram sent by a host.
     * We here adopt a naive method
     */
    f_ip_header->id       = htons(s->req_ip_id - 2);
    f_ip_header->saddr    = ip_header->saddr;
    f_ip_header->daddr    = ip_header->daddr;
    f_tcp_header->source  = tcp_header->source;
    f_tcp_header->dest    = tcp_header->dest;
    f_tcp_header->syn     = 1;
    f_tcp_header->seq     = htonl(ntohl(tcp_header->seq) - 1);
    s->vir_next_seq       = ntohl(tcp_header->seq);
#if (TCPCOPY_MYSQL_BASIC)
    mysql_prepare_for_new_session(s, f_ip_header, f_tcp_header);
#endif
#if (DEBUG_TCPCOPY)
    strace_pack(LOG_DEBUG, FAKED_CLIENT_FLAG, f_ip_header, f_tcp_header);
#endif
    wrap_send_ip_packet(s, f_s_buf, true);
    s->req_halfway_intercepted = 1;
    s->resp_syn_received = 0;
}

/*
 * Send faked syn ack packet(the third handshake packet) to back 
 */
static void send_faked_third_handshake(session_t *s, 
        struct iphdr *ip_header, struct tcphdr *tcp_header)
{
    unsigned char fake_ack_buf[FAKE_IP_DATAGRAM_LEN];
    struct iphdr  *f_ip_header;
    struct tcphdr *f_tcp_header;

    memset(fake_ack_buf, 0, FAKE_IP_DATAGRAM_LEN);
    f_ip_header  = (struct iphdr *)fake_ack_buf;
    f_tcp_header = (struct tcphdr *)(fake_ack_buf + IP_HEADER_LEN);
    fill_protocol_common_header(f_ip_header, f_tcp_header);
    f_ip_header->id       = htons(++s->req_ip_id);
    f_ip_header->saddr    = s->src_addr;
    /* Here we must recored online ip address */
    f_ip_header->daddr    = s->online_addr; 
    f_tcp_header->source  = tcp_header->dest;
    /* Here we must recored online port */
    f_tcp_header->dest    = s->online_port;
    f_tcp_header->ack     = 1;
    f_tcp_header->ack_seq = s->vir_ack_seq;
    f_tcp_header->seq     = tcp_header->ack_seq;
    
#if (DEBUG_TCPCOPY)
    strace_pack(LOG_DEBUG, FAKED_CLIENT_FLAG, f_ip_header, f_tcp_header);
#endif
    wrap_send_ip_packet(s, fake_ack_buf, false);
}

/*
 * Send faked ack packet to backend from the backend packet
 */
static void send_faked_ack(session_t *s , struct iphdr *ip_header, 
        struct tcphdr *tcp_header, bool active)
{
    unsigned char fake_ack_buf[FAKE_IP_DATAGRAM_LEN];
    struct iphdr  *f_ip_header;
    struct tcphdr *f_tcp_header;

    memset(fake_ack_buf, 0, FAKE_IP_DATAGRAM_LEN);
    f_ip_header  = (struct iphdr *)fake_ack_buf;
    f_tcp_header = (struct tcphdr *)(fake_ack_buf + IP_HEADER_LEN);
    fill_protocol_common_header(f_ip_header, f_tcp_header);
    f_ip_header->id       = htons(++s->req_ip_id);
    f_ip_header->saddr    = ip_header->daddr;
    f_tcp_header->source  = tcp_header->dest;
    f_tcp_header->ack     = 1;
    f_tcp_header->ack_seq = s->vir_ack_seq;
    if(active){
        /* Seq is determined by session virtual next seq */
        f_tcp_header->seq = htonl(s->vir_next_seq);
    }else{
        /* Seq is determined by backend ack seq */
        f_tcp_header->seq = tcp_header->ack_seq;
    }
    s->unack_pack_omit_save_flag = 1;
    wrap_send_ip_packet(s, fake_ack_buf, false);
}

/*
 * Send faked reset packet to backend from the backend packet
 */
static void send_faked_rst(session_t *s, 
        struct iphdr *ip_header, struct tcphdr *tcp_header)
{
    unsigned char faked_rst_buf[FAKE_IP_DATAGRAM_LEN];
    struct iphdr  *f_ip_header;
    struct tcphdr *f_tcp_header;
    uint16_t      cont_len, tot_len;

#if (DEBUG_TCPCOPY)
    log_info(LOG_DEBUG, "send faked rst To Back:%u", s->src_h_port);
#endif

    memset(faked_rst_buf, 0, FAKE_IP_DATAGRAM_LEN);
    f_ip_header  = (struct iphdr *)faked_rst_buf;
    f_tcp_header = (struct tcphdr *)(faked_rst_buf + IP_HEADER_LEN);
    fill_protocol_common_header(f_ip_header, f_tcp_header);
    f_ip_header->id       = htons(++s->req_ip_id);
    f_ip_header->saddr    = ip_header->daddr;
    f_tcp_header->source  = tcp_header->dest;
    f_tcp_header->rst     = 1;
    f_tcp_header->ack     = 1;
    tot_len     = ntohs(ip_header->tot_len);
    cont_len    = get_pack_cont_len(ip_header, tcp_header);

    if(cont_len > 0){   
        s->vir_ack_seq = htonl(ntohl(tcp_header->seq) + cont_len); 
    }else{
        s->vir_ack_seq = tcp_header->seq;
    }
    f_tcp_header->ack_seq = s->vir_ack_seq;
    f_tcp_header->seq = tcp_header->ack_seq;
    s->unack_pack_omit_save_flag = 1;
    wrap_send_ip_packet(s, faked_rst_buf, false);
    s->reset_sent = 1;
}

/*
 * Fake the first handshake packet for intercepting already 
 * connected online packets
 */
static void fake_syn(session_t *s, struct iphdr *ip_header, 
        struct tcphdr *tcp_header, bool is_hard)
{
    bool     result;
    uint16_t target_port;
    uint64_t new_key;
#if (DEBUG_TCPCOPY)
    log_info(LOG_NOTICE, "fake syn:%u", s->src_h_port);
#endif
    if(is_hard){
        while(true){
            target_port = get_port_by_rand_addition(tcp_header->source);
            s->src_h_port = target_port;
            target_port   = htons(target_port);
            new_key       = get_key(ip_header->saddr, target_port);
            if(NULL ==  hash_find(sessions_table, new_key)){
                break;
            }else{
                log_info(LOG_NOTICE, "already exist:%u", s->src_h_port);
            }
        }
#if (DEBUG_TCPCOPY)
        log_info(LOG_NOTICE, "change port from :%u to :%u",
                ntohs(tcp_header->source), s->src_h_port);
#endif
        hash_add(tf_port_table, new_key, (void *)(long)s->orig_src_port);
        tcp_header->source = target_port;
        s->faked_src_port  = tcp_header->source;
        s->port_transfered = 1;
    }

    /* Send route info to backend */
    result = send_router_info(tcp_header->dest, ip_header->saddr,
            tcp_header->source, CLIENT_ADD);
    if(!result){
        return;
    }
    send_faked_syn(s, ip_header, tcp_header);
    s->req_syn_ok = 1;
    if(is_hard){
        recon_for_closed_cnt++;
    }else{
        recon_for_no_syn_cnt++;
    }
}

/* TODO READ HERE*/
#if (TCPCOPY_MYSQL_BASIC)
/*
 * Check if the packet is needed for reconnection by mysql 
 */
static bool mysql_check_reconnection(session_t *s, struct iphdr *ip_header,
        struct tcphdr *tcp_header)
{
    unsigned char *payload, command;
    uint16_t      size_ip, size_tcp, tot_len, cont_len;
    link_list     *list;

    size_ip  = ip_header->ihl << 2;
    size_tcp = tcp_header->doff << 2;
    tot_len  = ntohs(ip_header->tot_len);
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
                    return false;
                }
            }
            save_packet(s->mysql_special_packets, ip_header, tcp_header);
#if (DEBUG_TCPCOPY)
            log_info(LOG_NOTICE, "push back necc statement:%u", s->src_h_port);
#endif
            list = (link_list *)hash_find(mysql_table, s->src_h_port);
            if(!list){
                list = link_list_create();
                if(NULL == list)
                {
                    log_info(LOG_ERR, "list create err");
                    return false;
                }else{
                    hash_add(mysql_table, s->src_h_port, list);
                }
            }
            save_packet(list, ip_header, tcp_header);
            return true;
        }
    }
    return false;
}

/*
 * Check if the packet is the right packet for starting a new session 
 * by mysql tcpcopy
 */
static bool check_mysql_padding(struct iphdr *ip_header,
        struct tcphdr *tcp_header)
{
    unsigned char *payload, command, pack_number;
    uint16_t      size_ip, size_tcp, tot_len, cont_len;

    size_ip  = ip_header->ihl << 2;
    size_tcp = tcp_header->doff << 2;
    tot_len  = ntohs(ip_header->tot_len);
    cont_len = tot_len - size_tcp - size_ip;

    if(cont_len > 0){
        payload = (unsigned char*)((char*)tcp_header + size_tcp);
        /* Skip Packet Length */
        payload = payload + 3;
        /* Get packet number */
        pack_number = payload[0];
        /* If it is the second authenticate_user,then skip it */
        if(0 != pack_number){
            return false;
        }
        /* Skip Packet Number */
        payload = payload + 1;
        command = payload[0];
        if(COM_QUERY == command){
            return true;
        }
    }
    return false;
}
#endif

static int check_backend_ack(session_t *s, struct iphdr *ip_header,
         struct tcphdr *tcp_header, uint32_t ack, uint16_t cont_len)
{
    bool slide_window_empty = false;
    /* If ack from test server is more than what we expect */
    if(ack > s->vir_next_seq){
        log_info(LOG_NOTICE, " ack more than vir next seq");
        if(!s->resp_syn_received){
            s->sess_over = 1;
            return DISP_STOP;
        }
        s->vir_next_seq = ack;
    }else if(ack < s->vir_next_seq){
        /* If ack from test server is less than what we expect */
#if (DEBUG_TCPCOPY)
        log_info(LOG_INFO, "bak ack less than vir_next_seq:%u,%u, p:%u",
                ack, s->vir_next_seq, s->src_h_port);
#endif
        if(!s->resp_syn_received){
            /* Try to eliminate the tcp state of backend */
            send_faked_rst(s, ip_header, tcp_header);
            s->sess_over = 1;
            return DISP_STOP;
        }
        if(s->src_closed && !tcp_header->fin){
            /* Try to close the connection */
            send_faked_rst(s, ip_header, tcp_header);
            s->sess_over = 1;
            return DISP_STOP;
        }else{
            /* Simulaneous close */
            if(s->src_closed && tcp_header->fin){
                s->simul_closing = 1;
            }
        }
        /* When the slide window in test server is full*/
        if(0 == tcp_header->window){
            log_info(LOG_NOTICE, "slide window zero:%u", s->src_h_port);
            /* Although slide window is full, it may require retransmission */
            if(!s->last_window_full){
                s->resp_last_ack_seq = ack;
                s->last_window_full = 1;
                update_retransmission_packets(s);
                return DISP_STOP;
            }
        }else{
            if(s->last_window_full){
                s->last_window_full = 0;
                s->vir_already_retransmit = 0;
                slide_window_empty = true;
            }
        }

        if(ack != s->resp_last_ack_seq){
            s->resp_last_same_ack_num = 0;
            s->vir_already_retransmit = 0;
            return DISP_CONTINUE;
        }
        /* Check if it needs retransmission */
        if(0 == cont_len && !tcp_header->fin){
            s->resp_last_same_ack_num++;
            if(s->resp_last_same_ack_num > 1){
                /* It needs retransmission */
                log_info(LOG_WARN, "bak lost packs:%u", s->src_h_port);
                if(!s->vir_already_retransmit){
                    if(!retransmit_packets(s)){
                        /* Retransmit failure, send reset */
                        send_faked_rst(s, ip_header, tcp_header);
                    }
                    s->vir_already_retransmit = 1;
                }else{
                    log_info(LOG_WARN, "omit retransmit:%u", s->src_h_port);
                }
                if(slide_window_empty){
                    /* Send reserved packets when slide window available */
                    send_reserved_packets(s);
                }
                return DISP_STOP;
            }
        }
    }
    return DISP_CONTINUE;
}

static void process_back_syn(session_t *s, struct iphdr *ip_header,
        struct tcphdr *tcp_header)
{
    conn_cnt++;
    s->resp_syn_received = 1;
#if (DEBUG_TCPCOPY)
    log_info(LOG_DEBUG, "recv syn from back:%u", s->src_h_port);
#endif
    s->status = SYN_CONFIRM;
    s->vir_ack_seq = htonl(ntohl(tcp_header->seq) + 1);
    s->dst_closed  = 0;
    s->reset_sent  = 0;
    if(s->req_halfway_intercepted){
        send_faked_third_handshake(s, ip_header, tcp_header);
        send_reserved_packets(s);
    }else{
        send_reserved_packets(s);
    }
}

static void process_back_fin(session_t *s, struct iphdr *ip_header,
        struct tcphdr *tcp_header)
{
#if (DEBUG_TCPCOPY)
    log_info(LOG_INFO, "recv fin from back:%u", s->src_h_port);
#endif
    s->dst_closed = 1;
    s->candidate_response_waiting = 0;
    s->status  |= SERVER_FIN;
    send_faked_ack(s, ip_header, tcp_header, s->simul_closing?true:false);
    if(!s->src_closed){
        /* 
         * Add seq here in order to keep the rst packet's ack right 
         * Because we send two packets here and are all dependent 
         * on this packet
         */
        tcp_header->seq = htonl(ntohl(tcp_header->seq) + 1);
        /* Send the constructed reset packet to backend */
        send_faked_rst(s, ip_header, tcp_header);
    }
    /* 
     * Why session over in such situations?
     * This is for releasing router info.
     * Too many router info will slow the intercept program 
     */
    s->sess_over = 1;
}

#if (TCPCOPY_MYSQL_BASIC)
static int mysql_process_greet(session_t *s, struct iphdr *ip_header,
        struct tcphdr *tcp_header, uint16_t cont_len)
{
#if (TCPCOPY_MYSQL_ADVANCED)
    int           ret; 
    unsigned char *payload;
#endif
    log_info(LOG_NOTICE, "recv greeting from back");
#if (TCPCOPY_MYSQL_ADVANCED) 
    s->mysql_cont_num_aft_greet  = 0;
    payload =(unsigned char*)((char*)tcp_header + sizeof(struct tcphdr));
    memset(s->mysql_scramble, 0, SCRAMBLE_LENGTH + 1);
    ret = parse_handshake_init_cont(payload, cont_len, s->mysql_scramble);
    log_info(LOG_WARN, "scram:%s,p:%u", s->mysql_scramble, s->src_h_port);
    if(!ret){
        /* Try to print error info*/
        if(cont_len > 11){
            strace_pack(LOG_WARN, BACKEND_FLAG, ip_header, tcp_header);
            log_info(LOG_WARN, "port:%u,payload:%s",
                    s->src_h_port, (char*)(payload + 11));
        }
        s->sess_over = 1;
        return DISP_STOP;
    }
#endif
    return DISP_CONTINUE;
}

#if (TCPCOPY_MYSQL_ADVANCED)
static void mysql_check_need_sec_auth(session_t *s, 
        struct iphdr *ip_header, struct tcphdr *tcp_header)
{
    unsigned char *payload;
    log_info(LOG_NOTICE, "check if it needs second auth");
    payload = (unsigned char*)((char*)tcp_header + sizeof(struct tcphdr));
    /* 
     * If it is the last data packet, 
     * then it means it needs sec auth
     */
    if(is_last_data_packet(payload)){
        strace_pack(LOG_WARN, BACKEND_FLAG, ip_header, tcp_header);
        log_info(LOG_WARN, "it needs sec auth:%u", s->src_h_port);
        s->mysql_sec_auth = 1;
    }
}
#endif
#endif

/*
 * Processing backend packets
 * TODO Have not considered TCP Keepalive situations
 */
void process_backend_packet(session_t *s, struct iphdr *ip_header,
        struct tcphdr *tcp_header)
{
    uint16_t size_ip, size_tcp, tot_len, cont_len;
    uint32_t ack;
    time_t   current;
    bool     is_greet = false; 

    resp_cnt++;
#if (DEBUG_TCPCOPY)
    strace_pack(LOG_DEBUG, BACKEND_FLAG, ip_header, tcp_header);
#endif

    if( tcp_header->rst){
        s->reset_sent = 1;
#if (DEBUG_TCPCOPY)
        log_info(LOG_INFO, "reset from backend:%u", s->src_h_port);
#endif
        return;
    }

    /* Retrieve packet info */
    ack      = ntohl(tcp_header->ack_seq);
    tot_len  = ntohs(ip_header->tot_len);
    size_ip  = ip_header->ihl << 2;
    size_tcp = tcp_header->doff << 2;
    cont_len = tot_len - size_tcp - size_ip;

    current  = time(0);

    if(cont_len > 0){
        /* Calculate the total successful retransmisssons */
        if(s->vir_new_retransmit){
            retrans_succ_cnt++;
            s->vir_new_retransmit = 0;
        }
        s->resp_last_same_ack_num = 0;
        s->vir_already_retransmit = 0;
        resp_cont_cnt++;
        s->resp_last_recv_cont_time = current;
        s->vir_ack_seq = htonl(ntohl(tcp_header->seq) + cont_len);
    }else{
        s->vir_ack_seq = tcp_header->seq;
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
        if(!s->resp_syn_received){
            /* Process syn packet */
            process_back_syn(s, ip_header, tcp_header);
        }
        return;
    }else if(tcp_header->fin){
        s->vir_ack_seq = htonl(ntohl(s->vir_ack_seq) + 1);
        /* Process fin packet */
        process_back_fin(s, ip_header, tcp_header);
        return;
    }else if(tcp_header->ack){
        /* Process ack packet */
        if(s->src_closed && s->dst_closed){
            s->sess_over = 1;
            return;
        }
    }

    /* We are not sure if it will come here */
    if(!s->resp_syn_received){
        log_info(LOG_NOTICE, "unbelievable:%u", s->src_h_port);
        strace_pack(LOG_NOTICE, BACKEND_FLAG, ip_header, tcp_header);
        /* Try to solve backend's obstacle */
        send_faked_rst(s, ip_header, tcp_header);
        return;
    }

    /* 
     * It is nontrivial to check if the packet is the last packet 
     * of the response
     */
    if(cont_len > 0){
        if(s->src_closed){
            /* Try to solve the obstacle */ 
            send_faked_rst(s, ip_header, tcp_header);
            return;
        }
        if(s->status < SEND_REQUEST){
            if(!s->resp_greet_received){
                s->resp_greet_received = 1;
                s->need_resp_greet = 0;
                is_greet = true;
            }
        }
#if (TCPCOPY_MYSQL_BASIC)
        if(is_greet && DISP_STOP == mysql_process_greet(s, ip_header, 
                    tcp_header, cont_len)){
            return;
        }
#if (TCPCOPY_MYSQL_ADVANCED)
        if(!is_greet){
            if(0 == s->mysql_cont_num_aft_greet){
                mysql_check_need_sec_auth(s, ip_header, tcp_header);
            }
            s->mysql_cont_num_aft_greet++;
        }
#endif

#endif
        /* TODO Why mysql does not need this packet ? */
        send_faked_ack(s, ip_header, tcp_header, true);
#if (TCPCOPY_MYSQL_BASIC)
        if(s->candidate_response_waiting || is_greet)
#else
            if(s->candidate_response_waiting)
#endif
            {
#if (DEBUG_TCPCOPY)
                log_info(LOG_DEBUG, "receive back server's resp");
#endif
                s->candidate_response_waiting = 0;
                s->status = RECV_RESP;
                send_reserved_packets(s);
                return;
            }
    }else{
        /* There are no content in packet */
        if(s->src_closed && !s->dst_closed){
            send_faked_rst(s, ip_header, tcp_header);
            s->sess_over = 1;
            return;
        }
    }
}

static void process_client_rst(session_t *s, struct iphdr *ip_header,
        struct tcphdr *tcp_header)  
{
    uint32_t seq;
#if (DEBUG_TCPCOPY)
    log_info(LOG_INFO, "reset from client:%u", s->src_h_port);
#endif
    if(s->candidate_response_waiting){
        save_packet(s->unsend_packets, ip_header, tcp_header);
    }else{
        seq = ntohl(tcp_header->seq);   
        if(seq < s->vir_next_seq){
            tcp_header->seq = htonl(s->vir_next_seq);
        }
        s->unack_pack_omit_save_flag = 1;
        wrap_send_ip_packet(s, (unsigned char *)ip_header, true);
        s->reset = 1;
    }
}

static void process_client_syn(session_t *s, struct iphdr *ip_header,
        struct tcphdr *tcp_header)  
{
#if (TCPCOPY_MYSQL_BASIC)
    link_list     *list;
    p_link_node   ln, tmp_ln;
#endif

    s->req_syn_ok = 1;

#if (DEBUG_TCPCOPY)
    log_info(LOG_INFO, "syn port:%u", s->src_h_port);
#endif

#if (TCPCOPY_MYSQL_BASIC)
    /* Remove old mysql info*/
    list = (link_list *)hash_find(mysql_table, s->src_h_port);
    if(!list){
        ln = link_list_first(list); 
        while(ln){
            tmp_ln = ln;
            ln = link_list_get_next(list, ln);
            link_list_remove(list, tmp_ln);
            free(tmp_ln->data);
            free(tmp_ln);
        }
    }
    if(!hash_del(mysql_table, s->src_h_port)){
        log_info(LOG_ERR, "mysql table hash not deleted");
    }
#endif
    wrap_send_ip_packet(s, (unsigned char *)ip_header, true);
}

static int process_client_fin(session_t *s, struct iphdr *ip_header,
        struct tcphdr *tcp_header)  
{
    uint16_t cont_len;
    s->status |= CLIENT_FIN;
#if (DEBUG_TCPCOPY)
    log_info(LOG_DEBUG, "recv fin packet from clt:%u", s->src_h_port);
#endif
    cont_len = get_pack_cont_len(ip_header, tcp_header);
    if(cont_len > 0){
#if (DEBUG_TCPCOPY)
        log_info(LOG_INFO, "fin has content:%u", s->src_h_port);
#endif
        return DISP_CONTINUE;
    }

    /* Practical experience */
    if(s->resp_last_ack_seq == ntohl(tcp_header->seq)){
        if(s->candidate_response_waiting){
            save_packet(s->unsend_packets, ip_header, tcp_header);
        }else{
            wrap_send_ip_packet(s, (unsigned char *)ip_header, true);
            s->status |= CLIENT_FIN;
            s->src_closed = 1;
        }
    }else{
        save_packet(s->unsend_packets, ip_header, tcp_header);
    }
    return DISP_STOP;
}

/* 
 * When server's response comes first
 * If packet's syn and ack are not according to the tcp protocol,
 * then it may encouter problems here
 */
static bool is_wait_greet(session_t *s, struct iphdr *ip_header,
        struct tcphdr *tcp_header)
{
    uint32_t seq, ack;
    if(s->status < SEND_REQUEST && s->req_valid_last_ack_sent){
        ack = ntohl(tcp_header->ack_seq);
        seq = ntohl(tcp_header->seq);
        if(ack > s->req_last_ack_sent_seq && seq == s->vir_next_seq){
            s->need_resp_greet = 1;
            if(!s->resp_greet_received){
                log_info(LOG_NOTICE, "it should wait:%u", s->src_h_port);
                /* It must wait for response */
                return true;
            }else{
                s->need_resp_greet = 0;
                return false;
            }
        }
    }
    if(s->need_resp_greet && !s->resp_greet_received){
        return true;
    }
    return false;
}

#if (TCPCOPY_MYSQL_BASIC)
static int process_mysql_clt_auth_pack(session_t *s, 
        struct iphdr *ip_header, struct tcphdr *tcp_header, 
        uint16_t cont_len)  
{   
    bool is_need_omit;
    if(!s->req_halfway_intercepted){
        is_need_omit = false;
#if (TCPCOPY_MYSQL_ADVANCED)
        if(s->resp_greet_received){
            if(FAILURE == mysql_dispose_auth(s, ip_header, tcp_header)){
                return DISP_STOP;
            }
        }
#endif
#if (!TCPCOPY_MYSQL_ADVANCED)
        if(!s->mysql_req_begin){
            /*
             * Check if mysql protocol validation ends? 
             */
            payload =(unsigned char*)((char*)tcp_header + size_tcp);
            /* Skip Packet Length */
            payload = payload + 3;
            pack_number = payload[0];
            /* If it is the second authenticate_user,then skip it */
            if(3 == pack_number){
                is_need_omit = true;
                s->mysql_req_begin = 1;
                log_info(LOG_NOTICE, "this is the sec auth packet");
            }
            if(0 == pack_number){
                s->mysql_req_begin = 1;
                log_info(LOG_NOTICE, "it has no sec auth packet");
            }
        }
#else
        s->mysql_req_begin = 1;
#endif
        if(is_need_omit){
            log_info(LOG_NOTICE, "omit sec validation for mysql");
            s->mysql_vir_req_seq_diff = cont_len;
            g_seq_omit = s->mysql_vir_req_seq_diff;
            return DISP_STOP;
        }
        if(!s->mysql_req_begin){
            if(!fir_auth_u_p){
                fir_auth_u_p = (struct iphdr*)copy_ip_packet(ip_header);
            }
            if(s->resp_greet_received){
                s->mysql_req_login_received = 1;
            }else{
                if(!s->mysql_req_login_received){
                    s->mysql_req_login_received = 1;
                    save_packet(s->unsend_packets, ip_header, tcp_header);
                    return DISP_STOP;
                }
            }
        }
        mysql_check_reconnection(s, ip_header, tcp_header);
        if(!s->resp_greet_received){
            save_packet(s->unsend_packets, ip_header, tcp_header);
            return DISP_STOP;
        }
    }
    return DISP_CONTINUE;
}
#endif

static void proc_clt_cont_when_bak_closed(session_t *s,
        struct iphdr *ip_header, struct tcphdr *tcp_header)
{
    uint64_t key;
    /* 
     * When the connection to the backend is closed, we 
     * reestablish the connection and 
     * we reserve all comming packets for later disposure
     */
#if (TCPCOPY_MYSQL_BASIC)
    if(!check_mysql_padding(ip_header, tcp_header)){
        return;
    }
#endif
    if(s->port_transfered){
        key = get_key(ip_header->saddr, s->faked_src_port);
        if(!hash_del(tf_port_table, key)){
            log_info(LOG_WARN, "no hash item for port transfer");
        }
    }
    session_init(s, SESS_KEEPALIVE);
    /* It wil change src port when setting true */
    fake_syn(s, ip_header, tcp_header, true);
    save_packet(s->unsend_packets, ip_header, tcp_header);

}

/* Check the current packet will be saved or not */
static int check_pack_save_or_not(session_t *s, struct iphdr *ip_header,
        struct tcphdr *tcp_header, int *is_new_req)
{
    bool        is_save = false;
    uint32_t    cur_seq;

    *is_new_req  = 0;
    /*
     * If the ack seq of the last content packet is not equal to 
     * it of the current content packet, then we consider 
     * the current packet to be the packet of the new request.
     * Although it is not always rigtht, it works well with the help of 
     * activate_dead_sessions function
     */
    if(s->req_cont_last_ack_seq != s->req_cont_cur_ack_seq){
        *is_new_req = 1;
#if (DEBUG_TCPCOPY)
        log_info(LOG_INFO, "it is a new req,p:%u", s->src_h_port);
#endif
    }

    if(*is_new_req){
        cur_seq = ntohl(tcp_header->seq);
        if(cur_seq > s->req_last_cont_sent_seq){
            is_save =true;
        }
    }else{
        if(s->unsend_packets->size > 0){
            if(check_reserved_content_left(s)){
                is_save = true;
            }
        }
    }
    if(is_save){
        save_packet(s->unsend_packets, ip_header, tcp_header);
        return DISP_STOP;
    }else{
        return DISP_CONTINUE;
    }
}

static int check_wait_prev_packet(session_t *s, struct iphdr *ip_header, 
        struct tcphdr *tcp_header, uint16_t cont_len)
{
    uint32_t cur_seq, retransmit_seq;
    int      diff;

    cur_seq = ntohl(tcp_header->seq);
    if(cur_seq > s->vir_next_seq){
#if (DEBUG_TCPCOPY)
        log_info(LOG_NOTICE, "lost and need prev packet:%u", s->src_h_port);
#endif
        save_packet(s->unsend_packets, ip_header, tcp_header);
        send_reserved_packets(s);
        return DISP_STOP;
    }else if(cur_seq == s->vir_next_seq){
        if(s->is_waiting_previous_packet){
            /* Send the packet and reserved packets */
            wrap_send_ip_packet(s, (unsigned char *)ip_header, true);
            send_reserved_packets(s);
            return DISP_STOP;
        }else{
            return DISP_CONTINUE;
        }
    }else{
        retransmit_seq = s->vir_next_seq - cont_len;
        if(cur_seq <= retransmit_seq){
            /* Retransmission packet from client */
#if (DEBUG_TCPCOPY)
            log_info(LOG_INFO, "retransmit from clt:%u", s->src_h_port);
#endif
        }else{
            diff = s->vir_next_seq - cur_seq;
            if(trim_packet(s, ip_header, tcp_header, diff)){
                return DISP_CONTINUE;
            }
        }
        return DISP_STOP;
    }
}

static int is_continuous_packet(session_t *s, struct iphdr *ip_header,
        struct tcphdr *tcp_header, int is_new_req)
{
    uint32_t cur_seq = ntohl(tcp_header->seq);
    if(s->candidate_response_waiting){
        if(cur_seq > s->req_last_cont_sent_seq){
            if(!is_new_req){
                wrap_send_ip_packet(s, (unsigned char *)ip_header, true);
#if (DEBUG_TCPCOPY)
                log_info(LOG_DEBUG, "it is a continuous req");
#endif
                return DISP_STOP;
            }
        }
    }
    return DISP_CONTINUE;
}

/* Process client packet info after the main processing */
static void process_clt_afer_filtering(session_t *s, 
        struct iphdr *ip_header, struct tcphdr *tcp_header, uint16_t len)
{
    if(!s->candidate_response_waiting){
        if(len > 0){
            s->candidate_response_waiting = 1;
            wrap_send_ip_packet(s, (unsigned char *)ip_header, true);
            return;
        }else if(SYN_CONFIRM == s->status){
            if(s->vir_next_seq == ntohl(tcp_header->seq)){
                wrap_send_ip_packet(s, (unsigned char *)ip_header, true);
                return;
            }
        }
    }
#if (DEBUG_TCPCOPY)
    log_info(LOG_DEBUG, "drop packet:%u", s->src_h_port);
#endif  
}

/*
 * Processing client packets
 * TODO 
 * 1)Have not consider TCP Keepalive
 * 2)TCP is always allowed to send 1 byte of data 
 *   beyond the end of a closed window which confuses tcpcopy.
 * These will be resolved later
 * 
 */
void process_client_packet(session_t *s, struct iphdr *ip_header,
        struct tcphdr *tcp_header)
{
    int       is_new_req;
    uint16_t  cont_len;

#if (DEBUG_TCPCOPY)
    strace_pack(LOG_DEBUG, CLIENT_FLAG, ip_header, tcp_header);
#endif  
    /* Change source port for multiple copying,etc */
    if(s->port_transfered != 0){
        tcp_header->source = s->faked_src_port;
    }
    s->src_h_port = ntohs(tcp_header->source);
    tcp_header->window  = 65535;

#if (TCPCOPY_MYSQL_BASIC)
    /* Subtract client packet's seq for mysql */
    if(s->mysql_req_begin){
        tcp_header->seq = htonl(ntohl(tcp_header->seq) - 
                s->mysql_vir_req_seq_diff);
    }
#endif

    /* If the packet is the next session's packet */
    if(s->sess_more){
        /* TODO Some statitics are not right because of this */
        save_packet(s->next_sess_packs, ip_header, tcp_header);
#if (DEBUG_TCPCOPY)
        log_info(LOG_INFO, "buffer for next session:%u", s->src_h_port);
#endif
        return;
    }

    /* If slide window is full, we wait*/
    if(s->last_window_full){
        save_packet(s->unsend_packets, ip_header, tcp_header);
        return;
    }

    s->online_addr  = ip_header->daddr;
    s->online_port  = tcp_header->dest;

    /* Syn packet has been sent to back,but not recv back's syn */
    if(SYN_SENT == s->status){
        save_packet(s->unsend_packets, ip_header, tcp_header);
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
    if(tcp_header->fin){
        if(DISP_STOP == process_client_fin(s, ip_header, tcp_header)){
            return;
        }
    }

    /* If not receiving syn packet */ 
    if(!s->req_syn_ok){
        s->req_halfway_intercepted = 1;
        fake_syn(s, ip_header, tcp_header, false);
        s->req_cont_cur_ack_seq  = ntohl(tcp_header->ack_seq);
        save_packet(s->unsend_packets, ip_header, tcp_header);
        return;
    }
    /* Retrieve the content length of tcp payload */
    cont_len = get_pack_cont_len(ip_header, tcp_header);

    if(cont_len > 0){
        if(is_wait_greet(s, ip_header, tcp_header)){
            save_packet(s->unsend_packets, ip_header, tcp_header);
            return;
        }
        /* Update ack seq values for checking a new request */
        s->req_cont_last_ack_seq = s->req_cont_cur_ack_seq;
        s->req_cont_cur_ack_seq  = ntohl(tcp_header->ack_seq);
#if (DEBUG_TCPCOPY)
        log_info(LOG_INFO, "cont len:%d,p:%u", cont_len, s->src_h_port);
#endif
#if (TCPCOPY_MYSQL_BASIC)
        /* Process mysql client auth packet */
        if(DISP_STOP == process_mysql_clt_auth_pack(s, ip_header, 
                    tcp_header, cont_len)){
            return;
        }
#endif
        if(s->dst_closed || s->reset_sent){
            /* When backend is closed or we have sent rst packet */
            proc_clt_cont_when_bak_closed(s, ip_header, tcp_header);
            return;
        }
        /* Check if the packet is to be saved for later use */
        if(s->candidate_response_waiting){
            if(DISP_STOP == check_pack_save_or_not(s, 
                        ip_header, tcp_header, &is_new_req)){
                return;
            }
        }
        /* Check if current session needs to wait prevous packet */
        if(DISP_STOP == check_wait_prev_packet(s, 
                    ip_header, tcp_header, cont_len)){
            return;
        }
        /* Check if it is a continuous packet */
        if(DISP_STOP == is_continuous_packet(s, ip_header, 
                    tcp_header, is_new_req)){
            return;
        }
#if (DEBUG_TCPCOPY)
        log_info(LOG_DEBUG, "a new request from client");
#endif
    }
    /* Post disposure */
    process_clt_afer_filtering(s, ip_header, tcp_header, cont_len);
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

    process_client_packet(s, ip_header,tcp_header);

    free(data);
    free(ln);
}

/*
 * Filter packets 
 */
bool is_packet_needed(const char *packet)
{
    bool          is_needed = false;
    struct tcphdr *tcp_header;
    struct iphdr  *ip_header;
    uint16_t      size_ip, size_tcp, tot_len, cont_len;

    ip_header = (struct iphdr*)packet;

    /* Check if it is a tcp packet */
    if(ip_header->protocol != IPPROTO_TCP){
        return is_needed;
    }

    size_ip   = ip_header->ihl << 2;
    tot_len   = ntohs(ip_header->tot_len);
    if (size_ip < 20) {
        log_info(LOG_WARN, "Invalid IP header length: %d", size_ip);
        return is_needed;
    }

    tcp_header = (struct tcphdr*)((char *)ip_header + size_ip);
    size_tcp   = tcp_header->doff << 2;
    if (size_tcp < 20) {
        log_info(LOG_WARN, "Invalid TCP header len: %d bytes,pack len:%d",
                size_tcp, tot_len);
        return is_needed;
    }

    /* Here we filter the packets we do care about */
    if(LOCAL == check_pack_src(&(clt_settings.transfer), 
                ip_header->daddr, tcp_header->dest)){
        is_needed = true;
        cont_len  = tot_len - size_tcp - size_ip;
        if(tcp_header->syn){
            clt_syn_cnt++;
        }else if(cont_len > 0){
            clt_cont_cnt++;
        }
        clt_packs_cnt++;
    }

    return is_needed;

}

/* Output statistics */
static void output_stat(time_t now, int run_time)
{
    double    ratio;

    last_stat_time = now;
    log_info(LOG_WARN, "active:%u,rel reqs:%llu,obs del:%llu",
            sessions_table->total, leave_cnt, obs_cnt);
    log_info(LOG_WARN, "conns:%llu,total resp packs:%llu,c-resp packs:%llu",
            conn_cnt, resp_cnt, resp_cont_cnt);
    log_info(LOG_WARN, "send Packets:%llu,send content packets:%llu",
            packs_sent_cnt, con_packs_sent_cnt);
    log_info(LOG_NOTICE, "reconnect for closed :%llu,for no syn:%llu",
            recon_for_closed_cnt, recon_for_no_syn_cnt);
    log_info(LOG_NOTICE, "successful retransmit:%llu", retrans_succ_cnt);
    log_info(LOG_NOTICE, "syn cnt:%llu,all clt packs:%llu, clt cont:%llu",
            clt_syn_cnt, clt_packs_cnt, clt_cont_cnt);

    clear_timeout_sessions();

    if(run_time > 3){
        if(0 == resp_cont_cnt){
            log_info(LOG_WARN, "no responses after %d secends", run_time);
        }
        if(sessions_table->total > 0){
            ratio = 100*conn_cnt/sessions_table->total;
            if(ratio < 80){
                log_info(LOG_WARN, "many connections can't be established");
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
    uint16_t       size_ip;
    uint64_t       key;
    time_t         now  = time(0);
    int            diff, run_time = 0;
    bool           result;
    session_t      *s;
    void           *ori_port;
    ip_port_pair_mappings_t *tf;

    if(0 == start_p_time){
        start_p_time = now;
    }else{
        run_time = now -start_p_time;
    }
    diff = now - last_stat_time;
    if(diff > 5){
        /* Output statistics */
        output_stat(now, run_time);
        /* We also activate dead session */
        activate_dead_sessions();
    }

    ip_header  = (struct iphdr*)packet;
    size_ip    = ip_header->ihl<<2;
    tcp_header = (struct tcphdr*)((char *)ip_header + size_ip);
    tf         = &(clt_settings.transfer);

    if(check_pack_src(tf, ip_header->saddr, tcp_header->source) == REMOTE){
        /* When the packet comes from the targeted test machine */
        key = get_key(ip_header->daddr, tcp_header->dest);
        s = hash_find(sessions_table, key);
        if(NULL == s){
            /* Give another chance for port changed*/
            ori_port = hash_find(tf_port_table, key);
            if(ori_port != NULL){
                key = get_key(ip_header->daddr, (uint16_t)(long)ori_port);
                s = hash_find(sessions_table, key);
            }
        }
        if(s){
            s->last_update_time = now;
            process_backend_packet(s, ip_header, tcp_header);
            if(check_session_over(s)){
                if(s->sess_more){
                    /* Restore the next session which has the same key */
                    session_init_for_next(s);
                    log_info(LOG_NOTICE, "init for next sess from bak");
                    restore_buffered_next_session(s);
                    return;
                }else{
                    send_router_info(s->online_port, ip_header->daddr,
                            tcp_header->dest, CLIENT_DEL);
                    session_rel_dynamic_mem(s);
                    if(!hash_del(sessions_table, s->hash_key)){
                        log_info(LOG_ERR, "wrong del:%u", s->src_h_port);
                    }
                    free(s);
                }
            }
        }else{
#if (DEBUG_TCPCOPY)
            strace_pack(LOG_DEBUG, BACKEND_FLAG, ip_header, tcp_header);
            log_info(LOG_DEBUG, "no active session for me");
#endif
        }
    }else if(check_pack_src(tf, ip_header->daddr, tcp_header->dest) == LOCAL){
        /* When the packet comes from client */
        if(clt_settings.factor){
            /* Change client source port*/
            tcp_header->source = get_port_from_shift(tcp_header->source,
                    clt_settings.rand_port_shifted, clt_settings.factor);
        }
        key = get_key(ip_header->saddr, tcp_header->source);
        if(tcp_header->syn){
            s  = hash_find(sessions_table, key);
            if(s){
                /* Check if it is a duplicate syn */
                if(tcp_header->seq == s->req_last_syn_seq){
#if (DEBUG_TCPCOPY)
                    log_info(LOG_INFO, "duplicate syn");
                    strace_pack(LOG_INFO, CLIENT_FLAG, ip_header, tcp_header);
#endif
                    return;
                }else{
                    /*
                     * Buffer the next session to current session
                     * We only support one more session which has the hash key
                     */
                    s->sess_more = 1;
                    if(s->next_sess_packs){
                        if(s->next_sess_packs->size > 0){
                            link_list_clear(s->next_sess_packs);
                        }
                    }else{
                        s->next_sess_packs = link_list_create();
                    }
                    save_packet(s->next_sess_packs, ip_header, tcp_header);
#if (DEBUG_TCPCOPY)
                    log_info(LOG_INFO, "buffer the new session");
                    strace_pack(LOG_INFO, CLIENT_FLAG, ip_header, tcp_header);
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
            result = send_router_info(tcp_header->dest, 
                    ip_header->saddr, tcp_header->source, CLIENT_ADD);
            if(!result){
                return;
            }else{
                process_client_packet(s, ip_header, tcp_header);
            }
        }else{
            s = hash_find(sessions_table, key);
            if(s){
                process_client_packet(s, ip_header, tcp_header);
                s->last_update_time = now;
                if(check_session_over(s)){
                    if(s->sess_more){
                        session_init_for_next(s);
                        log_info(LOG_NOTICE, "init for next sess from clt");
                        restore_buffered_next_session(s);
                        return;
                    }else{
                        send_router_info(s->online_port, ip_header->saddr,
                            htons(s->src_h_port), CLIENT_DEL);
                        session_rel_dynamic_mem(s);
                        if(!hash_del(sessions_table, s->hash_key)){
                            log_info(LOG_ERR, "wrong del:%u", s->src_h_port);
                        }
                        free(s);
                    }
                }
            }else
            {
                /* We check if we can pad tcp handshake */
                if(get_pack_cont_len(ip_header, tcp_header) > 0){
#if (TCPCOPY_MYSQL_BASIC)
                    if(!check_mysql_padding(ip_header,tcp_header)){
                        return;
                    }
#endif
                    s = session_add(key, ip_header, tcp_header);
                    if(NULL == s){
                        return;
                    }
                    process_client_packet(s, ip_header, tcp_header);
                }
            }
        }
    }else{
        /* We don't know where the packet comes from */
        log_info(LOG_WARN, "unknown packet");
        strace_pack(LOG_WARN, UNKNOWN_FLAG, ip_header, tcp_header);
    }
}

