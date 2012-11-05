
#include <xcopy.h>
#include <tcpcopy.h>

static hash_table *sessions_table;
static hash_table *tf_port_table;

#if (TCPCOPY_MYSQL_BASIC)
static hash_table *mysql_table;
#endif
#if (TCPCOPY_MYSQL_ADVANCED)
static hash_table *fir_auth_pack_table;
static hash_table *sec_auth_pack_table;
#endif

/* total sessions deleted */
static uint64_t leave_cnt            = 0;
/* total obsolete sessions */
static uint64_t obs_cnt              = 0;
/* total client syn packets */
static uint64_t clt_syn_cnt          = 0;
/* total client content packets */
static uint64_t clt_cont_cnt         = 0;
/* total client packets */
static uint64_t clt_packs_cnt        = 0;
/* total client packets sent to backend */
static uint64_t packs_sent_cnt       = 0;
/* total client content packets sent to backend */
static uint64_t con_packs_sent_cnt   = 0;
/* total response packets */
static uint64_t resp_cnt             = 0;
/* total response content packets */
static uint64_t resp_cont_cnt        = 0;
/* total connections successfully cheated */
static uint64_t conn_cnt             = 0;
/* total successful retransmission */
static uint64_t retrans_succ_cnt     = 0;
/* total retransmission */
static uint64_t retrans_cnt          = 0;
/* total reconnections for backend */
static uint64_t recon_for_closed_cnt = 0;
/* total reconnections for halfway interception */
static uint64_t recon_for_no_syn_cnt = 0;
/* start time for excuting the process function */
static time_t   start_p_time         = 0;
#if (TCPCOPY_MYSQL_BASIC)
/* global sequence omission */
static uint32_t g_seq_omit           = 0;
/* the global first auth user packet */
static tc_ip_header_t *fir_auth_u_p  = NULL;
#endif

static bool
check_session_over(session_t *s)
{
    if (s->sm.reset) {   
        return true;
    }   

    if (s->sm.sess_over) {   
        return true;
    }   

    return false;
}


static bool
trim_packet(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header, uint32_t diff)
{
    uint16_t        size_ip, size_tcp, tot_len, cont_len;
    unsigned char  *payload;

    size_ip   = ip_header->ihl << 2;
    tot_len   = ntohs(ip_header->tot_len);
    size_ip   = ip_header->ihl << 2;
    size_tcp  = tcp_header->doff << 2;
    cont_len  = tot_len - size_tcp - size_ip;

    if (cont_len <= diff) {
        return false;
    }

    ip_header->tot_len = htons(tot_len - diff);
    tcp_header->seq    = htonl(s->vir_next_seq);
    payload = (unsigned char *) ((char*) tcp_header + size_tcp);
    memmove(payload, payload + diff, cont_len - diff);
    tc_log_debug1(LOG_DEBUG, 0, "trim packet:%u", s->src_h_port);

    return true;
}


static uint16_t
get_pack_cont_len(tc_ip_header_t *ip_header, tc_tcp_header_t *tcp_header)
{
    uint16_t  size_ip, size_tcp, tot_len, cont_len;

    size_ip   = ip_header->ihl << 2;

    if (tcp_header == NULL) {
        tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);
    }

    tot_len   = ntohs(ip_header->tot_len);
    size_ip   = ip_header->ihl << 2;
    size_tcp  = tcp_header->doff << 2;
    cont_len  = tot_len - size_tcp - size_ip;
    
    return cont_len;
}

/*
 * it is called by fast retransmit
 */
static void
wrap_retransmit_ip_packet(session_t *s, unsigned char *data)
{
    int               ret;
    uint16_t          size_ip, tot_len, cont_len;
    tc_ip_header_t   *ip_header;
    tc_tcp_header_t  *tcp_header;

    if (data == NULL) {
        tc_log_info(LOG_ERR, 0, "error ip data is null");
        return;
    }

    ip_header  = (tc_ip_header_t *) data;
    size_ip    = ip_header->ihl << 2;
    tcp_header = (tc_tcp_header_t *) (data + size_ip);

    /* set the destination ip and port */
    ip_header->daddr = s->dst_addr;
    tcp_header->dest = s->dst_port;

    tot_len  = ntohs(ip_header->tot_len);
    cont_len = get_pack_cont_len(ip_header, tcp_header);

    if (cont_len > 0) {
        s->sm.vir_new_retransmit = 1;
        retrans_cnt++;
    }

    /* It should be set zero for tcp checksum */
    tcp_header->check = 0;
    tcp_header->check = tcpcsum((unsigned char *)ip_header,
            (unsigned short *) tcp_header, (int) (tot_len - size_ip));

    tc_log_trace(LOG_NOTICE, 0, TO_BAKEND_FLAG, ip_header, tcp_header);

    ret = tc_raw_socket_send(tc_raw_socket_out, ip_header, tot_len,
                             ip_header->daddr);
    if (ret == TC_ERROR) {
        tc_log_trace(LOG_WARN, 0, TO_BAKEND_FLAG, ip_header, tcp_header);
        tc_log_info(LOG_ERR, 0, "send to back error,tot_len is:%d,cont_len:%d",
                    tot_len,cont_len);
    }
}


/*
 * wrap sending ip packet function
 */
static void
wrap_send_ip_packet(session_t *s, unsigned char *data, bool client)
{
    int               ret;
    uint16_t          size_ip, tot_len, cont_len;
    p_link_node       ln;
    tc_ip_header_t   *ip_header;
    tc_tcp_header_t  *tcp_header;

    if (data == NULL) {
        tc_log_info(LOG_ERR, 0, "error ip data is null");
        return;
    }

    ip_header  = (tc_ip_header_t *) data;
    size_ip    = ip_header->ihl << 2;
    tcp_header = (tc_tcp_header_t *) (data + size_ip);

    if (client) {
        s->req_last_ack_sent_seq = ntohl(tcp_header->ack_seq);
        s->sm.req_valid_last_ack_sent = 1;
    }

    /* set the destination ip and port*/
    ip_header->daddr = s->dst_addr;
    tcp_header->dest = s->dst_port;

    s->vir_next_seq  = ntohl(tcp_header->seq);

    /* add virtual next seq when meeting syn or fin packet */
    if (tcp_header->syn || tcp_header->fin) {

        if (tcp_header->syn) {
            s->sm.req_valid_last_ack_sent = 0;
            s->sm.status = SYN_SENT;
            s->req_last_syn_seq = tcp_header->seq;
        } else {
            s->sm.fin_add_seq = 1;
        }
        s->vir_next_seq = s->vir_next_seq + 1;
    }
    if (tcp_header->ack) {
        tcp_header->ack_seq = s->vir_ack_seq;
    }

    tot_len  = ntohs(ip_header->tot_len);
    cont_len = get_pack_cont_len(ip_header, tcp_header);
    if (cont_len > 0) {

        s->sm.status = SEND_REQ;
        s->req_last_send_cont_time = tc_time();
        s->req_last_cont_sent_seq  = htonl(tcp_header->seq);
        s->vir_next_seq = s->vir_next_seq + cont_len;
        if (s->sm.unack_pack_omit_save_flag) {
            /*It means that this packet is a retransmission packet */
            s->sm.vir_new_retransmit = 1;
        } else {
            con_packs_sent_cnt++;
        }
    }

    /* It should be set zero for tcp checksum */
    tcp_header->check = 0;
    tcp_header->check = tcpcsum((unsigned char *)ip_header,
            (unsigned short *) tcp_header, (int) (tot_len - size_ip));

    tc_log_debug_trace(LOG_DEBUG, 0, TO_BAKEND_FLAG, ip_header, tcp_header);

    packs_sent_cnt++;

    s->req_ip_id = ntohs(ip_header->id);

    if (!s->sm.unack_pack_omit_save_flag) {
        ln = link_node_malloc(copy_ip_packet(ip_header));
        link_list_append(s->unack_packets, ln);
    } else {
        s->sm.unack_pack_omit_save_flag = 0;
    }

    ret = tc_raw_socket_send(tc_raw_socket_out, ip_header, tot_len,
                             ip_header->daddr);
    if (ret == TC_ERROR) {
        tc_log_trace(LOG_WARN, 0, TO_BAKEND_FLAG, ip_header, tcp_header);
        tc_log_info(LOG_ERR, 0, "send to back error,tot_len is:%d,cont_len:%d",
                    tot_len,cont_len);
    }
}


static void 
fill_pro_common_header(tc_ip_header_t *ip_header, tc_tcp_header_t *tcp_header)
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
    /* don't Fragment */
    ip_header->frag_off = htons(IP_DF); 
    /* 
     * sets an upper limit on the number of routers through 
     * which a datagram can pass
     */
    ip_header->ttl      = 64; 
    /* TCP packet */
    ip_header->protocol = IPPROTO_TCP;
    /* the TCP header length(the number of 32-bit words in the header) */
    tcp_header->doff    = 5;
    /* window size(you may feel strange here) */
    tcp_header->window  = 65535;
}


/*
 * send faked rst packet to backend passively
 */
static void
send_faked_passive_rst(session_t *s)
{
    unsigned char     faked_rst_buf[FAKE_IP_DATAGRAM_LEN];
    tc_ip_header_t   *f_ip_header;
    tc_tcp_header_t  *f_tcp_header;

    tc_log_debug1(LOG_DEBUG, 0, "send_faked_passive_rst:%u", s->src_h_port);

    memset(faked_rst_buf, 0, FAKE_IP_DATAGRAM_LEN);

    f_ip_header  = (tc_ip_header_t *) faked_rst_buf;
    f_tcp_header = (tc_tcp_header_t *) (faked_rst_buf + IP_HEADER_LEN);

    fill_pro_common_header(f_ip_header, f_tcp_header);
    f_ip_header->id       = htons(++s->req_ip_id);
    f_ip_header->saddr    = s->src_addr;
    f_tcp_header->source  = htons(s->src_h_port);
    f_tcp_header->rst     = 1;
    f_tcp_header->ack     = 1;
    f_tcp_header->ack_seq = s->vir_ack_seq;

    if (s->sm.fin_add_seq) {
        /* This is because of '++' in wrap_send_ip_packet */
        f_tcp_header->seq = htonl(s->vir_next_seq - 1); 
    } else {
        f_tcp_header->seq = htonl(s->vir_next_seq); 
    }

    s->sm.unack_pack_omit_save_flag = 1;

    wrap_send_ip_packet(s, faked_rst_buf, true);
}

static bool
send_router_info(uint32_t local_ip, uint16_t local_port, uint32_t client_ip,
        uint16_t client_port, uint16_t type)
{
    int            fd;
    msg_client_t   msg;

    fd = address_find_sock(local_ip, local_port);
    if (fd == -1) {
        tc_log_info(LOG_WARN, 0, "sock invalid,%u:%u",
                ntohl(local_ip), ntohs(local_port));
        return false;
    }

    msg.client_ip = client_ip;
    msg.client_port = client_port;
    msg.type = type;

    if (tc_socket_send(fd, (char *) &msg, MSG_CLIENT_SIZE) == TC_ERROR) {
        tc_log_info(LOG_ERR, 0, "msg client send error:%u", ntohs(client_port));
        return false;
    }

    return true;
}


static void
session_rel_dynamic_mem(session_t *s)
{
    uint64_t key;

    leave_cnt++;
    
    if (!check_session_over(s)) {

        /* send the last rst packet to backend */
        send_faked_passive_rst(s);
        send_router_info(s->online_addr, s->online_port, s->src_addr,
                htons(s->src_h_port), CLIENT_DEL);
        s->sm.sess_over = 1;
    }

    if (s->sm.port_transfered) {

        key = get_key(s->src_addr, s->faked_src_port);
        if (!hash_del(tf_port_table, key)) {
            tc_log_info(LOG_WARN, 0, "no hash item for port transfer");
        }
        s->sm.port_transfered = 0;
    }

    if (s->unsend_packets != NULL) {
        link_list_clear(s->unsend_packets);
        free(s->unsend_packets);
        s->unsend_packets = NULL;
    }

    if (s->next_sess_packs != NULL) {
        link_list_clear(s->next_sess_packs);
        free(s->next_sess_packs);
        s->next_sess_packs = NULL;
    }

    if (s->unack_packets != NULL) {
        link_list_clear(s->unack_packets);
        free(s->unack_packets);
        s->unack_packets = NULL;
    }

#if (TCPCOPY_MYSQL_BASIC)
    if (s->mysql_special_packets != NULL) {
        link_list_clear(s->mysql_special_packets);
        free(s->mysql_special_packets);
        s->mysql_special_packets = NULL;
    }
#endif
}


void
init_for_sessions()
{
    /* create 65536 slots for session table */
    sessions_table = hash_create(65536);
    strcpy(sessions_table->name, "session-table");

    tf_port_table  = hash_create(65536);
    strcpy(tf_port_table->name, "transfer port table");

#if (TCPCOPY_MYSQL_BASIC)
    mysql_table    = hash_create(65536);
    strcpy(mysql_table->name, "mysql table");
#endif

#if (TCPCOPY_MYSQL_ADVANCED) 
    fir_auth_pack_table = hash_create(65536);
    strcpy(fir_auth_pack_table->name, "first auth table");

    sec_auth_pack_table = hash_create(65536);
    strcpy(sec_auth_pack_table->name, "second auth table");
#endif
}


void
destroy_for_sessions()
{
    size_t       i;           
    hash_node   *hn;
    session_t   *s;
    link_list   *list;
    p_link_node  ln, tmp_ln;

    tc_log_info(LOG_NOTICE, 0, "enter destroy_for_sessions");

    if (sessions_table != NULL) {

        /* free session table */
        for (i = 0; i < sessions_table->size; i++) {

            list = sessions_table->lists[i];
            ln   = link_list_first(list);   
            while (ln) {

                tmp_ln = link_list_get_next(list, ln);
                hn = (hash_node *)ln->data;
                if (hn->data != NULL) {

                    s = hn->data;
                    hn->data = NULL;
                    /* delete session */
                    session_rel_dynamic_mem(s);
                    if (!hash_del(sessions_table, s->hash_key)) {
                        tc_log_info(LOG_ERR, 0, "wrong del");
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
    }

    /* free transfer port table */
    if (tf_port_table != NULL) {
        hash_destroy(tf_port_table);
        free(tf_port_table);
        tf_port_table = NULL;
    }

#if (TCPCOPY_MYSQL_BASIC)
    if (mysql_table != NULL) {

        for (i = 0; i < mysql_table->size; i++) {

            list = mysql_table->lists[i];
            ln   = link_list_first(list);   
            while (ln) {

                tmp_ln = link_list_get_next(list, ln);
                hn = (hash_node *)ln->data;
                if (hn->data != NULL) {
                    link_list_clear((link_list *)hn->data);
                }
                ln = tmp_ln;
            }
        }
        hash_deep_destroy(mysql_table);
        free(mysql_table);
        mysql_table = NULL;
    }
#endif

#if (TCPCOPY_MYSQL_ADVANCED) 
    if (fir_auth_pack_table != NULL) {
        hash_deep_destroy(fir_auth_pack_table);
        free(fir_auth_pack_table);
        fir_auth_pack_table = NULL;
    }

    if (sec_auth_pack_table != NULL) {
        hash_deep_destroy(sec_auth_pack_table);
        free(sec_auth_pack_table);
        sec_auth_pack_table = NULL;
    }
#endif

    tc_log_info(LOG_NOTICE, 0, "leave destroy_for_sessions");

}


static void
session_init(session_t *s, int flag)
{
    if (s->unsend_packets) {
        if (s->unsend_packets->size > 0) {
            link_list_clear(s->unsend_packets);
        }

        if (SESS_REUSE == flag) {
            if (s->next_sess_packs != NULL) {
                free(s->unsend_packets);
                s->unsend_packets = NULL;
            }
        }
    } else {
        s->unsend_packets = link_list_create();
    }

    if (s->unack_packets) {
        if (s->unack_packets->size > 0) {
            link_list_clear(s->unack_packets);
        }
    } else {
        s->unack_packets = link_list_create();
    }

#if (TCPCOPY_MYSQL_BASIC)
    if (SESS_CREATE == flag) {
        s->mysql_special_packets = link_list_create();
    } else {
        if (s->mysql_special_packets) {
            if (s->mysql_special_packets->size > 0) {
                link_list_clear(s->mysql_special_packets);
            }
        } else {
            s->mysql_special_packets = link_list_create();
        }
    }
#endif

    s->create_time      = tc_time();
    s->last_update_time = s->create_time;
    s->resp_last_recv_cont_time = s->create_time;
    s->req_last_send_cont_time  = s->create_time;

    if (SESS_CREATE != flag) {
        memset(&(s->sm), 0, sizeof(sess_state_machine_t));
    }
    s->sm.status  = CLOSED;
    s->resp_last_same_ack_num = 0;

#if (TCPCOPY_MYSQL_BASIC)
    s->sm.mysql_first_excution = 1;
    s->mysql_excute_times = 0;
#endif
}


/*
 * We only support one more session which has the same hash key
 */
static void
session_init_for_next(session_t *s)
{
    uint64_t    key;
    link_list  *list;

    list = s->next_sess_packs;

    if (s->sm.port_transfered) {
        key = get_key(s->src_addr, s->faked_src_port);
        if (!hash_del(tf_port_table, key)) {
            tc_log_info(LOG_WARN, 0, "no hash item for port transfer");
        }
    }

    session_init(s, SESS_REUSE);

    if (list != NULL) {
        s->unsend_packets  = list;
        s->next_sess_packs = NULL;
    } else {
        s->unsend_packets = link_list_create();
    }
}


static session_t *
session_create(tc_ip_header_t *ip_header, tc_tcp_header_t *tcp_header)
{
    session_t               *s;
    ip_port_pair_mapping_t  *test;

    s = (session_t *)calloc(1, sizeof(session_t));
    if (s == NULL) {
        return NULL;
    }

    session_init(s, SESS_CREATE);

    s->src_addr      = ip_header->saddr;
    s->online_addr   = ip_header->daddr;
    s->orig_src_port = tcp_header->source;
    s->src_h_port    = ntohs(tcp_header->source);
    s->online_port   = tcp_header->dest;
    test = get_test_pair(&(clt_settings.transfer), 
            s->online_addr, s->online_port);
    s->dst_addr      = test->target_ip;
    s->dst_port      = test->target_port;

    return s;
}


static session_t *
session_add(uint64_t key, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    session_t *s;

    s = session_create(ip_header, tcp_header);
    if (s != NULL) {
        s->hash_key = key;
        if (!hash_add(sessions_table, key, s)) {
            tc_log_info(LOG_ERR, 0, "session item already exist");
        }
    }

    return s;
}


static void 
save_packet(link_list *list, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    p_link_node ln = link_node_malloc(copy_ip_packet(ip_header));

    ln->key = ntohl(tcp_header->seq);
    link_list_append_by_order(list, ln);
    tc_log_debug0(LOG_DEBUG, 0, "save packet");
}


#if (TCPCOPY_MYSQL_ADVANCED)
static int
mysql_dispose_auth(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    int             ch_auth_success;
    void           *value;
    char            encryption[16];
    uint16_t        size_tcp, cont_len;
    unsigned char  *payload;

    size_tcp = tcp_header->doff << 2;
    cont_len = get_pack_cont_len(ip_header, tcp_header);

    if (!s->sm.mysql_first_auth_sent) {

        tc_log_info(LOG_NOTICE, 0, "mysql login req from reserved");
        payload = (unsigned char *) ((char *) tcp_header + size_tcp);
        ch_auth_success = change_client_auth_content(payload, 
                (int) cont_len, s->mysql_password, s->mysql_scramble);

        tc_log_trace(LOG_NOTICE, 0, CLIENT_FLAG, ip_header, tcp_header);

        if (!ch_auth_success) {
            s->sm.sess_over  = 1;
            tc_log_info(LOG_WARN, 0, "it is strange here,possibility");
            tc_log_info(LOG_WARN, 0, "1)user password pair not equal");
            tc_log_info(LOG_WARN, 0, "2)half-intercepted");
            return FAILURE;
        }

        s->sm.mysql_first_auth_sent = 1;
        value = hash_find(fir_auth_pack_table, s->hash_key);
        if (value != NULL) {
            free(value);
            tc_log_info(LOG_NOTICE, 0, "free for fir auth:%llu", s->hash_key);
        }

        value = (void *) copy_ip_packet(ip_header);
        hash_add(fir_auth_pack_table, s->hash_key, value);
        tc_log_info(LOG_NOTICE, 0, "set value for fir auth:%llu", s->hash_key);

    } else if (s->sm.mysql_first_auth_sent && s->sm.mysql_sec_auth) {

        tc_log_info(LOG_NOTICE, 0, "sec login req from reserved");

        payload = (unsigned char *) ((char *) tcp_header + size_tcp);

        memset(encryption, 0, 16);
        memset(s->mysql_seed323, 0, SEED_323_LENGTH + 1);
        memcpy(s->mysql_seed323, s->mysql_scramble, SEED_323_LENGTH);
        new_crypt(encryption, s->mysql_password, s->mysql_seed323);

        tc_log_info(LOG_NOTICE, 0, "change second req:%u", s->src_h_port);

        /* Change sec auth content from client auth packets */
        change_client_second_auth_content(payload, cont_len, encryption);
        s->sm.mysql_sec_auth = 0;

        tc_log_trace(LOG_NOTICE, 0, CLIENT_FLAG, ip_header, tcp_header);

        value = hash_find(sec_auth_pack_table, s->hash_key);
        if (value != NULL) {
            free(value);
            tc_log_info(LOG_NOTICE, 0, "free for sec auth:%llu", s->hash_key);
        }
        value = (void *) copy_ip_packet(ip_header);
        hash_add(sec_auth_pack_table, s->hash_key, value);
        tc_log_info(LOG_WARN, 0, "set sec auth packet:%llu", s->hash_key);

    }

    return SUCCESS;
}
#endif


/* 
 * This happens when server's response comes first(mysql etc)
 * Only support one greet packet here
 * If packet's syn and ack are not according to the tcp protocol,
 * then it may be mistaken to be the greet packet
 */
static inline bool
is_wait_greet(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    uint32_t seq, ack;

    if (s->sm.req_valid_last_ack_sent) {

        ack = ntohl(tcp_header->ack_seq);
        seq = ntohl(tcp_header->seq);

        /* 
         * For mysql,waiting is implied by the following
         * when backend is closed
         * (TODO should be optimized)
         */
        if (ack > s->req_last_ack_sent_seq && seq == s->vir_next_seq) {
            s->sm.need_resp_greet = 1;
            if (!s->sm.resp_greet_received) {
                tc_log_info(LOG_NOTICE, 0, "it should wait:%u", s->src_h_port);
                /* It must wait for response */
                return true;
            } else {
                s->sm.need_resp_greet = 0;
                return false;
            }
        }
    }

    if (s->sm.need_resp_greet && !s->sm.resp_greet_received) {
        return true;
    }

    return false;
}


/*
 * send reserved packets to backend
 */
static int
send_reserved_packets(session_t *s)
{
    int               count = 0, total_cont_sent = 0; 
    bool              need_pause = false, cand_pause = false,
                      omit_transfer = false; 
    uint16_t          size_ip, cont_len;
    uint32_t          cur_ack, cur_seq, diff;
    link_list        *list;
    p_link_node       ln, tmp_ln;
    unsigned char    *data;
    tc_ip_header_t   *ip_header;
    tc_tcp_header_t  *tcp_header;

    tc_log_debug2(LOG_DEBUG, 0, "send reserved packs,size:%u, port:%u",
            s->unsend_packets->size, s->src_h_port);

    if (SYN_CONFIRM > s->sm.status) {
        return count;
    }

    list = s->unsend_packets;
    if (list == NULL) {
        tc_log_info(LOG_WARN, 0, "list is null");
        return count;
    }

    ln = link_list_first(list); 

    while (ln && (!need_pause)) {

        data = ln->data;
        ip_header  = (tc_ip_header_t*) ((char *) data);
        size_ip    = ip_header->ihl << 2;
        tcp_header = (tc_tcp_header_t*) ((char *) ip_header + size_ip);
        cur_seq    = ntohl(tcp_header->seq);

        tc_log_debug_trace(LOG_DEBUG, 0, CLIENT_FLAG, ip_header, tcp_header);

        if (cur_seq > s->vir_next_seq) {

            /* We need to wait for previous packet */
            tc_log_debug0(LOG_DEBUG, 0, "we need to wait prev pack");
            s->sm.is_waiting_previous_packet = 1;
            s->sm.candidate_response_waiting = 0;
            break;
        } else if (cur_seq < s->vir_next_seq) {

            cont_len   = get_pack_cont_len(ip_header, tcp_header);
            if (cont_len > 0) {
                /* special disposure here */
                tc_log_debug1(LOG_DEBUG, 0, "reserved strange:%u", 
                        s->src_h_port);
                diff = s->vir_next_seq - cur_seq;
                if (!trim_packet(s, ip_header, tcp_header, diff)) {
                    omit_transfer = true;
                }
            } else {
                tcp_header->seq = htonl(s->vir_next_seq);
            }
        }

        if (s->sm.status < SEND_REQ
                && is_wait_greet(s, ip_header, tcp_header))
        {
            break;
        }

        cont_len   = get_pack_cont_len(ip_header, tcp_header);
        if (!omit_transfer && cont_len > 0) {

            if (total_cont_sent > MAX_SIZE_PER_CONTINUOUS_SEND) {
                s->sm.delay_sent_flag = 1;
                break;
            }
#if (TCPCOPY_MYSQL_ADVANCED) 
            if (mysql_dispose_auth(s, ip_header, tcp_header) == FAILURE) {
                break;
            }
#endif
            cur_ack = ntohl(tcp_header->ack_seq);
            if (cand_pause) {
                if (cur_ack != s->req_last_ack_sent_seq) {
                    break;
                }
            }
            cand_pause = true;
            s->sm.candidate_response_waiting = 1;
        } else if (tcp_header->rst) {

            if (s->sm.candidate_response_waiting) {
                break;
            }
            s->sm.reset      = 1;
            omit_transfer = false;
            need_pause    = true;
        } else if (tcp_header->fin) {

            if (s->sm.candidate_response_waiting) {
                break;
            }
            need_pause = true;
            if (s->req_last_ack_sent_seq == ntohl(tcp_header->ack_seq)) {
                /* active close from client */
                s->sm.src_closed = 1;
                s->sm.status |= CLIENT_FIN;
            } else {
                /* server active close */
                omit_transfer = true;
            }
        } else if (cont_len == 0) {

            /* waiting the response pack or the sec handshake pack */
            if (s->sm.candidate_response_waiting
                    || SYN_CONFIRM != s->sm.status)
            {
                omit_transfer = true;
            }
        }
        if (!omit_transfer) {

            count++;
            if (s->sm.sess_candidate_erased) {
                s->sm.sess_candidate_erased = 0;
            }
            wrap_send_ip_packet(s, data, true);
            total_cont_sent += cont_len;
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


static int 
check_overwhelming(session_t *s, const char *message, 
        int max_hold_packs, int size)
{
    if (size > max_hold_packs) {
        if (!s->sm.sess_candidate_erased) {
            s->sm.sess_candidate_erased = 1;
            tc_log_info(LOG_WARN, 0, "%s:candidate erased:%u,p:%u",
                message, size, s->src_h_port);
            return CANDIDATE_OBSOLETE;
        }
        obs_cnt++;
        tc_log_info(LOG_WARN, 0, "%s:too many packets:%u,p:%u",
                message, size, s->src_h_port);
        return OBSOLETE;
    }

    return NOT_YET_OBSOLETE;
}


/*
 * This happens in uploading large file situations
 */
static bool
is_session_dead(session_t *s)
{
    int    packs_unsend, diff;

    packs_unsend = s->unsend_packets->size;
    diff = tc_time() - s->req_last_send_cont_time;

    /* more than 2 seconds */
    if (diff > 2) {
        /* if there are more than 5 packets unsend */
        if (packs_unsend > 5) {
            return true;
        }
    }

    return false;
}


static void activate_dead_sessions()
{
    int           i;
    session_t    *s;
    link_list    *list;
    hash_node    *hn;
    p_link_node   ln;

    tc_log_info(LOG_NOTICE, 0, "activate_dead_sessions");

    for (i = 0; i < sessions_table->size; i++) {

        list = sessions_table->lists[i];
        ln   = link_list_first(list);   
        while (ln) {

            hn = (hash_node *)ln->data;
            if (hn->data != NULL) {
                s = hn->data;
                if (s->sm.sess_over) {
                    tc_log_info(LOG_NOTICE, 0, "already del:%u", s->src_h_port);
                }
                if (is_session_dead(s)) {
                    send_reserved_packets(s);
                }
            }
            ln = link_list_get_next(list, ln);
        }
    }
}

/* check if session is obsolete */
static int
check_session_obsolete(session_t *s, time_t cur, time_t threshold_time)
{
    int threshold = 256, result, diff;  
    
    /* if not receiving response for a long time */
    if (s->resp_last_recv_cont_time < threshold_time) {
        obs_cnt++;
        tc_log_debug2(LOG_DEBUG, 0, "timeout,unsend number:%u,p:%u",
                s->unsend_packets->size, s->src_h_port);
        return OBSOLETE;
    }

    diff = cur - s->req_last_send_cont_time;
    /* check if the session is idle for a long time */
    if (diff < 30) {
        threshold = threshold << 2;
        if (diff <= 3) {
            /* if it is idle for less than or equal to 3 seconds */
            threshold = threshold << 4;
        }
        if (s->sm.last_window_full) {
            /* if slide window is full */
            threshold = threshold << 2;
        }
    }

    result = check_overwhelming(s, "unsend", threshold, 
            s->unsend_packets->size);
    if (NOT_YET_OBSOLETE != result) {
        return result;
    }

    result = check_overwhelming(s, "unack", threshold, 
            s->unack_packets->size);
    if (NOT_YET_OBSOLETE != result) {
        return result;
    }

    if (s->next_sess_packs) {
        result = check_overwhelming(s, "next session", threshold, 
                s->next_sess_packs->size);
        if (NOT_YET_OBSOLETE != result) {
            return result;
        }
    }

#if (TCPCOPY_MYSQL_BASIC)
    result = check_overwhelming(s, "mysql special", threshold, 
            s->mysql_special_packets->size);
    if (NOT_YET_OBSOLETE != result) {
        return result;
    }
#endif

    return NOT_YET_OBSOLETE;
}


/*
 * clear TCP timeout sessions
 */
static void
clear_timeout_sessions()
{
    int          result;
    size_t       i;           
    time_t       current, threshold_time;
    link_list   *list;
    hash_node   *hn;
    session_t   *s;
    p_link_node  ln, tmp_ln;

    current = tc_time();
    threshold_time = current - clt_settings.session_timeout;

    tc_log_info(LOG_NOTICE, 0, "session size:%u", sessions_table->total);

    for (i = 0; i < sessions_table->size; i++) {

        list = sessions_table->lists[i];
        if (!list) {
            tc_log_info(LOG_WARN, 0, "list is null in sess table");
            continue;
        }

        ln   = link_list_first(list);   
        while (ln) {
            tmp_ln = link_list_get_next(list, ln);
            hn = (hash_node *)ln->data;
            if (hn->data != NULL) {

                s = hn->data;
                if (s->sm.sess_over) {
                    tc_log_info(LOG_WARN, 0, "wrong,del:%u", s->src_h_port);
                }
                result = check_session_obsolete(s, current, threshold_time);
                if (OBSOLETE == result) {
                    hn->data = NULL;
                    /* release memory for session internals */
                    session_rel_dynamic_mem(s);
                    /* remove session from table */
                    if (!hash_del(sessions_table, s->hash_key)) {
                        tc_log_info(LOG_ERR, 0, "wrong del:%u", s->src_h_port);
                    }
                    free(s);
                }
            }
            ln = tmp_ln;
        }
    }
}


/*
 * retransmit the packets to backend
 * only support fast retransmit here
 * (assume the network between online and target server is very well,
 * so other congestion situations are not detected here )
 */
static int
retransmit_packets(session_t *s, uint32_t expected_seq)
{
    bool              need_pause = false, is_success = false;
    uint16_t          size_ip;
    uint32_t          cur_seq;
    link_list        *list;
    p_link_node       ln, tmp_ln;
    unsigned char    *data;
    tc_ip_header_t   *ip_header;
    tc_tcp_header_t  *tcp_header;

    if (s->sm.status == SYN_SENT) {
        /* don't retransmit the first handshake packet */
        return true;
    }

    list = s->unack_packets;
    ln = link_list_first(list); 

    while (ln && (!need_pause)) {

        data       = ln->data;
        ip_header  = (tc_ip_header_t *) ((char *) data);
        size_ip    = ip_header->ihl << 2;
        tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);
        cur_seq    = ntohl(tcp_header->seq);  

        if (!is_success) {
            if (cur_seq == expected_seq) {
                /* fast retransmit */
                is_success = true;
                tc_log_info(LOG_NOTICE, 0, "fast retransmit:%u",
                        s->src_h_port);
                wrap_retransmit_ip_packet(s, data);
                need_pause = true;  
            } else if (cur_seq < s->resp_last_ack_seq) {
                tmp_ln = ln;
                ln = link_list_get_next(list, ln);
                link_list_remove(list, tmp_ln);
                free(data);
                free(tmp_ln);
            } else {
                tc_log_info(LOG_NOTICE, 0, "no retrans pack:%u", s->src_h_port);
                need_pause = true;
            }
        }
    }
    
    return is_success;
}


/*
 * update retransmission packets
 */
static void
update_retransmission_packets(session_t *s)
{
    uint16_t          size_ip;
    uint32_t          cur_seq;
    link_list        *list;
    p_link_node       ln, tmp_ln;
    unsigned char    *data;
    tc_ip_header_t   *ip_header;
    tc_tcp_header_t  *tcp_header;

    list = s->unack_packets;
    ln = link_list_first(list); 

    while (ln) {

        data       = ln->data;
        ip_header  = (tc_ip_header_t *) ((char *) data);
        size_ip    = ip_header->ihl << 2;
        tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);
        cur_seq    = ntohl(tcp_header->seq);  

        if (cur_seq < s->resp_last_ack_seq) {
            tmp_ln = ln;
            ln = link_list_get_next(list, ln);
            link_list_remove(list, tmp_ln);
            free(data);
            free(tmp_ln);
        } else {
            break;
        }
    }
}


/*
 * check if the reserved container has content left
 */
static bool
check_reserved_content_left(session_t *s)
{
    uint16_t        cont_len;
    link_list      *list;
    p_link_node     ln;
    tc_ip_header_t *ip_header;
    unsigned char  *data;

    tc_log_debug0(LOG_DEBUG, 0, "check_reserved_content_left");

    list = s->unsend_packets;
    ln = link_list_first(list); 

    while (ln) {
        data = ln->data;
        ip_header = (tc_ip_header_t *) ((char *) data);
        cont_len  = get_pack_cont_len(ip_header, NULL);
        if (cont_len > 0) {
            return true;
        }
        ln = link_list_get_next(list, ln);
    }
    return false;
}


#if (TCPCOPY_MYSQL_BASIC)
static void
mysql_prepare_for_new_session(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    uint16_t          size_ip, fir_cont_len, tmp_cont_len;
    uint32_t          total_cont_len, base_seq;
    link_list        *list;
    p_link_node       ln;
    tc_ip_header_t   *fir_auth_pack, *fir_ip_header, *tmp_ip_header;
    tc_tcp_header_t  *fir_tcp_header, *tmp_tcp_header;

#if (TCPCOPY_MYSQL_ADVANCED)
    void             *value;
    uint16_t          sec_cont_len = 0;
    uint64_t          key;
    tc_ip_header_t   *sec_auth_packet = NULL, *sec_ip_header;
    tc_tcp_header_t  *sec_tcp_header  = NULL;
#endif

    s->sm.mysql_req_begin = 1;
    /* use the global first auth user packet for mysql skip-grant-tables */
    fir_auth_pack = fir_auth_u_p;
#if (TCPCOPY_MYSQL_ADVANCED)
    key   = get_key(ip_header->saddr, tcp_header->source);
    value = hash_find(fir_auth_pack_table, key);
    if (value != NULL) {
        /* use the private first auth user packet */
        fir_auth_pack = (tc_ip_header_t *) value;
    }

    value = hash_find(sec_auth_pack_table, key);
    if (value != NULL) {
        sec_auth_packet = (tc_ip_header_t *) value;
    }

#endif

    if (!fir_auth_pack) {
        tc_log_info(LOG_WARN, 0, "no first auth pack here:%u", s->src_h_port);
        return;
    }

    fir_ip_header  = (tc_ip_header_t *) fir_auth_pack;
    fir_ip_header->saddr = ip_header->saddr;
    size_ip        = fir_ip_header->ihl << 2;
    fir_tcp_header = (tc_tcp_header_t *) ((char *) fir_ip_header
            + size_ip);
    fir_cont_len = get_pack_cont_len(fir_ip_header, fir_tcp_header);
    fir_tcp_header->source = tcp_header->source;

    /* save packet to unsend */
    save_packet(s->unsend_packets, fir_ip_header, fir_tcp_header);

    s->mysql_vir_req_seq_diff = g_seq_omit;

#if (TCPCOPY_MYSQL_ADVANCED)
    if (sec_auth_packet) {

        sec_ip_header = (tc_ip_header_t *) sec_auth_packet;
        sec_ip_header->saddr = ip_header->saddr;
        size_ip   = sec_ip_header->ihl << 2;
        sec_tcp_header = (tc_tcp_header_t *) ((char *) sec_ip_header
                + size_ip);
        sec_cont_len = get_pack_cont_len(sec_ip_header, sec_tcp_header);
        sec_tcp_header->source = tcp_header->source;
        save_packet(s->unsend_packets, sec_ip_header, sec_tcp_header);
        tc_log_info(LOG_NOTICE, 0, "set sec auth(normal):%u",s->src_h_port);
    } else {
        tc_log_info(LOG_WARN, 0, "no sec auth packet here:%u", s->src_h_port);
    }
#endif

#if (TCPCOPY_MYSQL_ADVANCED)
    total_cont_len = fir_cont_len + sec_cont_len;   
#else
    total_cont_len = fir_cont_len;
#endif

    list = (link_list *)hash_find(mysql_table, s->src_h_port);
    if (list) {
        /* calculate the total content length */
        ln = link_list_first(list); 
        while (ln) {
            tmp_ip_header = (tc_ip_header_t *) (ln->data);
            tmp_cont_len = get_pack_cont_len(tmp_ip_header, NULL);
            total_cont_len += tmp_cont_len;
            ln = link_list_get_next(list, ln);
        }
    }

    tc_log_debug2(LOG_DEBUG, 0, "total len subtracted:%u,p:%u", 
            total_cont_len, s->src_h_port);

    /* rearrange seq */
    tcp_header->seq = htonl(ntohl(tcp_header->seq) - total_cont_len);
    fir_tcp_header->seq = htonl(ntohl(tcp_header->seq) + 1);

#if (TCPCOPY_MYSQL_ADVANCED)
    if (sec_tcp_header != NULL) {
        sec_tcp_header->seq = htonl(ntohl(fir_tcp_header->seq) 
                + fir_cont_len);
    }
#endif

#if (TCPCOPY_MYSQL_ADVANCED)
    base_seq = ntohl(fir_tcp_header->seq) + fir_cont_len + sec_cont_len;
#else
    base_seq = ntohl(fir_tcp_header->seq) + fir_cont_len;
#endif

    if (list) {
        /* insert prepare statements */
        ln = link_list_first(list); 
        while (ln) {
            tmp_ip_header  = (tc_ip_header_t *) (ln->data);
            tmp_ip_header  = (tc_ip_header_t *) copy_ip_packet(tmp_ip_header);
            tmp_tcp_header = (tc_tcp_header_t *) ((char *) tmp_ip_header 
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
 * send faked syn packet to backend.
 */
static void
send_faked_syn(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    unsigned char    f_s_buf[FAKE_IP_DATAGRAM_LEN];
    tc_ip_header_t  *f_ip_header;
    tc_tcp_header_t *f_tcp_header;

    memset(f_s_buf, 0, FAKE_IP_DATAGRAM_LEN);
    f_ip_header  = (tc_ip_header_t *) f_s_buf;
    f_tcp_header = (tc_tcp_header_t *) (f_s_buf + IP_HEADER_LEN);

    fill_pro_common_header(f_ip_header, f_tcp_header);

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

    tc_log_debug_trace(LOG_DEBUG, 0, FAKED_CLIENT_FLAG,
            f_ip_header, f_tcp_header);

    wrap_send_ip_packet(s, f_s_buf, true);
    s->sm.req_halfway_intercepted = 1;
    s->sm.resp_syn_received = 0;
}


/*
 * send faked syn ack packet(the third handshake packet) to back 
 */
static void 
send_faked_third_handshake(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    unsigned char     fake_ack_buf[FAKE_IP_DATAGRAM_LEN];
    tc_ip_header_t   *f_ip_header;
    tc_tcp_header_t  *f_tcp_header;

    memset(fake_ack_buf, 0, FAKE_IP_DATAGRAM_LEN);
    f_ip_header  = (tc_ip_header_t *) fake_ack_buf;
    f_tcp_header = (tc_tcp_header_t *) (fake_ack_buf + IP_HEADER_LEN);
    fill_pro_common_header(f_ip_header, f_tcp_header);
    f_ip_header->id       = htons(++s->req_ip_id);
    f_ip_header->saddr    = s->src_addr;

    /* here record online ip address */
    f_ip_header->daddr    = s->online_addr; 

    f_tcp_header->source  = tcp_header->dest;

    /* here record online port */
    f_tcp_header->dest    = s->online_port;

    f_tcp_header->ack     = 1;
    f_tcp_header->ack_seq = s->vir_ack_seq;
    f_tcp_header->seq     = tcp_header->ack_seq;
    
    tc_log_debug_trace(LOG_DEBUG, 0, FAKED_CLIENT_FLAG,
            f_ip_header, f_tcp_header);

    wrap_send_ip_packet(s, fake_ack_buf, false);
}


/*
 * send faked ack packet to backend from the backend packet
 */
static void 
send_faked_ack(session_t *s, tc_ip_header_t *ip_header, 
        tc_tcp_header_t *tcp_header, bool active)
{
    tc_ip_header_t   *f_ip_header;
    tc_tcp_header_t  *f_tcp_header;
    unsigned char   fake_ack_buf[FAKE_IP_DATAGRAM_LEN];

    memset(fake_ack_buf, 0, FAKE_IP_DATAGRAM_LEN);
    f_ip_header  = (tc_ip_header_t *) fake_ack_buf;
    f_tcp_header = (tc_tcp_header_t *) (fake_ack_buf + IP_HEADER_LEN);

    fill_pro_common_header(f_ip_header, f_tcp_header);

    f_ip_header->id       = htons(++s->req_ip_id);
    f_ip_header->saddr    = ip_header->daddr;
    f_tcp_header->source  = tcp_header->dest;
    f_tcp_header->ack     = 1;
    f_tcp_header->ack_seq = s->vir_ack_seq;
    if (active) {
        /* seq determined by session virtual next seq */
        f_tcp_header->seq = htonl(s->vir_next_seq);
    } else {
        /* seq determined by backend ack seq */
        f_tcp_header->seq = tcp_header->ack_seq;
    }
    s->sm.unack_pack_omit_save_flag = 1;
    wrap_send_ip_packet(s, fake_ack_buf, false);
}

/*
 * send faked reset packet to backend from the backend packet
 */
static void 
send_faked_rst(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    uint16_t          cont_len;
    unsigned char     faked_rst_buf[FAKE_IP_DATAGRAM_LEN];
    tc_ip_header_t   *f_ip_header;
    tc_tcp_header_t  *f_tcp_header;

    tc_log_debug1(LOG_DEBUG, 0, "send faked rst:%u", s->src_h_port);

    memset(faked_rst_buf, 0, FAKE_IP_DATAGRAM_LEN);
    f_ip_header  = (tc_ip_header_t *) faked_rst_buf;
    f_tcp_header = (tc_tcp_header_t *) (faked_rst_buf + IP_HEADER_LEN);
    fill_pro_common_header(f_ip_header, f_tcp_header);
    f_ip_header->id       = htons(++s->req_ip_id);
    f_ip_header->saddr    = ip_header->daddr;
    f_tcp_header->source  = tcp_header->dest;
    f_tcp_header->rst     = 1;
    f_tcp_header->ack     = 1;

    cont_len = get_pack_cont_len(ip_header, tcp_header);

    if (cont_len > 0) {   
        s->vir_ack_seq = htonl(ntohl(tcp_header->seq) + cont_len); 
    } else {
        s->vir_ack_seq = tcp_header->seq;
    }

    f_tcp_header->ack_seq = s->vir_ack_seq;
    f_tcp_header->seq = tcp_header->ack_seq;
    s->sm.unack_pack_omit_save_flag = 1;
    wrap_send_ip_packet(s, faked_rst_buf, false);
    s->sm.reset_sent = 1;
}

/*
 * fake the first handshake packet for intercepting already 
 * connected online packets
 */
static void
fake_syn(session_t *s, tc_ip_header_t *ip_header, 
        tc_tcp_header_t *tcp_header, bool is_hard)
{
    bool      result;
    uint16_t  target_port;
    uint64_t  new_key;

    tc_log_debug1(LOG_DEBUG, 0, "fake syn:%u", s->src_h_port);

    if (is_hard) {
        while (true) {
            target_port = get_port_by_rand_addition(tcp_header->source);
            s->src_h_port = target_port;
            target_port   = htons(target_port);
            new_key       = get_key(ip_header->saddr, target_port);
            if (hash_find(sessions_table, new_key) == NULL) {
                break;
            } else {
                tc_log_info(LOG_NOTICE, 0, "already exist:%u", s->src_h_port);
            }
        }

#if (TCPCOPY_MYSQL_BASIC)
        tc_log_info(LOG_NOTICE, 0, "change port from :%u to :%u",
                ntohs(tcp_header->source), s->src_h_port);
#endif

        hash_add(tf_port_table, new_key, (void *) (long) s->orig_src_port);
        tcp_header->source = target_port;
        s->faked_src_port  = tcp_header->source;
        s->sm.port_transfered = 1;
    }

    /* send route info to backend */
    result = send_router_info(ip_header->daddr, tcp_header->dest,
            ip_header->saddr, tcp_header->source, CLIENT_ADD);
    if (!result) {
        return;
    }

    send_faked_syn(s, ip_header, tcp_header);

    s->sm.req_syn_ok = 1;
    if (is_hard) {
        recon_for_closed_cnt++;
    } else {
        recon_for_no_syn_cnt++;
    }
}


#if (TCPCOPY_MYSQL_BASIC)
/*
 * check if the packet is needed for reconnection by mysql 
 */
static bool
mysql_check_reconnection(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    uint16_t        size_ip, size_tcp, tot_len, cont_len;
    link_list      *list;
    unsigned char  *payload, command;

    size_ip  = ip_header->ihl << 2;
    size_tcp = tcp_header->doff << 2;
    tot_len  = ntohs(ip_header->tot_len);
    cont_len = tot_len - size_tcp - size_ip;

    if (cont_len > 0) {

        payload = (unsigned char *) ((char *) tcp_header + size_tcp);
        /* skip packet length */
        payload = payload + 3;
        /* skip packet number */
        payload = payload + 1;
        /* get commmand */
        command = payload[0];

        if (command == COM_STMT_PREPARE||
                (s->sm.mysql_prepare_stat && s->sm.mysql_first_excution))
        {
            if (command == COM_STMT_PREPARE) {
                s->sm.mysql_prepare_stat = 1;
            } else {
                if (command == COM_QUERY && s->sm.mysql_prepare_stat) {
                    if (s->mysql_excute_times > 0) {
                        s->sm.mysql_first_excution = 0;
                    }
                    s->mysql_excute_times++;
                }
                if (!s->sm.mysql_first_excution) {
                    return false;
                }
            }

            save_packet(s->mysql_special_packets, ip_header, tcp_header);

            tc_log_debug1(LOG_DEBUG, 0, "push statement:%u", s->src_h_port);

            list = (link_list *)hash_find(mysql_table, s->src_h_port);
            if (!list) {
                list = link_list_create();
                if (list == NULL) {
                    tc_log_info(LOG_ERR, 0, "list create err");
                    return false;
                } else {
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
 * check if the packet is the right packet for starting a new session 
 * by mysql tcpcopy
 */
static bool
check_mysql_padding(tc_ip_header_t *ip_header, tc_tcp_header_t *tcp_header)
{
    uint16_t        size_ip, size_tcp, tot_len, cont_len;
    unsigned char  *payload, command, pack_number;

#if (TCPCOPY_MYSQL_ADVANCED)
    uint64_t key    = get_key(ip_header->saddr, tcp_header->source);
    void     *value = hash_find(fir_auth_pack_table, key);
    if (value == NULL) {
        return false;
    }
#else
    /* valid only for mysql skip-grant-tables*/
    if (fir_auth_u_p == NULL) {
        return false;
    }
#endif

    size_ip  = ip_header->ihl << 2;
    size_tcp = tcp_header->doff << 2;
    tot_len  = ntohs(ip_header->tot_len);
    cont_len = tot_len - size_tcp - size_ip;

    if (cont_len > 0) {
        payload = (unsigned char *) ((char *) tcp_header + size_tcp);
        /* skip packet length */
        payload = payload + 3;
        /* get packet number */
        pack_number = payload[0];
        /* if it is the second authenticate_user,then skip it */
        if (pack_number != 0) {
            return false;
        }
        /* skip packet number */
        payload = payload + 1;
        command = payload[0];
        if (command == COM_QUERY) {
            return true;
        }
    }

    return false;
}
#endif


static int
check_backend_ack(session_t *s, tc_ip_header_t *ip_header,
         tc_tcp_header_t *tcp_header, uint32_t seq, uint32_t ack)
{
    bool slide_window_empty = false;

    /* if ack from test server is more than what we expect */
    if (ack > s->vir_next_seq) {
        tc_log_info(LOG_NOTICE, 0, "ack more than vir next seq");
        if (!s->sm.resp_syn_received) {
            s->sm.sess_over = 1;
            return DISP_STOP;
        }
        s->vir_next_seq = ack;
    } else if (ack < s->vir_next_seq) {

        /* if ack from test server is less than what we expect */
        tc_log_debug3(LOG_DEBUG, 0, "bak_ack less than vir_next_seq:%u,%u,p:%u",
                ack, s->vir_next_seq, s->src_h_port);

        if (!s->sm.resp_syn_received) {
            /* try to eliminate the tcp state of backend */
            send_faked_rst(s, ip_header, tcp_header);
            s->sm.sess_over = 1;
            return DISP_STOP;
        }

        if (s->sm.src_closed && !tcp_header->fin) {
            send_faked_ack(s, ip_header, tcp_header, true);
            return DISP_STOP;
        } else {
            /* simulaneous close */
            if (s->sm.src_closed && tcp_header->fin) {
                s->sm.simul_closing = 1;
            }
        }

        /* when the slide window in test server is full*/
        if (tcp_header->window == 0) {
            tc_log_info(LOG_NOTICE, 0, "slide window zero:%u", s->src_h_port);
            /* Although slide window is full, it may require retransmission */
            if (!s->sm.last_window_full) {
                s->resp_last_ack_seq = ack;
                s->resp_last_seq     = seq;
                s->sm.last_window_full  = 1;
                update_retransmission_packets(s);
                return DISP_STOP;
            }

        } else {
            if (s->sm.last_window_full) {
                s->sm.last_window_full = 0;
                s->sm.vir_already_retransmit = 0;
                slide_window_empty = true;
            }
        }

        if (ack != s->resp_last_ack_seq) {
            s->resp_last_same_ack_num = 0;
            s->sm.vir_already_retransmit = 0;
            return DISP_CONTINUE;
        }

        /* check if it needs retransmission */
        if (!tcp_header->fin && seq == s->resp_last_seq
                && ack == s->resp_last_ack_seq)
        {
            s->resp_last_same_ack_num++;
            /* a packet loss when receving three acknowledgement duplicates */
            if (s->resp_last_same_ack_num > 1) {
                /* retransmission needed */
                tc_log_info(LOG_WARN, 0, "bak lost packs:%u,same ack:%d", 
                        s->src_h_port, s->resp_last_same_ack_num);

                if (!s->sm.vir_already_retransmit) {
                    if (!retransmit_packets(s, ack)) {
                        /* retransmit failure, send reset */
                        send_faked_rst(s, ip_header, tcp_header);
                    }
                    s->sm.vir_already_retransmit = 1;
                } else {
                    tc_log_info(LOG_WARN, 0, "omit retransmit:%u",
                            s->src_h_port);
                }

                if (slide_window_empty) {
                    /* send reserved packets when slide window available */
                    send_reserved_packets(s);
                }
                return DISP_STOP;
            }
        }
    }

    return DISP_CONTINUE;
}


static void
process_back_syn(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    conn_cnt++;

    tc_log_debug1(LOG_DEBUG, 0, "recv syn from back:%u", s->src_h_port);

    s->sm.resp_syn_received = 1;
    s->sm.status = SYN_CONFIRM;
    s->vir_ack_seq = htonl(ntohl(tcp_header->seq) + 1);
    s->sm.dst_closed  = 0;
    s->sm.reset_sent  = 0;

    if (s->sm.req_halfway_intercepted) {
        send_faked_third_handshake(s, ip_header, tcp_header);
        send_reserved_packets(s);
    } else {
        send_reserved_packets(s);
    }

}

static void
process_back_fin(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    tc_log_debug1(LOG_DEBUG, 0, "recv fin from back:%u", s->src_h_port);

    s->sm.dst_closed = 1;
    s->sm.candidate_response_waiting = 0;
    s->sm.status  |= SERVER_FIN;
    send_faked_ack(s, ip_header, tcp_header, s->sm.simul_closing?true:false);

    if (!s->sm.src_closed) {
        /* 
         * add seq here in order to keep the rst packet's ack right 
         * because we send two packets here and are all dependent 
         * on this packet
         */
        tcp_header->seq = htonl(ntohl(tcp_header->seq) + 1);
        /* send the constructed reset packet to backend */
        send_faked_rst(s, ip_header, tcp_header);
    }
    /* 
     * Why session over in such situations?
     * Just for releasing router info.
     * Too many router info will slow the intercept program 
     */
    s->sm.sess_over = 1;
}


#if (TCPCOPY_MYSQL_BASIC)
static int
mysql_process_greet(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header, uint16_t cont_len)
{
#if (TCPCOPY_MYSQL_ADVANCED)
    int            ret; 
    unsigned char *payload;
#endif

    tc_log_info(LOG_NOTICE, 0, "recv greeting from back:%u", s->src_h_port);

#if (TCPCOPY_MYSQL_ADVANCED) 
    s->sm.mysql_sec_auth_checked  = 0;
    payload = (unsigned char *) ((char *) tcp_header + sizeof(tc_tcp_header_t));
    memset(s->mysql_scramble, 0, SCRAMBLE_LENGTH + 1);
    ret = parse_handshake_init_cont(payload, cont_len, s->mysql_scramble);
    tc_log_info(LOG_WARN, 0, "scram:%s,p:%u", s->mysql_scramble, s->src_h_port);
    if (!ret) {
        /* Try to print error info*/
        if (cont_len > 11) {
            tc_log_debug_trace(LOG_DEBUG, 0, BACKEND_FLAG,
                    ip_header, tcp_header);
            tc_log_info(LOG_WARN, 0, "port:%u,payload:%s",
                        s->src_h_port, (char *) (payload + 11));
        }
        s->sm.sess_over = 1;
        return DISP_STOP;
    }
#endif

    return DISP_CONTINUE;
}


#if (TCPCOPY_MYSQL_ADVANCED)
static void
mysql_check_need_sec_auth(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    unsigned char *payload;

    tc_log_info(LOG_NOTICE, 0, "check if it needs second auth:%u",
                s->src_h_port);

    payload = (unsigned char *) ((char *) tcp_header + sizeof(tc_tcp_header_t));

     /* check if it is the last data packet */
    if (is_last_data_packet(payload)) {
        /* sec auth needed */ 
        tc_log_debug_trace(LOG_DEBUG, 0, BACKEND_FLAG, ip_header, tcp_header);
        tc_log_info(LOG_WARN, 0, "it needs sec auth:%u", s->src_h_port);
        s->sm.mysql_sec_auth = 1;
    }
}
#endif
#endif


/*
 * processing backend packets
 * TODO (Have not considered TCP Keepalive situations)
 */
void
process_backend_packet(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    time_t    current;
    uint16_t  size_ip, size_tcp, tot_len, cont_len;
    uint32_t  ack, seq;

#if (TCPCOPY_MYSQL_BASIC)
    bool is_greet = false; 
#endif

    resp_cnt++;

    tc_log_debug_trace(LOG_DEBUG, 0, BACKEND_FLAG, ip_header, tcp_header);

    if ( tcp_header->rst) {
        s->sm.reset_sent = 1;
        tc_log_debug1(LOG_DEBUG, 0, "reset from back:%u", s->src_h_port);
        return;
    }

    /* retrieve packet info */
    seq      = ntohl(tcp_header->seq);
    ack      = ntohl(tcp_header->ack_seq);
    tot_len  = ntohs(ip_header->tot_len);
    size_ip  = ip_header->ihl << 2;
    size_tcp = tcp_header->doff << 2;
    cont_len = tot_len - size_tcp - size_ip;

    current  = tc_time();

    if (cont_len > 0) {

        /* calculate the total successful retransmisssons */
        if (s->sm.vir_new_retransmit) {
            retrans_succ_cnt++;
            s->sm.vir_new_retransmit = 0;
        }
        if (seq != s->resp_last_seq || ack != s->resp_last_ack_seq) {
            s->resp_last_same_ack_num = 0;
        }
        s->sm.vir_already_retransmit = 0;
        resp_cont_cnt++;
        s->resp_last_recv_cont_time = current;
        s->vir_ack_seq = htonl(ntohl(tcp_header->seq) + cont_len);
    } else {
        s->vir_ack_seq = tcp_header->seq;
    }

    /* need to check ack */
    if (check_backend_ack(s, ip_header, tcp_header, seq, ack) 
            == DISP_STOP) {
        s->resp_last_ack_seq = ack;
        s->resp_last_seq     = seq;
        return;
    }

    s->resp_last_seq     = seq;
    s->resp_last_ack_seq = ack;
    /* update session's retransmisson packets */
    update_retransmission_packets(s);

     /* process syn, fin or ack packet here */
    if ( tcp_header->syn) {

        if (!s->sm.resp_syn_received) {
            /* process syn packet */
            process_back_syn(s, ip_header, tcp_header);
        } else {
            s->vir_ack_seq = htonl(ntohl(s->vir_ack_seq) + 1);
        }
        return;
    } else if (tcp_header->fin) {

        s->vir_ack_seq = htonl(ntohl(s->vir_ack_seq) + 1);
        /* process fin packet */
        process_back_fin(s, ip_header, tcp_header);
        return;
    } else if (tcp_header->ack) {

        /* process ack packet */
        if (s->sm.src_closed && s->sm.dst_closed) {
            s->sm.sess_over = 1;
            return;
        }
    }

    if (!s->sm.resp_syn_received) {

        tc_log_info(LOG_NOTICE, 0, "unbelievable:%u", s->src_h_port);
        tc_log_trace(LOG_NOTICE, 0, BACKEND_FLAG, ip_header, tcp_header);
        /* try to solve backend's obstacle */
        send_faked_rst(s, ip_header, tcp_header);
        return;
    }

    /* 
     * It is nontrivial to check if the packet is the last packet 
     * of the response
     */
    if (cont_len > 0) {

        if (s->sm.src_closed) {
            /* try to solve the obstacle */ 
            send_faked_rst(s, ip_header, tcp_header);
            return;
        }

        if (s->sm.status < SEND_REQ) {
            if (!s->sm.resp_greet_received) {
                s->sm.resp_greet_received = 1;
                s->sm.need_resp_greet = 0;
#if (TCPCOPY_MYSQL_BASIC)
                is_greet = true;
#endif
            }
        }

#if (TCPCOPY_MYSQL_BASIC)
        if (is_greet && mysql_process_greet(s, ip_header, tcp_header, cont_len)
                == DISP_STOP) {
            return;
        }
#if (TCPCOPY_MYSQL_ADVANCED)
        if (!is_greet) {
            if (s->sm.mysql_sec_auth_checked == 0) {
                mysql_check_need_sec_auth(s, ip_header, tcp_header);
                s->sm.mysql_sec_auth_checked = 1;
            }
        }
#endif

#endif

        /* TODO Why mysql does not need this packet ? */
        send_faked_ack(s, ip_header, tcp_header, true);

#if (TCPCOPY_MYSQL_BASIC)
        if (s->sm.candidate_response_waiting || is_greet)
#else
            if (s->sm.candidate_response_waiting)
#endif
            {
                tc_log_debug0(LOG_DEBUG, 0, "receive back server's resp");
                s->sm.candidate_response_waiting = 0;
                s->sm.status = RECV_RESP;
                s->sm.delay_sent_flag = 0;
                send_reserved_packets(s);
                return;
            }
    } else {
        /* no content in packet */

        if (s->sm.delay_sent_flag) {
            tc_log_debug1(LOG_DEBUG, 0, "send delayed cont:%u", s->src_h_port);
            s->sm.delay_sent_flag = 0;
            send_reserved_packets(s);
            return;
        }
        if (s->sm.src_closed && !s->sm.dst_closed) {
            send_faked_rst(s, ip_header, tcp_header);
            s->sm.sess_over = 1;
            return;
        }
    }
}


static void
process_client_rst(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)  
{
    uint32_t seq;

    tc_log_debug1(LOG_DEBUG, 0, "reset from client:%u", s->src_h_port);

    if (s->sm.candidate_response_waiting) {
        save_packet(s->unsend_packets, ip_header, tcp_header);
    } else {
        seq = ntohl(tcp_header->seq);   
        if (seq < s->vir_next_seq) {
            tcp_header->seq = htonl(s->vir_next_seq);
        }
        s->sm.unack_pack_omit_save_flag = 1;
        wrap_send_ip_packet(s, (unsigned char *) ip_header, true);
        s->sm.reset = 1;
    }
}


static void
process_client_syn(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)  
{
#if (TCPCOPY_MYSQL_BASIC)
    link_list     *list;
    p_link_node    ln, tmp_ln;
#endif

    s->sm.req_syn_ok = 1;

    tc_log_debug1(LOG_DEBUG, 0, "syn port:%u", s->src_h_port);

#if (TCPCOPY_MYSQL_BASIC)
    /* remove old mysql info*/
    list = (link_list *)hash_find(mysql_table, s->src_h_port);
    if (list) {
        ln = link_list_first(list); 
        while (ln) {
            tmp_ln = ln;
            ln = link_list_get_next(list, ln);
            link_list_remove(list, tmp_ln);
            free(tmp_ln->data);
            free(tmp_ln);
        }
        if (!hash_del(mysql_table, s->src_h_port)) {
            tc_log_info(LOG_ERR, 0, "mysql table hash not deleted");
        }
        free(list);
    }
#endif

    wrap_send_ip_packet(s, (unsigned char *) ip_header, true);
}

static int
process_client_fin(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)  
{
    uint16_t cont_len;

    tc_log_debug1(LOG_DEBUG, 0, "recv fin from clt:%u", s->src_h_port);

    s->sm.status |= CLIENT_FIN;
    cont_len = get_pack_cont_len(ip_header, tcp_header);
    if (cont_len > 0) {
        tc_log_debug1(LOG_DEBUG, 0, "fin has content:%u", s->src_h_port);
        return DISP_CONTINUE;
    }

    /* practical experience */
    if (s->resp_last_ack_seq == ntohl(tcp_header->seq)) {
        if (s->sm.candidate_response_waiting) {
            save_packet(s->unsend_packets, ip_header, tcp_header);
        } else {
            wrap_send_ip_packet(s, (unsigned char *) ip_header, true);
            s->sm.status |= CLIENT_FIN;
            s->sm.src_closed = 1;
        }

    } else {
        save_packet(s->unsend_packets, ip_header, tcp_header);
    }

    return DISP_STOP;
}


#if (TCPCOPY_MYSQL_BASIC)
static int
process_mysql_clt_auth_pack(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header, uint16_t cont_len)  
{   
    bool           is_need_omit;

#if (!TCPCOPY_MYSQL_ADVANCED)
    unsigned char *payload, pack_number;
    uint16_t       size_tcp;
#endif

    if (!s->sm.req_halfway_intercepted) {
        is_need_omit = false;
#if (TCPCOPY_MYSQL_ADVANCED)
        if (s->sm.resp_greet_received) {
            if (mysql_dispose_auth(s, ip_header, tcp_header) == FAILURE) {
                return DISP_STOP;
            }
        }
#endif

#if (!TCPCOPY_MYSQL_ADVANCED)
        if (!s->sm.mysql_req_begin) {
            /*
             * check if mysql protocol validation ends? 
             */
            size_tcp    = tcp_header->doff << 2;
            payload     = (unsigned char *) ((char *) tcp_header + size_tcp);
            /* skip packet length */
            payload     = payload + 3;
            pack_number = payload[0];
            /* if it is the second authenticate_user,then skip it */
            if (pack_number == 3) {
                is_need_omit = true;
                s->sm.mysql_req_begin = 1;
                tc_log_info(LOG_NOTICE, 0, "this is the sec auth packet");
            }
            if (pack_number == 0) {
                s->sm.mysql_req_begin = 1;
                tc_log_info(LOG_NOTICE, 0, "it has no sec auth packet");
            }
        }
#else
        s->sm.mysql_req_begin = 1;
#endif

        if (is_need_omit) {
            tc_log_info(LOG_NOTICE, 0, "omit sec validation for mysql");
            s->mysql_vir_req_seq_diff = cont_len;
            g_seq_omit = s->mysql_vir_req_seq_diff;
            return DISP_STOP;
        }

        if (!s->sm.mysql_req_begin) {
            if (!fir_auth_u_p) {
                fir_auth_u_p = (tc_ip_header_t *) copy_ip_packet(ip_header);
                tc_log_info(LOG_NOTICE, 0, "fir auth is set");
            }

            if (s->sm.resp_greet_received) {
                s->sm.mysql_req_login_received = 1;
            } else {
                if (!s->sm.mysql_req_login_received) {
                    s->sm.mysql_req_login_received = 1;
                    save_packet(s->unsend_packets, ip_header, tcp_header);
                    return DISP_STOP;
                }
            }
        }

        mysql_check_reconnection(s, ip_header, tcp_header);
        if (!s->sm.resp_greet_received) {
            save_packet(s->unsend_packets, ip_header, tcp_header);
            return DISP_STOP;
        }
    }

    return DISP_CONTINUE;
}
#endif


/* 
 * When the connection to the backend is closed, we 
 * reestablish the connection and 
 * we reserve all comming packets for later disposure
 */
static void
proc_clt_cont_when_bak_closed(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    uint64_t key;

#if (TCPCOPY_MYSQL_BASIC)
    if (!check_mysql_padding(ip_header, tcp_header)) {
        return;
    }
#endif

    if (s->sm.port_transfered) {
        key = get_key(ip_header->saddr, s->faked_src_port);
        if (!hash_del(tf_port_table, key)) {
            tc_log_info(LOG_WARN, 0, "no hash item for port transfer");
        }
    }

    session_init(s, SESS_KEEPALIVE);
    /* It will change src port when setting true */
    fake_syn(s, ip_header, tcp_header, true);
    save_packet(s->unsend_packets, ip_header, tcp_header);

}


/* check the current packet be saved or not */
static int 
check_pack_save_or_not(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header, int *is_new_req)
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
    if (s->req_cont_last_ack_seq != s->req_cont_cur_ack_seq) {
        *is_new_req = 1;
        tc_log_debug1(LOG_DEBUG, 0, "it is a new req,p:%u", s->src_h_port);
    }

    if (*is_new_req) {
        cur_seq = ntohl(tcp_header->seq);
        if (cur_seq > s->req_last_cont_sent_seq) {
            is_save =true;
        }
    } else {
        if (s->unsend_packets->size > 0) {
            if (check_reserved_content_left(s)) {
                is_save = true;
            }
        }
    }

    if (is_save) {
        save_packet(s->unsend_packets, ip_header, tcp_header);
        return DISP_STOP;
    } else {
        return DISP_CONTINUE;
    }
}


static int
check_wait_prev_packet(session_t *s, tc_ip_header_t *ip_header, 
        tc_tcp_header_t *tcp_header, uint16_t cont_len)
{
    int       diff;
    uint32_t  cur_seq, retransmit_seq;

    cur_seq = ntohl(tcp_header->seq);

    if (cur_seq > s->vir_next_seq) {

        tc_log_debug1(LOG_DEBUG, 0, "lost and need prev:%u", s->src_h_port);
        save_packet(s->unsend_packets, ip_header, tcp_header);
        send_reserved_packets(s);
        return DISP_STOP;
    } else if (cur_seq == s->vir_next_seq) {

        if (s->sm.is_waiting_previous_packet) {
            /* Send the packet and reserved packets */
            wrap_send_ip_packet(s, (unsigned char *)ip_header, true);
            send_reserved_packets(s);
            return DISP_STOP;
        } else {
            return DISP_CONTINUE;
        }
    } else {

        retransmit_seq = s->vir_next_seq - cont_len;
        if (cur_seq <= retransmit_seq) {
            /* retransmission packet from client */
            tc_log_debug1(LOG_DEBUG, 0, "retransmit from clt:%u",
                    s->src_h_port);
        } else {
            diff = s->vir_next_seq - cur_seq;
            if (trim_packet(s, ip_header, tcp_header, diff)) {
                return DISP_CONTINUE;
            }
        }
        return DISP_STOP;
    }
}

static int
is_continuous_packet(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    uint32_t cur_seq = ntohl(tcp_header->seq);

    if (s->sm.candidate_response_waiting) {
        if (cur_seq > s->req_last_cont_sent_seq) {
            wrap_send_ip_packet(s, (unsigned char *) ip_header, true);
            tc_log_debug0(LOG_DEBUG, 0, "it is a continuous req");
            return DISP_STOP;
        }
    }

    return DISP_CONTINUE;
}


/* process client packet info after the main processing */
static void
process_clt_afer_filtering(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header, uint16_t len)
{
    if (!s->sm.candidate_response_waiting) {
        if (len > 0) {
            s->sm.candidate_response_waiting = 1;
            wrap_send_ip_packet(s, (unsigned char *) ip_header, true);
            return;
        } else if (SYN_CONFIRM == s->sm.status) {
            if (s->vir_next_seq == ntohl(tcp_header->seq)) {
                wrap_send_ip_packet(s, (unsigned char *) ip_header, true);
                return;
            }
        }
    }

    tc_log_debug1(LOG_DEBUG, 0, "drop packet:%u", s->src_h_port);
}


/*
 * processing client packets
 * TODO 
 * 1)It have not consider TCP Keepalive
 * 2)TCP is always allowed to send 1 byte of data 
 *   beyond the end of a closed window which confuses tcpcopy.
 * 
 */
void
process_client_packet(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    int       is_new_req = 0;
    uint16_t  cont_len;

    tc_log_debug_trace(LOG_DEBUG, 0, CLIENT_FLAG, ip_header, tcp_header);

    /* change source port for multiple copying,etc */
    if (s->sm.port_transfered != 0) {
        tcp_header->source = s->faked_src_port;
    }

    s->src_h_port = ntohs(tcp_header->source);
    tcp_header->window  = 65535;

#if (TCPCOPY_MYSQL_BASIC)
    /* subtract client packet's seq for mysql */
    if (s->sm.mysql_req_begin) {
        tcp_header->seq = htonl(ntohl(tcp_header->seq) - 
                s->mysql_vir_req_seq_diff);
    }
#endif

    /* if the packet is the next session's packet */
    if (s->sm.sess_more) {
        /* TODO not always right because of this */
        save_packet(s->next_sess_packs, ip_header, tcp_header);
        tc_log_debug1(LOG_DEBUG, 0, "buffer for next session:%u",
                s->src_h_port);
        return;
    }

    /* if slide window is full */
    if (s->sm.last_window_full) {
        save_packet(s->unsend_packets, ip_header, tcp_header);
        return;
    }

    s->online_addr  = ip_header->daddr;
    s->online_port  = tcp_header->dest;

    /* Syn packet has been sent to back,but not recv back's syn */
    if (s->sm.status == SYN_SENT) {
        save_packet(s->unsend_packets, ip_header, tcp_header);
        return;
    }

    /* process the reset packet */
    if (tcp_header->rst) {
        process_client_rst(s, ip_header, tcp_header);
        return;
    }

    /* process the syn packet */
    if (tcp_header->syn) {
        process_client_syn(s, ip_header, tcp_header);
        return;
    }

    /* process the fin packet */
    if (tcp_header->fin) {
        if (process_client_fin(s, ip_header, tcp_header) == DISP_STOP) {
            return;
        }
    }

    /* if not receiving syn packet */ 
    if (!s->sm.req_syn_ok) {
        s->sm.req_halfway_intercepted = 1;
        fake_syn(s, ip_header, tcp_header, false);
        s->req_cont_cur_ack_seq  = ntohl(tcp_header->ack_seq);
        save_packet(s->unsend_packets, ip_header, tcp_header);
        return;
    }

    if (s->sm.status < SEND_REQ && is_wait_greet(s, ip_header, tcp_header)) {
        save_packet(s->unsend_packets, ip_header, tcp_header);
        return;
    }

    /* retrieve the content length of tcp payload */
    cont_len = get_pack_cont_len(ip_header, tcp_header);

    if (cont_len > 0) {
        /* update ack seq values for checking a new request */
        s->req_cont_last_ack_seq = s->req_cont_cur_ack_seq;
        s->req_cont_cur_ack_seq  = ntohl(tcp_header->ack_seq);
        tc_log_debug2(LOG_DEBUG, 0, "cont len:%d,p:%u",
                cont_len, s->src_h_port);
#if (TCPCOPY_MYSQL_BASIC)
        /* process mysql client auth packet */
        if (process_mysql_clt_auth_pack(s, ip_header, tcp_header, cont_len)
                == DISP_STOP)
        {
            return;
        }
#endif
        if (s->sm.dst_closed || s->sm.reset_sent) {
            /* when backend is closed or we have sent rst packet */
            proc_clt_cont_when_bak_closed(s, ip_header, tcp_header);
            return;
        }

        /* check if the packet is to be saved for later use */
        if (s->sm.candidate_response_waiting) {
            if (check_pack_save_or_not(s, ip_header, tcp_header, &is_new_req)
                    == DISP_STOP)
            {
                return;
            }
        }

        /* check if current session needs to wait prevous packet */
        if (check_wait_prev_packet(s, ip_header, tcp_header, cont_len)
                == DISP_STOP)
        {
            return;
        }

        /* check if it is a continuous packet */
        if (!is_new_req && is_continuous_packet(s, ip_header, tcp_header)
                == DISP_STOP)
        {
            return;
        }

        tc_log_debug0(LOG_DEBUG, 0, "a new request from client");
    }

    /* post disposure */
    process_clt_afer_filtering(s, ip_header, tcp_header, cont_len);
}


void
restore_buffered_next_session(session_t *s)
{
    uint16_t          size_ip;
    p_link_node       ln;
    unsigned char    *data;
    tc_ip_header_t   *ip_header;
    tc_tcp_header_t  *tcp_header;

    ln     = link_list_first(s->unsend_packets);    
    data   = (unsigned char *) ln->data;
    link_list_remove(s->unsend_packets, ln);
    ip_header  = (tc_ip_header_t *) ((char *) data);
    size_ip    = ip_header->ihl << 2;
    tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);

    process_client_packet(s, ip_header,tcp_header);

    free(data);
    free(ln);
}


/*
 * filter packets 
 */
bool
is_packet_needed(const char *packet)
{
    bool              is_needed = false;
    uint16_t          size_ip, size_tcp, tot_len, cont_len, header_len, key;
    tc_ip_header_t   *ip_header;
    tc_tcp_header_t  *tcp_header;

    ip_header = (tc_ip_header_t *) packet;

    /* check if it is a tcp packet(could be removed) */
    if (ip_header->protocol != IPPROTO_TCP) {
        return is_needed;
    }

    size_ip   = ip_header->ihl << 2;
    tot_len   = ntohs(ip_header->tot_len);
    if (size_ip < 20) {
        tc_log_info(LOG_WARN, 0, "Invalid IP header length: %d", size_ip);
        return is_needed;
    }

    tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);
    size_tcp   = tcp_header->doff << 2;
    if (size_tcp < 20) {
        tc_log_info(LOG_WARN, 0, "Invalid TCP header len: %d bytes,pack len:%d",
                size_tcp, tot_len);
        return is_needed;
    }

    /* Here we filter the packets we do care about */
    if (LOCAL == check_pack_src(&(clt_settings.transfer), 
                ip_header->daddr, tcp_header->dest, CHECK_DEST)) {
        header_len = size_tcp + size_ip;
        if (tot_len >= header_len) {

            if (clt_settings.percentage) {
                key = 0xFFFF & (tcp_header->source + ip_header->saddr);
                key = ((key & 0xFF00) >> 8) + (key & 0x00FF);
                key = key % 100;
                if (key >= clt_settings.percentage) {
                    return is_needed;
                }
            }
            is_needed = true;
            cont_len  = tot_len - header_len;
            if (tcp_header->syn) {
                clt_syn_cnt++;
            } else if (cont_len > 0) {
                clt_cont_cnt++;
            }
            clt_packs_cnt++;
        } else {
            tc_log_info(LOG_WARN, 0, "bad tot_len: %d bytes,header len:%d",
                    tot_len, header_len);
        }
    }

    return is_needed;

}


/*
 * output statistics
 */
void
output_stat()
{
    int       run_time;
    double    ratio;

    if (start_p_time == 0) {
        return;
    }

    tc_log_info(LOG_NOTICE, 0, "active:%u,rel reqs:%llu,obs del:%llu",
            sessions_table->total, leave_cnt, obs_cnt);
    tc_log_info(LOG_NOTICE, 0, "conns:%llu,resp packs:%llu,c-resp packs:%llu",
            conn_cnt, resp_cnt, resp_cont_cnt);
    tc_log_info(LOG_NOTICE, 0, "send Packets:%llu,send content packets:%llu",
            packs_sent_cnt, con_packs_sent_cnt);
    tc_log_info(LOG_NOTICE, 0, "reconnect for closed :%llu,for no syn:%llu",
            recon_for_closed_cnt, recon_for_no_syn_cnt);
    tc_log_info(LOG_NOTICE, 0, "retransmit:%llu", retrans_cnt);
    tc_log_info(LOG_NOTICE, 0, "successful retransmit:%llu", retrans_succ_cnt);
    tc_log_info(LOG_NOTICE, 0, "syn cnt:%llu,all clt packs:%llu,clt cont:%llu",
            clt_syn_cnt, clt_packs_cnt, clt_cont_cnt);

    run_time = tc_time() - start_p_time;

    if (run_time > 3) {
        if (resp_cont_cnt == 0) {
            tc_log_info(LOG_WARN, 0, "no responses after %d secends",
                        run_time);
        }
        if (sessions_table->total > 0) {
            ratio = 100 * conn_cnt / sessions_table->total;
            if (ratio < 80) {
                tc_log_info(LOG_WARN, 0,
                        "many connections can't be established");
            }
        }
    }

}


void
tc_interval_dispose(tc_event_timer_t *evt)
{
    /* output stat */
    output_stat();

    /* clear timeout sessions */
    clear_timeout_sessions();

    /* activate dead session */
    activate_dead_sessions();

    evt->msec = tc_current_time_msec + 5000;
}


/*
 * main procedure for processing the filtered packets
 */
bool
process(char *packet, int pack_src)
{
    bool               result;
    void              *ori_port;
    uint16_t           size_ip;
    uint64_t           key;
    session_t         *s;
    tc_ip_header_t    *ip_header;
    tc_tcp_header_t   *tcp_header;

    if (start_p_time == 0) {
        start_p_time = tc_time();
    }

    ip_header  = (tc_ip_header_t *) packet;
    size_ip    = ip_header->ihl << 2;
    tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);

    if (pack_src == REMOTE) {

        /* when the packet comes from the targeted test machine */
        key = get_key(ip_header->daddr, tcp_header->dest);
        s = hash_find(sessions_table, key);
        if (s == NULL) {
            /* give another chance for port changed*/
            ori_port = hash_find(tf_port_table, key);
            if (ori_port != NULL) {
                key = get_key(ip_header->daddr, (uint16_t) (long) ori_port);
                s = hash_find(sessions_table, key);
            }
        }

        if (s) {

            s->last_update_time = tc_time();
            process_backend_packet(s, ip_header, tcp_header);
            if (check_session_over(s)) {
                if (s->sm.sess_more) {
                    /* restore the next session which has the same key */
                    session_init_for_next(s);
                    tc_log_info(LOG_NOTICE, 0, "init for next sess from bak");
                    restore_buffered_next_session(s);
                } else {
                    send_router_info(s->online_addr, s->online_port,
                            ip_header->daddr, tcp_header->dest, CLIENT_DEL);
                    session_rel_dynamic_mem(s);
                    if (!hash_del(sessions_table, s->hash_key)) {
                        tc_log_info(LOG_ERR, 0, "wrong del:%u", s->src_h_port);
                    }
                    free(s);
                }
            }
        } else {
            tc_log_debug_trace(LOG_DEBUG, 0, BACKEND_FLAG, ip_header,
                    tcp_header);
            tc_log_debug0(LOG_DEBUG, 0, "no active session for me");
        }
    } else if (pack_src == LOCAL) {

        /* when the packet comes from client */
        if (clt_settings.factor) {
            /* change client source port*/
            tcp_header->source = get_port_from_shift(tcp_header->source,
                    clt_settings.rand_port_shifted, clt_settings.factor);
        }
        key = get_key(ip_header->saddr, tcp_header->source);
        if (tcp_header->syn) {

            s  = hash_find(sessions_table, key);
            if (s) {
                /* check if it is a duplicate syn */
                if (tcp_header->seq == s->req_last_syn_seq) {
                    tc_log_debug0(LOG_DEBUG, 0, "duplicate syn");
                    return true;
                } else {
                    /*
                     * buffer the next session to current session
                     * (only support one more session which has the hash key)
                     */
                    s->sm.sess_more = 1;
                    if (s->next_sess_packs) {
                        if (s->next_sess_packs->size > 0) {
                            link_list_clear(s->next_sess_packs);
                        }
                    } else {
                        s->next_sess_packs = link_list_create();
                    }
                    save_packet(s->next_sess_packs, ip_header, tcp_header);
                    tc_log_debug0(LOG_DEBUG, 0, "buffer the new session");
                    return true;
                }
            } else {
                /* create a new session */
                s = session_add(key, ip_header, tcp_header);
                if (s == NULL) {
                    return true;
                }
            }

            result = send_router_info(ip_header->daddr, tcp_header->dest, 
                    ip_header->saddr, tcp_header->source, CLIENT_ADD);
            if (result) {
                process_client_packet(s, ip_header, tcp_header);
            }

        } else {

            s = hash_find(sessions_table, key);
            if (s) {
                process_client_packet(s, ip_header, tcp_header);
                s->last_update_time = tc_time();
                if (check_session_over(s)) {
                    if (s->sm.sess_more) {
                        session_init_for_next(s);
                        tc_log_info(LOG_NOTICE, 0, "init for next from clt");
                        restore_buffered_next_session(s);
                    } else {
                        send_router_info(s->online_addr, s->online_port,
                                ip_header->saddr, htons(s->src_h_port),
                                CLIENT_DEL);
                        session_rel_dynamic_mem(s);
                        if (!hash_del(sessions_table, s->hash_key)) {
                            tc_log_info(LOG_ERR, 0, "wrong del:%u",
                                    s->src_h_port);
                        }
                        free(s);
                    }
                }
            } else {
                /* check if we can pad tcp handshake */
                if (get_pack_cont_len(ip_header, tcp_header) > 0) {
#if (TCPCOPY_MYSQL_BASIC)
                   if (!check_mysql_padding(ip_header,tcp_header)) {
                        return false;
                    }
#endif
                    s = session_add(key, ip_header, tcp_header);
                    if (s == NULL) {
                        return true;
                    }
                    process_client_packet(s, ip_header, tcp_header);
                } else {
                    return false;
                }
            }
        }
    } else {
        /* don't know where the packet comes from */
        tc_log_info(LOG_WARN, 0, "unknown packet");
        tc_log_trace(LOG_WARN, 0, UNKNOWN_FLAG, ip_header, tcp_header);
        return false;
    }

    return true;
}

