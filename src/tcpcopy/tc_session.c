
#include <xcopy.h>
#include <tcpcopy.h>

static bool retrans_pack(tc_sess_t *, uint32_t);
static bool proc_clt_pack_from_buffer(tc_sess_t *);
static void send_pack(tc_sess_t *, tc_iph_t *, tc_tcph_t *, bool);
static void utimer_disp(tc_sess_t *, int, int);
static void update_retrans_packs(tc_sess_t *);
static void snd_rst(tc_sess_t *);
static void update_timestamp(tc_sess_t *, tc_tcph_t *);
static void send_faked_ack_from_timer(tc_sess_t *);
static void proc_bak_fin(tc_sess_t *, tc_iph_t *, tc_tcph_t *);
static void proc_bak_syn(tc_sess_t *, tc_tcph_t *);
static void sess_timeout(tc_event_timer_t *ev);
static inline void fill_pro_common_header(tc_iph_t *, tc_tcph_t *);
static inline int overwhelm(tc_sess_t *, const char *, int, int);
static inline tc_sess_t *sess_add(uint64_t, tc_iph_t *, tc_tcph_t *);

    
static void 
reconstruct_sess(tc_sess_t *s) 
{
    snd_rst(s);

    tc_log_debug1(LOG_INFO, 0, "sess reconstruct:%u", ntohs(s->src_port));

    tc_memzero(&(s->sm), sizeof(sess_state_machine_t));

    s->sm.record_mcon_seq = 1;
    s->sm.recon = 1;
#if (TC_DETECT_MEMORY)
    s->sm.active_timer_cnt = 2;
#endif
    tc_log_debug2(LOG_INFO, 0, "rtt:%ld,p:%u", s->rtt, ntohs(s->src_port));
    utimer_disp(s, s->rtt, TYPE_RECONSTRUCT);
}


static void
sess_post_disp(tc_sess_t *s,  bool complete)
{
    tc_log_debug1(LOG_DEBUG, 0, "sess post disp:%u", ntohs(s->src_port));

#if (TC_DETECT_MEMORY)
    s->sm.call_sess_post_cnt++;
    if (s->sm.call_sess_post_cnt == 1 && s->sm.timeout) {
        tc_log_info(LOG_WARN, 0, "false timeout phrase");
    }
    if (s->sm.call_sess_post_cnt == 2 && s->sm.active_timer_cnt == 2) {
        tc_log_info(LOG_WARN, 0, "false activer timer count");
    }
#endif
    if (!s->sm.timeout) {
        if (!s->sm.sess_over) {
            snd_rst(s);
            s->sm.sess_over = 1;
        }

#if (TC_DEBUG)
        if (s->sm.record_mcon_seq) {
            if (s->sm.state < SND_REQ) {
                tc_log_debug3(LOG_INFO, 0, "req unsend:%u,syn seq:%u,max:%u",
                        ntohs(s->src_port), s->req_syn_seq, s->max_con_seq);
            } else {
                if (!before(s->max_con_seq, s->rep_ack_seq_bf_fin)) {
                    tc_log_debug3(LOG_INFO, 0, "cont unsend:%u,ack:%u,max:%u",
                            ntohs(s->src_port), s->rep_ack_seq_bf_fin, 
                            s->max_con_seq);
                }
            }
        }
#endif
#if (TC_DETECT_MEMORY)
        s->sm.active_timer_cnt--;
#endif
        if (s->ev) {
            if (s->ev->timer_set) {
                s->ev->data = NULL;
                tc_event_del_timer(s->ev);
                s->ev = NULL;
            }
        }

        tc_stat.time_wait_cnt++;
        s->sm.timeout = 1;

        if (!complete) {
            tc_event_update_timer(s->gc_ev, TCP_MS_TIMEOUT);
            return;
        }
    } 

    if (!hash_del(sess_table, s->pool, s->hash_key)) {
        tc_log_info(LOG_ERR, 0, "wrong del:%u", ntohs(s->src_port));
    }

    if (s->gc_ev) {
        if (s->gc_ev->timer_set) {
            s->gc_ev->data = NULL;
            tc_event_del_timer(s->gc_ev);
            s->gc_ev = NULL;
            tc_log_debug2(LOG_NOTICE, 0, "del gc timer:%llu, p:%u",
                    s->hash_key, ntohs(s->src_port));
        }
#if (TC_DETECT_MEMORY)
        s->sm.active_timer_cnt--;
#endif
    }

    tc_stat.time_wait_cnt--;
    tc_stat.leave_cnt++;

#if (TC_DETECT_MEMORY)
    if (s->sm.active_timer_cnt != 0) {
        tc_log_info(LOG_ERR, 0, "possible timer memory leak:%d, %u", 
                s->sm.active_timer_cnt, ntohs(s->src_port));
    }
#endif
    tc_destroy_pool(s->pool);
}


static void
snd_rst(tc_sess_t *s)
{
    tc_iph_t       *ip;
    tc_tcph_t      *tcp;
    unsigned char  *p, frame[FFRAME_LEN];

    tc_log_debug1(LOG_DEBUG, 0, "send passive rst:%u", ntohs(s->src_port));

    tc_memzero(frame, FFRAME_LEN);
    p = frame + ETHERNET_HDR_LEN;

    ip  = (tc_iph_t *) p;
    tcp = (tc_tcph_t *) (p + IPH_MIN_LEN);

    fill_pro_common_header(ip, tcp);
    ip->tot_len  = htons(FMIN_IP_LEN);
    ip->id       = htons(++s->req_ip_id);
    ip->saddr    = s->src_addr;

    tcp->doff    = TCPH_DOFF_MIN_VALUE;
    tcp->source  = s->src_port;
    tcp->rst     = 1;
    tcp->ack     = 1;
    if (!s->sm.src_closed) {
        tcp->seq = htonl(s->target_nxt_seq); 
    } else {
        tcp->seq = htonl(s->target_nxt_seq - 1); 
    }

    s->frame = frame;
    s->cur_pack.cont_len = 0;
    send_pack(s, ip, tcp, true);
}


static inline void 
fill_pro_common_header(tc_iph_t *ip, tc_tcph_t *tcp)
{
    /* IPv4 */
    ip->version  = 4;
    ip->ihl      = IPH_MIN_LEN / 4;
    ip->frag_off = htons(IP_DF); 
    ip->ttl      = 64; 
    ip->protocol = IPPROTO_TCP;
    tcp->window  = 65535; 
}


int
tc_init_sess_table(void)
{
    tc_pool_t *pool = tc_create_pool(TC_DEFAULT_POOL_SIZE, 0, 0);
    if (pool != NULL) {
        sess_table = hash_create(pool, 65536);
        if (sess_table != NULL) {
            return TC_OK;
        }
    }
    return TC_ERR;
}


void
tc_dest_sess_table(void)
{
    size_t       i;           
    tc_sess_t   *s;
    hash_node   *hn;
    link_list   *list;
    p_link_node  ln, tln;

    if (sess_table != NULL) {
        tc_log_info(LOG_INFO, 0, "session table, size:%u, total:%u",
                sess_table->size, sess_table->total);
        for (i = 0; i < sess_table->size; i++) {
            list = sess_table->lists[i];
            ln   = link_list_first(list);   
            while (ln) {
                tln = link_list_get_next(list, ln);
                hn = (hash_node *) ln->data;
                if (hn->data != NULL) {
                    s = hn->data;
                    hn->data = NULL;
#if (TC_DETECT_MEMORY)
                    tc_log_info(LOG_INFO, 0, "sess packs in swin:%d,p:%u",
                            s->slide_win_packs->size, ntohs(s->src_port));
#endif
                    sess_post_disp(s, true);
                }
                ln = tln;
            }
        }
        tc_destroy_pool(sess_table->pool);
        sess_table = NULL;
    }
}


static inline void
sess_init(tc_sess_t *s)
{
    s->slide_win_packs = link_list_create(s->pool);

    s->create_time = tc_time();
    s->rep_rcv_con_time = tc_time();
    s->req_snd_con_time  = tc_time();

    s->sm.state  = CLOSED;
    s->sm.rep_dup_ack_cnt = 0;
}


static tc_sess_t *
sess_create(tc_iph_t *ip, tc_tcph_t *tcp)
{
    int              sub_pl_size;
    tc_sess_t       *s;
    tc_pool_t       *pool;
    transfer_map_t  *test;

#if (!TC_MILLION_SUPPORT)
    sub_pl_size = clt_settings.s_pool_size;
#else
    sub_pl_size = TC_DEFAULT_UPOOL_SIZE;
#endif
    pool = tc_create_pool(TC_DEFAULT_UPOOL_SIZE, sub_pl_size, TC_UPOOL_MAXV);

    if (pool == NULL) {
        return NULL;
    }

    s = (tc_sess_t *) tc_pcalloc(pool, sizeof(tc_sess_t));
    if (s != NULL) {
        s->pool = pool;
        sess_init(s);
        s->src_addr       = ip->saddr;
        s->online_addr    = ip->daddr;
        s->src_port       = tcp->source;
        s->online_port    = tcp->dest;
        test = get_test_pair(&(clt_settings.transfer), s->online_addr, 
                s->online_port);
        s->dst_addr       = test->target_ip;
        s->dst_port       = test->target_port;
#if (TC_PCAP_SND)
        s->src_mac        = test->src_mac;
        s->dst_mac        = test->dst_mac;
#endif
        if (s->src_addr == LOCALHOST && s->dst_addr != LOCALHOST) {
            tc_log_info(LOG_WARN, 0, "src host localost but dst host not");
            tc_log_info(LOG_WARN, 0, "use -H to avoid this warning");
        }

        if (s->src_addr == s->dst_addr) {
            tc_log_info(LOG_WARN, 0, "src host equal to dst host");
        }

        tc_log_debug2(LOG_INFO, 0, "pl:%llu, p:%u", pool, ntohs(s->src_port));

#if (TC_DETECT_MEMORY)
        s->sm.active_timer_cnt = 0;
#endif
        utimer_disp(s, TIMER_DEFAULT_TIMEOUT, TYPE_DEFAULT);
#if (TC_DETECT_MEMORY)
        s->sm.active_timer_cnt++;
#endif
        s->gc_ev = tc_event_add_timer(s->pool, SESS_EST_MS_TIMEOUT, s, 
                sess_timeout);
#if (TC_PLUGIN)
        if (clt_settings.plugin && clt_settings.plugin->proc_when_sess_created)
        {
            clt_settings.plugin->proc_when_sess_created(s, ip, tcp);
        }
#endif
    }

    return s;
}


static int
sess_obso(tc_sess_t *s, time_t cur, time_t thrsh_time, time_t thrsh_keep_time)
{
    int threshold, diff;
    
    if (s->sm.pack_lost) {
        diff = cur - s->pack_lost_time;
        if (diff > PACK_LOSS_TIMEOUT) {
            tc_log_info(LOG_NOTICE, 0, "wait for prev packet timeout,p:%u", 
                        ntohs(s->src_port));
            tc_stat.obs_cnt++;
            return OBSOLETE;
        }
    }
    if (s->rep_rcv_con_time < thrsh_time) {
        if (s->slide_win_packs->size > 0) {
            tc_stat.obs_cnt++;
            return OBSOLETE;
        }  else {
            if (s->sm.state >= SND_REQ) {
                if (s->rep_rcv_con_time < thrsh_keep_time) {
                    tc_stat.obs_cnt++;
                    tc_log_debug1(LOG_DEBUG, 0, "keepalive timeout ,p:%u", 
                            ntohs(s->src_port));
                    return OBSOLETE;
                } else {
                    tc_log_debug1(LOG_DEBUG, 0, "session keepalive,p:%u",
                            ntohs(s->src_port));
                    return NOT_YET_OBSOLETE;
                }
            } else {
                tc_stat.obs_cnt++;
                tc_log_debug1(LOG_INFO, 0, "wait timeout,p:%u", 
                        ntohs(s->src_port));
                return OBSOLETE;
            }
        }
    }

    threshold = 256;
    diff = cur - s->rep_rcv_con_time;
    if (diff < 6) {
        threshold = threshold << 1;
    }

    diff = cur - s->req_snd_con_time;
    /* check if the session is idle for 30 sec */
    if (diff < 30) {
        threshold = threshold << 2;
        if (diff <= 3) {
            /* if it is idle for less than or equal to 3 seconds */
            threshold = threshold << 4;
        }
        if (s->sm.window_full) {
            /* if slide window is full */
            threshold = threshold << 2;
        }
    }

    return overwhelm(s, "slide win", threshold, s->slide_win_packs->size);
}


static inline int 
overwhelm(tc_sess_t *s, const char *m, int max_hold_packs, int size)
{
    if (size < max_hold_packs && size < MAX_SLIDE_WIN_THRESH) {
        return NOT_YET_OBSOLETE;
    } else {
        tc_stat.obs_cnt++;
        tc_log_info(LOG_WARN, 0, "%s:too many packs:%u,p:%u", m, 
                size, ntohs(s->src_port));
        return OBSOLETE;
    }
}


static void
sess_timeout(tc_event_timer_t *ev)
{
    int        result;
    time_t     now, thrsh_time, thrsh_keep_time;
    tc_sess_t *s;

    s = ev->data;
    if (s != NULL) {
        if (s->sm.sess_over && !s->sm.timeout) {
            sess_post_disp(s, false);
            tc_log_debug1(LOG_INFO, 0, "enter timeout:%u", ntohs(s->src_port));
            return;
        }
        if (s->sm.timeout) {
            tc_log_debug1(LOG_INFO, 0, "last disp sess:%u", ntohs(s->src_port));
            sess_post_disp(s, true);
            return;
        }

        tc_log_debug2(LOG_INFO, 0, "sess key:%llu, check timeout:%u", s->hash_key, 
                ntohs(s->src_port));
        now = tc_time();
        thrsh_time = now - clt_settings.sess_timeout;
        thrsh_keep_time = now - clt_settings.sess_keepalive_timeout;

        result = NOT_YET_OBSOLETE;
        if (s->sm.state >= ESTABLISHED) {
            result = sess_obso(s, now, thrsh_time, thrsh_keep_time);
        } else {
            result = OBSOLETE;
            s->rtt = 1;
            tc_log_debug2(LOG_INFO, 0, "est timeout, state:%u, p:%u", 
                    s->sm.state, ntohs(s->src_port));
        }

        if (result != OBSOLETE) {
            tc_event_update_timer(ev, CHECK_SESS_TIMEOUT);
        } else {
            sess_post_disp(s, false);
        }

    } else {
        tc_log_info(LOG_ERR, 0, "sesson already deleted" );
    }
}


static void
retrans_ip_pack(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp)
{
    int       ret;
    uint16_t  size_ip, tot_len;

    size_ip    = ip->ihl << 2;

    if (s->sm.timestamp) {
        update_timestamp(s, tcp);
    }

    if (tcp->ack) {
        tcp->ack_seq = s->target_ack_seq;
    }

    /* set the destination ip and port */
    ip->daddr = s->dst_addr;
    tcp->dest = s->dst_port;

    tot_len  = ntohs(ip->tot_len);

    /* It should be set to zero for tcp checksum */
    tcp->check = 0;
    tcp->check = tcpcsum((unsigned char *) ip,
            (unsigned short *) tcp, (int) (tot_len - size_ip));

#if (TC_PCAP_SND)
    ip->check = 0;
    ip->check = csum((unsigned short *) ip,size_ip);
#endif

    tc_log_debug_trace(LOG_INFO, 0, TC_TO_BAK, ip, tcp);
#if (!TC_PCAP_SND)
    ret = tc_raw_socket_snd(tc_raw_socket_out, ip, tot_len, ip->daddr);
#else
    fill_frame((struct ethernet_hdr *) s->frame, s->src_mac, s->dst_mac);
    ret = tc_pcap_snd(s->frame, tot_len + ETHERNET_HDR_LEN);
    s->frame = NULL;
#endif

    if (ret == TC_ERR) {
        tc_log_trace(LOG_WARN, 0, TC_TO_BAK, ip, tcp);
        tc_log_info(LOG_ERR, 0, "send to back error,tot_len is:%d", tot_len);
        tc_over = SIGRTMAX;
#if (!TC_PCAP_SND)
        tc_raw_socket_out = TC_INVALID_SOCK;
#endif
    }
}


static void
send_pack(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp, bool client)
{
    int        ret;
    uint16_t   size_ip, tot_len;

    if (client) {
        s->req_ack_snd_seq = ntohl(tcp->ack_seq);
        s->sm.req_ack_snd = 1;
    }

    s->target_nxt_seq  = ntohl(tcp->seq);

    if (s->cur_pack.cont_len > 0) {

        s->sm.pack_lost = 0;
        s->sm.renew_hop = 0;
        s->sm.rcv_rep_af_hop = 0;
        if (s->sm.record_req_hop_seq) {
            if (!before(s->cur_pack.seq, s->req_hop_seq)) {
                s->sm.record_req_hop_seq = 0;
                s->sm.recheck_hop = 1;
            }
        }
#if (TC_PLUGIN)
        if (clt_settings.plugin && clt_settings.plugin->check_pack_for_renew) {
            clt_settings.plugin->check_pack_for_renew(s, ip, tcp);
        }
#endif
        s->sm.state = SND_REQ;
        s->req_snd_con_time = tc_time();
        s->req_con_snd_seq  = ntohl(tcp->seq);
        s->target_nxt_seq = s->target_nxt_seq + s->cur_pack.cont_len;
        s->req_exp_seq = s->target_nxt_seq;
        tc_stat.con_packs_sent_cnt++;

        if (s->sm.set_rto) {
            s->sm.snd_after_set_rto = 1;
        } else {
            utimer_disp(s, DEFAULT_RTO, TYPE_RTO);
            s->sm.set_rto = 1;
            s->sm.snd_after_set_rto = 0;
        }
    } 

    if (s->sm.timestamp) {
        update_timestamp(s, tcp);
    }

    /* set the destination ip and port */
    ip->daddr = s->dst_addr;
    tcp->dest = s->dst_port;

    if (tcp->syn || tcp->fin) {

        if (tcp->syn) {
            tc_stat.conn_try_cnt++;
            s->sm.req_ack_snd = 0;
            s->sm.state = SYN_SENT;
            s->req_syn_seq = ntohl(tcp->seq);
        } else {
            s->sm.state |= CLIENT_FIN;
            s->sm.src_closed = 1;
            tc_stat.fin_sent_cnt++;
        }
        s->target_nxt_seq = s->target_nxt_seq + 1;
        s->req_exp_seq = s->target_nxt_seq;
    } else if (tcp->rst) {
        tc_stat.rst_sent_cnt++;
    }

    if (tcp->ack) {
        tcp->ack_seq = s->target_ack_seq;
    }

    size_ip = ip->ihl << 2;
    tot_len = ntohs(ip->tot_len);

    /* It should be set to zero for tcp checksum */
    tcp->check = 0;
    tcp->check = tcpcsum((unsigned char *) ip,
            (unsigned short *) tcp, (int) (tot_len - size_ip));

#if (TC_PCAP_SND)
    ip->check = 0;
    ip->check = csum((unsigned short *) ip,size_ip);
#endif

    tc_log_debug_trace(LOG_DEBUG, 0, TC_TO_BAK, ip, tcp);
    tc_stat.packs_sent_cnt++;
    s->req_ip_id = ntohs(ip->id);

#if (!TC_PCAP_SND)
    ret = tc_raw_socket_snd(tc_raw_socket_out, ip, tot_len, ip->daddr);
#else
    fill_frame((struct ethernet_hdr *) s->frame, s->src_mac, s->dst_mac);
    ret = tc_pcap_snd(s->frame, tot_len + ETHERNET_HDR_LEN);
    s->frame = NULL;
#endif

    if (ret == TC_ERR) {
        tc_log_trace(LOG_WARN, 0, TC_TO_BAK, ip, tcp);
        tc_log_info(LOG_ERR, 0, "send to back error,tot_len is:%u", tot_len);
        tc_over = SIGRTMAX;
#if (!TC_PCAP_SND)
        tc_raw_socket_out = TC_INVALID_SOCK;
#endif
    }
}


static void 
update_timestamp(tc_sess_t *s, tc_tcph_t *tcp)
{
    uint32_t       ts;
    unsigned int   opt, opt_len;
    unsigned char *p, *end;

    p = ((unsigned char *) tcp) + TCPH_MIN_LEN;
    end =  ((unsigned char *) tcp) + (tcp->doff << 2);  
    while (p < end) {
        opt = p[0];
        switch (opt) {
            case TCPOPT_TIMESTAMP:
                if ((p + 1) >= end) {
                    return;
                }
                opt_len = p[1];
                if ((p + opt_len) <= end) {
                    ts = htonl(s->ts_ec_r);
                    tc_log_debug2(LOG_DEBUG, 0, "set ts reply:%u,p:%u", 
                            s->ts_ec_r, ntohs(s->src_port));
                    bcopy((void *) &ts, (void *) (p + 6), sizeof(ts));
                    ts = EXTRACT_32BITS(p + 2);
                    if (ts < s->ts_value) {
                        tc_log_debug1(LOG_DEBUG, 0, "ts < history,p:%u",
                                ntohs(s->src_port));
                        ts = htonl(s->ts_value);
                        bcopy((void *) &ts, (void *) (p + 2), sizeof(ts));
                    } else {
                        s->ts_value = ts;
                    }
                }
                return;
            case TCPOPT_NOP:
                p = p + 1; 
                break;
            case TCPOPT_EOL:
                return;
            default:
                if ((p + 1) >= end) {
                    return;
                }
                opt_len = p[1];
                if (opt_len < 2) {
                    tc_log_info(LOG_WARN, 0, "opt len:%d", opt_len);
                    return;
                }
                p += opt_len;
                break;
        }    
    }
}


static inline void 
fill_timestamp(tc_sess_t *s, tc_tcph_t *tcp)
{
    uint32_t       timestamp;
    unsigned char *opt, *p; 

    p   = (unsigned char *) tcp;
    opt = p + sizeof(tc_tcph_t);
    opt[0] = 1;
    opt[1] = 1;
    opt[2] = 8;
    opt[3] = 10;
    timestamp = htonl(s->ts_value);
    bcopy((void *) &timestamp, (void *) (opt + 4), sizeof(timestamp));
    timestamp = htonl(s->ts_ec_r);
    bcopy((void *) &timestamp, (void *) (opt + 8), sizeof(timestamp));
    tc_log_debug3(LOG_DEBUG, 0, "fill ts:%u,%u,p:%u", 
            s->ts_value, s->ts_ec_r, ntohs(s->src_port));
}


static void 
send_faked_ack(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp, bool active)
{
    tc_iph_t       *f_ip;
    tc_tcph_t      *f_tcp;
    unsigned char  *p, frame[FFRAME_LEN];

    tc_memzero(frame, FFRAME_LEN);
    p = frame + ETHERNET_HDR_LEN;
    f_ip  = (tc_iph_t *) p;
    f_tcp = (tc_tcph_t *) (p + IPH_MIN_LEN);

    fill_pro_common_header(f_ip, f_tcp);

    if (!s->sm.timestamp) {
        f_ip->tot_len  = htons(FMIN_IP_LEN);
        f_tcp->doff    = TCPH_DOFF_MIN_VALUE;
    } else {
        f_ip->tot_len  = htons(FIP_TS_LEN);
        f_tcp->doff    = TCPH_DOFF_TS_VALUE;
        fill_timestamp(s, f_tcp);
    }

    f_ip->id       = htons(++s->req_ip_id);
    f_ip->saddr    = ip->daddr;
    f_tcp->source  = tcp->dest;
    f_tcp->ack     = 1;
    if (active) {
        f_tcp->seq = htonl(s->target_nxt_seq);
    } else {
        f_tcp->seq = tcp->ack_seq;
    }

    s->frame = frame;
    s->cur_pack.cont_len = 0;
    send_pack(s, f_ip, f_tcp,  false);
}


static void 
send_faked_rst(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp)
{
    tc_iph_t      *f_ip;
    tc_tcph_t     *f_tcp;
    unsigned char *p, frame[FFRAME_LEN];

    tc_log_debug1(LOG_DEBUG, 0, "send faked rst:%u", ntohs(s->src_port));

    tc_memzero(frame, FFRAME_LEN);
    p = frame + ETHERNET_HDR_LEN;
    f_ip  = (tc_iph_t *) p;
    f_tcp = (tc_tcph_t *) (p + IPH_MIN_LEN);
    fill_pro_common_header(f_ip, f_tcp);

    f_ip->tot_len  = htons(FMIN_IP_LEN);
    f_ip->id       = htons(++s->req_ip_id);
    f_ip->saddr    = ip->daddr;
    f_tcp->doff    = TCPH_DOFF_MIN_VALUE; 
    f_tcp->source  = tcp->dest;
    f_tcp->rst     = 1;
    f_tcp->ack     = 1;

    if (s->cur_pack.cont_len == 0) {   
        s->target_ack_seq = tcp->seq;
    } else {
        s->target_ack_seq = htonl(ntohl(tcp->seq) + s->cur_pack.cont_len);
    }

    f_tcp->seq = tcp->ack_seq;

    s->frame = frame;
    s->cur_pack.cont_len  = 0;
    send_pack(s, f_ip, f_tcp, false);
}


#if (!TC_SINGLE)
static bool
send_router_info(tc_sess_t *s, uint16_t type)
{
    int          i, fd;
    bool         result = false;
    conns_t     *conns;
    msg_clt_t    msg;

    tc_memzero(&msg, sizeof(msg_clt_t));
    msg.clt_ip = s->src_addr;
    msg.clt_port = s->src_port;
    msg.type = htons(type);
    msg.target_ip = s->dst_addr;
    msg.target_port = s->dst_port;

    for (i = 0; i < clt_settings.real_servers.num; i++) {
        conns = &(clt_settings.real_servers.conns[i]);
        if (conns->active) {
            fd = conns->fds[conns->index];
            conns->index = (conns->index + 1) % conns->num;
            if (fd > 0) {
                if (tc_socket_snd(fd, (char *) &msg, MSG_CLT_SIZE) != TC_ERR) {
                    result = true;
                } else {
                    tc_log_info(LOG_ERR, 0, "fd:%d, msg send error", fd);
                    if (conns->active != 0) {
                        conns->active = 0;
                        clt_settings.real_servers.active_num--;
                    }
                }
            }
        }
    }

    return result;
}
#endif


static void
send_faked_syn(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp)
{
    u_short          mss;
    tc_iph_t        *f_ip;
    tc_tcph_t       *f_tcp;
    unsigned char   *p, frame[FFRAME_LEN];
    unsigned char   *opt;

    tc_memzero(frame, FFRAME_LEN);
    p = frame + ETHERNET_HDR_LEN;
    f_ip  = (tc_iph_t *) p;
    f_tcp = (tc_tcph_t *) (p + IPH_MIN_LEN);
    opt = p + IPH_MIN_LEN + sizeof(tc_tcph_t);

    fill_pro_common_header(f_ip, f_tcp);
    f_ip->tot_len  = htons(FSYN_IP_LEN);
    f_tcp->doff    = TCPH_DOFF_MSS_VALUE;
    mss = clt_settings.mss;
    mss = htons(mss);
    /* TCPOPT_MAXSEG flag */
    opt[0] = 2;
    opt[1] = 4;
    bcopy((void *) &mss, (void *) (opt + 2), sizeof(mss));

    s->req_ip_id  = ntohs(ip->id);
    f_ip->id      = htons(s->req_ip_id - 2);
    f_ip->saddr   = ip->saddr;
    f_ip->daddr   = ip->daddr;
    f_tcp->source = tcp->source;
    f_tcp->dest   = tcp->dest;
    f_tcp->syn    = 1;
    f_tcp->seq    = htonl(ntohl(tcp->seq) - 1);

#if (TC_PLUGIN)
    if (clt_settings.plugin && clt_settings.plugin->prepare_renew) {
        clt_settings.plugin->prepare_renew(s, f_ip, f_tcp);
    }
#endif

    s->cur_pack.cont_len = 0;
    s->frame = frame;
    send_pack(s, f_ip, f_tcp, true);
}


static void
fake_syn(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp)
{
    tc_log_debug1(LOG_DEBUG, 0, "fake syn:%u", ntohs(s->src_port)); 
        
#if (!TC_SINGLE)
    if (!send_router_info(s, CLIENT_ADD)) {
        return;
    }
#endif

    send_faked_syn(s, ip, tcp);

    if (s->sm.recon) {
        tc_stat.recon_for_closed_cnt++;
    } else {
        tc_stat.recon_for_no_syn_cnt++;
    }

    s->rtt = s->rtt > 0 ? s->rtt:1;
    tc_log_debug2(LOG_INFO, 0, "rtt:%ld,p:%u", s->rtt, ntohs(s->src_port));
}


static bool 
retrans_pack(tc_sess_t *s, uint32_t expected_seq)
{
    bool            find_and_retransmit;
    uint16_t        size_ip, cont_len;
    uint32_t        cur_seq, next_expected_seq;
    tc_iph_t       *ip;
    tc_tcph_t      *tcp;
    link_list      *list;
    p_link_node     ln, tln;

    if (s->sm.state == SYN_SENT) {
        return true;
    }

    find_and_retransmit = false;
    list = s->slide_win_packs;
    ln = link_list_first(list); 

    while (ln) {

        s->frame  = ln->data;
        ip        = (tc_iph_t *) (s->frame + ETHERNET_HDR_LEN);
        size_ip   = ip->ihl << 2;
        tcp       = (tc_tcph_t *) ((char *) ip + size_ip);
        cur_seq   = ntohl(tcp->seq);  
        cont_len  = TCP_PAYLOAD_LENGTH(ip, tcp);

        if (cont_len > 0) {
            if (cur_seq == expected_seq) {
                find_and_retransmit = true;
            } else {
                if (before(cur_seq, s->rep_ack_seq)) {
                    next_expected_seq = cur_seq + cont_len;
                    if (before(s->rep_ack_seq, next_expected_seq)) {
                        find_and_retransmit = true;
                        tc_log_debug1(LOG_DEBUG, 0, "partly retransmit:%u",
                                ntohs(s->src_port));
                    }
                } else {
                    tc_log_debug1(LOG_NOTICE, 0, "no retrans pack:%u", 
                            ntohs(s->src_port));
                    break;
                }
            }
        }

        if (find_and_retransmit) {
            tc_log_debug2(LOG_INFO, 0, "retransmit, len:%u,p:%u", cont_len, 
                    ntohs(s->src_port));
            retrans_ip_pack(s, ip, tcp);
            s->sm.rep_dup_ack_cnt = 0;
            s->sm.already_retrans = 1;
            tc_stat.retrans_cnt++;
            break;
        } else {
            tln = ln;
            ln = link_list_get_next(list, ln);
            link_list_remove(list, tln);
            tc_pfree(s->pool, tln->data);
            tc_pfree(s->pool, tln);
        }
    }

    return find_and_retransmit;
}


static void 
retrieve_options(tc_sess_t *s, int direction, tc_tcph_t *tcp)
{
    uint32_t       ts_value;
    unsigned int   opt, opt_len;
    unsigned char *p, *end;

    p = ((unsigned char *) tcp) + TCPH_MIN_LEN;
    end =  ((unsigned char *) tcp) + (tcp->doff << 2);  
    while (p < end) {
        opt = p[0];
        switch (opt) {
            case TCPOPT_NOP:
                p = p + 1; 
                break;
            case TCPOPT_WSCALE:
                if ((p + 1) >= end) {
                    return;
                }
                opt_len = p[1];
                if ((p + opt_len) > end) {
                    return;
                }
                s->wscale = (uint16_t) p[2];
                p += opt_len;
                break;
            case TCPOPT_TIMESTAMP:
                if ((p + 1) >= end) {
                    return;
                }
                opt_len = p[1];
                if ((p + opt_len) > end) {
                    return;
                }
                if (direction == TC_CLT) {
                    ts_value = EXTRACT_32BITS(p + 2);
                } else {
                    s->ts_ec_r  = EXTRACT_32BITS(p + 2);
                    ts_value = EXTRACT_32BITS(p + 6);
                    if (tcp->syn) {
                        s->sm.timestamp = 1;
                    }
                }
                if (ts_value > s->ts_value) {
                    s->ts_value = ts_value;
                }
                p += opt_len;
                break;
            case TCPOPT_EOL:
                return;
            default:
                if ((p + 1) >= end) {
                    return;
                }
                opt_len = p[1];
                if (opt_len < 2) {
                    tc_log_info(LOG_WARN, 0, "opt len:%d", opt_len);
                    return;
                }
                p += opt_len;
                break;
        }    
    }
}


static void 
send_faked_third_handshake(tc_sess_t *s, tc_tcph_t *tcp)
{
    tc_iph_t       *f_ip;
    tc_tcph_t      *f_tcp;
    unsigned char  *p, frame[FFRAME_LEN];
 
    tc_memzero(frame, FFRAME_LEN);
    p     = frame + ETHERNET_HDR_LEN;
    f_ip  = (tc_iph_t *) p;
    f_tcp = (tc_tcph_t *) (p + IPH_MIN_LEN);
    fill_pro_common_header(f_ip, f_tcp);

    if (!s->sm.timestamp) {
        f_ip->tot_len  = htons(FMIN_IP_LEN);
        f_tcp->doff    = TCPH_DOFF_MIN_VALUE;
    } else {
        f_ip->tot_len  = htons(FIP_TS_LEN);
        f_tcp->doff    = TCPH_DOFF_TS_VALUE;
        fill_timestamp(s, f_tcp);
    }

    f_ip->id       = htons(++s->req_ip_id);
    f_ip->saddr    = s->src_addr;
    f_ip->daddr    = s->online_addr; 
    f_tcp->source  = tcp->dest;
    f_tcp->dest    = s->online_port;
    f_tcp->ack     = 1;
    f_tcp->seq     = tcp->ack_seq;

    s->frame = frame;
    s->cur_pack.cont_len  = 0;
    send_pack(s, f_ip, f_tcp, false);
}


static void
tc_delay_ack(tc_sess_t *s)
{
    int   rtt;

    if (!s->sm.sess_over) {
        if (s->sm.rep_payload_type) {
            send_faked_ack_from_timer(s);
            if (s->sm.rep_payload_type != PAYLOAD_FULL) {
                rtt = s->rtt >> 1;
            } else {
                rtt = s->rtt;
                if (s->sm.record_mcon_seq) {
                    if (after(s->max_con_seq, s->req_exp_seq)) {
                        rtt = rtt >> 1;
                    }
                }
            }
            utimer_disp(s, rtt, TYPE_DELAY_ACK);
            s->sm.rep_payload_type = 0;
        } else {
            if (!s->sm.delay_snd) {
                tc_log_debug1(LOG_INFO, 0, "resp end:%u", ntohs(s->src_port));
                if (s->sm.candidate_rep_wait || s->sm.need_rep_greet) {
                    s->sm.candidate_rep_wait = 0;
                    s->sm.state = RCV_REP;
                    proc_clt_pack_from_buffer(s);
                }
            } else {
                tc_log_debug1(LOG_INFO, 0, "delay snd:%u", ntohs(s->src_port));
                s->sm.candidate_rep_wait = 0;
                s->sm.delay_snd = 0;
                proc_clt_pack_from_buffer(s);
            }
        }
    }
}


static void 
send_faked_ack_from_timer(tc_sess_t *s)
{
    tc_iph_t      *ip;
    tc_tcph_t     *tcp;
    unsigned char *p, frame[FFRAME_LEN];

    tc_memzero(frame, FFRAME_LEN);
    p   = frame + ETHERNET_HDR_LEN;
    ip  = (tc_iph_t *) p;
    tcp = (tc_tcph_t *) (p + IPH_MIN_LEN);

    fill_pro_common_header(ip, tcp);

    if (!s->sm.timestamp) {
        ip->tot_len  = htons(FMIN_IP_LEN);
        tcp->doff    = TCPH_DOFF_MIN_VALUE;
    } else {
        ip->tot_len  = htons(FIP_TS_LEN);
        tcp->doff    = TCPH_DOFF_TS_VALUE;
        fill_timestamp(s, tcp);
    }

    ip->id        = htons(++s->req_ip_id);
    ip->saddr     = s->src_addr;
    tcp->source   = s->src_port;
    tcp->ack      = 1;
    tcp->seq      = htonl(s->rep_ack_seq);

    s->frame = frame;
    s->cur_pack.cont_len = 0;
    send_pack(s, ip, tcp, false);
}


static inline void
shrink_rtt(tc_sess_t *s) 
{
    if (!s->sm.internal_usage) {
        s->rtt = s->rtt >> 1;
        tc_log_debug2(LOG_INFO, 0, "srtt:%ld:%u", s->rtt, ntohs(s->src_port));
        s->rtt = s->rtt ? s->rtt:1;
    }
}


static void 
tc_lantency_ctl(tc_event_timer_t *ev)
{
    tc_sess_t *s = ev->data;

    if (s != NULL) {
        if (s->sm.timer_type == TYPE_DELAY_ACK) {
            tc_delay_ack(s);
            if (s->slide_win_packs->size > SND_TOO_SLOW_THRESH) {
                if (!s->sm.internal_usage) {
                    shrink_rtt(s);
                } 
            }
        } else if (s->sm.timer_type == TYPE_RTO) {
            if (s->sm.snd_after_set_rto) {
                utimer_disp(s, DEFAULT_RTO, TYPE_RTO);
                s->sm.snd_after_set_rto = 0;
            } else {
                s->sm.set_rto = 0;
                if (before(s->rep_ack_seq, s->target_nxt_seq)) {
                    retrans_pack(s, s->rep_ack_seq);
                    tc_log_debug1(LOG_INFO, 0, "rto:%llu", ntohs(s->src_port));
                }
            }
        } else if (s->sm.timer_type == TYPE_RECONSTRUCT) {
            proc_clt_pack_from_buffer(s);
        } else if (s->sm.timer_type == TYPE_DEFAULT) {
        } else {
            tc_log_info(LOG_ERR, 0, "unknown ttype:%llu", ntohs(s->src_port));
        }
    } else {
        tc_log_info(LOG_ERR, 0, "sesson already deleted:%llu", ev);
    }
}


static void
utimer_disp(tc_sess_t *s, int lty, int type)
{
    int timeout = lty > 0 ? lty:1;

    if (s->ev) {
        tc_event_update_timer(s->ev, timeout);
        s->sm.timer_type  = type;
    } else {
#if (TC_DETECT_MEMORY)
        if (s->sm.active_timer_cnt != 0) {
            tc_log_info(LOG_WARN, 0, "abnormal add timer");
        }
        s->sm.active_timer_cnt++;
#endif
        s->ev = tc_event_add_timer(s->pool, timeout, s, tc_lantency_ctl);
        s->sm.timer_type = type;
        tc_log_debug2(LOG_INFO, 0, "nev:%llu,p:%u", s->ev, ntohs(s->src_port));
    }
}


static void
update_retrans_packs(tc_sess_t *s)
{
    uint16_t         size_ip;
    uint32_t         cur_seq;
    tc_iph_t        *ip;
    tc_tcph_t       *tcp;
    link_list       *list;
    p_link_node      ln, tln;
    unsigned char   *frame;

    list = s->slide_win_packs;
    ln = link_list_first(list); 

    while (ln) {

        frame   = ln->data;
        ip      = (tc_iph_t *) (frame + ETHERNET_HDR_LEN);
        size_ip = ip->ihl << 2;
        tcp     = (tc_tcph_t *) ((char *) ip + size_ip);
        cur_seq = ntohl(tcp->seq);  

        if (before(cur_seq, s->rep_ack_seq)) {

            if (ln == s->prev_snd_node) {
                s->prev_snd_node = NULL;
                tc_log_debug1(LOG_INFO, 0, "prev=nul:%u", ntohs(s->src_port));
            }
            tc_log_debug1(LOG_DEBUG, 0, "win forward:%u", ntohs(s->src_port));
            tln = ln;
            ln = link_list_get_next(list, ln);
            link_list_remove(list, tln);
            tc_pfree(s->pool, tln->data);
            tc_pfree(s->pool, tln);
        } else {
            break;
        }
    }
}


static void
remove_conflict_packs(tc_sess_t *s)
{
    uint16_t         size_ip;
    uint32_t         cur_seq;
    tc_iph_t        *ip;
    tc_tcph_t       *tcp;
    link_list       *list;
    p_link_node      ln;
    unsigned char   *frame;

    list = s->slide_win_packs;
    ln = link_list_tail(list); 

    while (ln) {

        frame   = ln->data;
        ip      = (tc_iph_t *) (frame + ETHERNET_HDR_LEN);
        size_ip = ip->ihl << 2;
        tcp     = (tc_tcph_t *) ((char *) ip + size_ip);
        cur_seq = ntohl(tcp->seq);  

        if (!before(cur_seq, s->req_hop_seq)) {

            if (ln == s->prev_snd_node) {
                s->prev_snd_node = NULL;
                tc_log_debug1(LOG_INFO, 0, "prev=nul:%u", ntohs(s->src_port));
            }
            tc_log_debug1(LOG_INFO, 0, "win backward:%u", ntohs(s->src_port));
            link_list_remove(list, ln);
            tc_pfree(s->pool, ln->data);
            tc_pfree(s->pool, ln);
            ln = link_list_tail(list);
        } else {
            break;
        }
    }
}


static int
check_bak_ack(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp)
{
    bool slide_win_empty;

    if (s->cur_pack.ack_seq == s->target_nxt_seq) {
        return PACK_CONTINUE;
    }

    if (before(s->cur_pack.ack_seq, s->target_nxt_seq)) {

        if (s->sm.state < SYN_CONFIRM && !tcp->syn) {
            send_faked_rst(s, ip, tcp);
            s->sm.sess_over = 1;
            return PACK_STOP;
        }

        if (s->sm.src_closed && !tcp->fin) {
            if (s->cur_pack.cont_len > 0) {
                send_faked_ack(s, ip, tcp, true);
            } else {
                send_faked_rst(s, ip, tcp);
            }
            return PACK_STOP;
        } 

        slide_win_empty = false;

        if (tcp->window > 0 && s->sm.window_full) {
            s->sm.window_full     = 0;
            s->sm.rep_dup_ack_cnt = 0;
            slide_win_empty    = true;
        } else if (tcp->window == 0) {
            tc_log_info(LOG_NOTICE, 0, "win zero:%u", ntohs(s->src_port));
            s->sm.window_full  = 1;
            if (s->cur_pack.cont_len > 0) {
                send_faked_ack(s, ip, tcp, true);
                return PACK_STOP;
            }
        }

        if (s->cur_pack.ack_seq != s->rep_ack_seq) {
            s->sm.rep_dup_ack_cnt = 0;
            return PACK_CONTINUE;
        }

        if (!tcp->fin && s->cur_pack.seq == s->rep_seq
                && s->cur_pack.ack_seq == s->rep_ack_seq)
        {
            s->sm.rep_dup_ack_cnt++;
            if (s->sm.rep_dup_ack_cnt >= 3) {
                if (!s->sm.already_retrans) {
                    retrans_pack(s, s->cur_pack.ack_seq);
                    tc_event_update_timer(s->ev, s->rtt);

                    if (slide_win_empty) {
                        proc_clt_pack_from_buffer(s);
                    }
                    return PACK_STOP;
                }
            }
        }
    } else {
        s->target_nxt_seq = s->cur_pack.ack_seq;
    }

    return PACK_CONTINUE;
}


static inline void 
check_pack_full(tc_sess_t *s, tc_iph_t *ip)
{
    int      index, offset, bit_value, value;
    uint16_t tot_len = ntohs(ip->tot_len);

    if (tot_len < MAX_CHECKED_MTU) {
        index = tot_len >> 3;
        offset = tot_len - (index << 3);
        bit_value = 1 << offset;
        value = clt_settings.candidate_mtu[index];

        if (value & bit_value) {
            s->sm.rep_payload_type = PAYLOAD_FULL;
        } else {
            s->sm.rep_payload_type = PAYLOAD_NOT_FULL;
        }
    } else {
        s->sm.rep_payload_type = PAYLOAD_FULL;
    }
}


static inline int
check_resp_greet(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp)
{
    if (s->sm.state < SND_REQ && !s->sm.rcv_rep_greet) {
        s->sm.rcv_rep_greet = 1;
        s->sm.need_rep_greet = 0;
        s->sm.candidate_rep_wait = 0;
#if (TC_PLUGIN)
        if (clt_settings.plugin && clt_settings.plugin->proc_greet) {
            clt_settings.plugin->proc_greet(s, ip, tcp);
        }
#endif
        return PACK_STOP;
    }

#if (TC_PLUGIN)
    if (s->sm.state >= SND_REQ) {
        if (clt_settings.plugin && clt_settings.plugin->post_auth) {
            clt_settings.plugin->post_auth(s, ip, tcp);
        }
    }
#endif
    return PACK_CONTINUE;
}


static void
proc_bak_pack(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp)
{
    uint32_t cur_target_ack_seq, last_target_ack_seq;

    tc_stat.resp_cnt++;
    tc_log_debug_trace(LOG_DEBUG, 0, TC_BAK, ip, tcp);

    if (!tcp->rst) {

        s->peer_window       = ntohs(tcp->window);
        s->cur_pack.seq      = ntohl(tcp->seq);
        s->cur_pack.ack_seq  = ntohl(tcp->ack_seq);
        s->cur_pack.cont_len = TCP_PAYLOAD_LENGTH(ip, tcp);
        if (s->wscale) {
            s->peer_window = s->peer_window << (s->wscale);
        }

        if (s->sm.timestamp) {
            retrieve_options(s, TC_BAK, tcp);
        }

        if (s->cur_pack.cont_len > 0) {
            if (s->sm.already_retrans) {
                tc_stat.retrans_succ_cnt++;
                s->sm.already_retrans = 0;
            }
            if (s->cur_pack.seq != s->rep_seq || 
                    s->cur_pack.ack_seq != s->rep_ack_seq) 
            {
                s->sm.rep_dup_ack_cnt = 0;
            }
            tc_stat.resp_cont_cnt++;
            s->rep_rcv_con_time = tc_time();
            cur_target_ack_seq = s->cur_pack.seq + s->cur_pack.cont_len;
            last_target_ack_seq = ntohl(s->target_ack_seq);

            if (after(cur_target_ack_seq, last_target_ack_seq) || tcp->fin) {
                s->target_ack_seq = htonl(cur_target_ack_seq);
            } else {
                tc_log_debug1(LOG_NOTICE, 0, "retrans from server:%u", 
                        ntohs(s->src_port));
                shrink_rtt(s);
            }
        } else {
            s->target_ack_seq = tcp->seq;
        }

        if (check_bak_ack(s, ip, tcp) != PACK_STOP) {
            s->rep_seq = s->cur_pack.seq;
            if (s->rep_ack_seq != s->cur_pack.ack_seq) {
                s->rep_ack_seq = s->cur_pack.ack_seq;
                if (s->sm.state >= ESTABLISHED) {
                    update_retrans_packs(s);
                }
            }
        } else {
            s->rep_ack_seq = s->cur_pack.ack_seq;
            s->rep_seq     = s->cur_pack.seq;
            return;
        }

        if (!tcp->syn && !tcp->fin) {
#if (TC_DEBUG)
            if (!s->sm.src_closed) {
                s->rep_ack_seq_bf_fin = s->cur_pack.ack_seq;
            }
#endif
            if (s->cur_pack.cont_len > 0) {

                if (s->sm.record_req_hop_seq) {
                    if (before(s->rep_ack_seq, s->req_hop_seq)) {
                        tc_log_debug1(LOG_NOTICE, 0, "recv rep after hop:%u",
                                ntohs(s->src_port));
                        s->sm.rcv_rep_af_hop = 1;
                    }
                }

                if (check_resp_greet(s, ip, tcp) == PACK_STOP) {
                    return;
                }

                check_pack_full(s, ip);

                if (s->sm.internal_usage && before(s->req_con_snd_seq,
                            s->max_con_seq)) 
                {
                    s->sm.candidate_rep_wait = 0;
                    proc_clt_pack_from_buffer(s);
                    s->sm.rep_payload_type = 0;
                } else {
                    utimer_disp(s, s->rtt, TYPE_DELAY_ACK);
                    s->sm.candidate_rep_wait = 1;
                }

            } else {
                s->sm.rep_payload_type = 0;
                if (s->sm.src_closed && s->sm.dst_closed) {
                    s->sm.sess_over = 1;
                }
            }
        } else {
            s->target_ack_seq = htonl(ntohl(s->target_ack_seq) + 1);
            if (tcp->syn) {
                proc_bak_syn(s, tcp);
            } else if (tcp->fin) {
                tc_stat.resp_fin_cnt++;
                proc_bak_fin(s, ip, tcp);
            }
        }
    } else {
        tc_stat.resp_rst_cnt++;
        tc_log_debug1(LOG_DEBUG, 0, "reset:%u", ntohs(s->src_port));
        if (s->sm.record_mcon_seq) {
            if (after(s->max_con_seq, s->req_con_snd_seq)) {
                reconstruct_sess(s);
                return;
            } 
        }
        s->sm.sess_over = 1;
    }
}


static void
proc_bak_syn(tc_sess_t *s, tc_tcph_t *tcp)
{
    bool     pack_sent;
    uint16_t size_tcp;

    if (s->sm.state < SYN_CONFIRM) {
        tc_stat.conn_cnt++;
        s->sm.state = SYN_CONFIRM;
    }

    size_tcp = tcp->doff << 2;
    tc_log_debug2(LOG_DEBUG, 0, "recv syn from back, size tcp:%u, p:%u",
            size_tcp, ntohs(s->src_port));

    if (size_tcp > TCPH_MIN_LEN) {
        retrieve_options(s, TC_BAK, tcp);
        if (s->wscale > 0) {
            tc_log_debug2(LOG_DEBUG, 0, "wscale:%u, p:%u", 
                    s->wscale, ntohs(s->src_port));
        }
    }

    if (!s->sm.fake_syn) {
        pack_sent = proc_clt_pack_from_buffer(s);
        if (pack_sent) {
            s->sm.state |= ESTABLISHED;
        }
    } else {
        send_faked_third_handshake(s, tcp);
        proc_clt_pack_from_buffer(s);
        s->sm.state |= ESTABLISHED;
    }
}


static void
proc_bak_fin(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp)
{
    uint16_t cont_len;

    tc_log_debug1(LOG_DEBUG, 0, "recv fin from back:%u", ntohs(s->src_port));

    s->sm.dst_closed = 1;
    s->sm.candidate_rep_wait = 0;
    s->sm.state |= SERVER_FIN;

    if (s->sm.src_closed) {
        send_faked_ack(s, ip, tcp, true);
        s->sm.sess_over = 1;
    } else {
        cont_len = s->cur_pack.cont_len;
        send_faked_ack(s, ip, tcp, false);
        tcp->seq = htonl(s->cur_pack.seq + 1);
        if (s->sm.record_mcon_seq) {
            if (after(s->max_con_seq, s->req_con_snd_seq)) {
                reconstruct_sess(s);
                return;
            } 
        }

        proc_clt_pack_from_buffer(s);

        if (!s->sm.sess_over) {
            s->cur_pack.cont_len = cont_len;
            send_faked_rst(s, ip, tcp);
            s->sm.sess_over = 1;
        }
    }
}


bool
tc_proc_outgress(unsigned char *pack)
{
    uint16_t     size_ip;
    uint64_t     key;
    tc_iph_t    *ip;
    tc_tcph_t   *tcp;
    tc_sess_t   *s;

    ip       = (tc_iph_t *) pack;
    size_ip  = ip->ihl << 2;
    tcp      = (tc_tcph_t *) ((char *) ip + size_ip);

    key = get_key(ip->daddr, tcp->dest);
    s = hash_find(sess_table, key);

    if (s) {

        if (s->sm.state >= SYN_CONFIRM || tcp->syn) {
            if (!s->sm.timeout) {
                s->cur_pack.cont_len = 0;
                proc_bak_pack(s, ip, tcp);
                if (s->sm.sess_over) {
                    sess_post_disp(s, false);
                }
            } else {
                if (!s->sm.last_ack) {
                    s->sm.last_ack = 1;
                    tc_log_debug1(LOG_INFO, 0, "last ack:%u", ntohs(s->src_port));
                } else {
                    if (!tcp->rst) {
                        send_faked_rst(s, ip, tcp);
                    }
                }
            }
        } else {
            tc_log_debug1(LOG_INFO, 0, "prev pack:%u", ntohs(s->src_port));
            if (tcp->rst) {
                sess_post_disp(s, true);
            } else {
                send_faked_rst(s, ip, tcp);
                if (!s->sm.timeout) {
                    s->sm.state = CLOSED;
                    utimer_disp(s, s->rtt, TYPE_RECONSTRUCT);
                    s->prev_snd_node = NULL;
                } else {
                    tc_log_debug1(LOG_INFO, 0, "kill:%u", ntohs(s->src_port));
                    sess_post_disp(s, true);
                }
            }
        }
    } else {
        tc_log_debug_trace(LOG_DEBUG, 0, TC_BAK, ip, tcp);
        tc_log_debug0(LOG_DEBUG, 0, "no active session for me");
    }

    return true;
}


static int
proc_clt_rst(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp)  
{
    if (s->sm.candidate_rep_wait) {
        return PACK_STOP;
    }
    tc_log_debug1(LOG_DEBUG, 0, "reset from clt:%u", ntohs(s->src_port));

    if (before(s->cur_pack.seq, s->target_nxt_seq)) {
        tcp->seq = htonl(s->target_nxt_seq);
    }

    send_pack(s, ip, tcp, true);

    s->sm.sess_over = 1;

    return PACK_SLIDE;
}


static void 
calculate_rtt(tc_sess_t *s) 
{
    if (s->sm.rtt_cal == RTT_INIT) {
        if (s->sm.state < SYN_SENT) {
            s->sm.rtt_cal = RTT_FIRST_RECORED;
#if (TC_OFFLINE)
            s->rtt = clt_settings.pcap_time;
#else
            s->rtt = tc_milliscond_time();
#endif
            tc_log_debug2(LOG_DEBUG, 0, "record rtt base:%ld,p:%u",
                    s->rtt, ntohs(s->src_port));
        }
    } else if (s->sm.rtt_cal == RTT_FIRST_RECORED) {
        s->sm.rtt_cal = RTT_CAL;

        if (clt_settings.default_rtt > 0) {
            s->rtt = clt_settings.default_rtt;
        } else {
#if (TC_OFFLINE)
            s->rtt = (clt_settings.pcap_time - s->rtt);
            if (clt_settings.accelerated_times > 1) {
                s->rtt = s->rtt / clt_settings.accelerated_times;
            }
#else
            s->rtt = tc_milliscond_time() - s->rtt;
#endif
        }

        tc_log_debug2(LOG_INFO, 0, "rtt:%ld,p:%u", s->rtt, ntohs(s->src_port));

        if (s->rtt <= 1) {
            s->sm.internal_usage = 1;
            tc_log_debug1(LOG_INFO, 0, "internal:%u", ntohs(s->src_port));
        }
    }
}


static void
proc_clt_syn(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp)  
{
    if (clt_settings.default_rtt == 0) {
        s->sm.rtt_cal = RTT_INIT;
        calculate_rtt(s);
    }

    tc_log_debug1(LOG_DEBUG, 0, "syn port:%u", ntohs(s->src_port));

    send_pack(s, ip, tcp, true);
}


static int
proc_clt_fin(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp)  
{
    tc_log_debug1(LOG_DEBUG, 0, "recv fin from clt:%u", ntohs(s->src_port));

    if (!s->sm.need_rep_greet) {
        if (s->cur_pack.cont_len == 0) {
            if (s->sm.candidate_rep_wait) {
                if (s->cur_pack.ack_seq == s->req_ack_snd_seq) {
                    s->sm.delay_snd = 1;
                    utimer_disp(s, s->rtt, TYPE_DELAY_ACK); 
                    return PACK_STOP;
                }
                if (s->rep_ack_seq == s->cur_pack.seq) {
                    return PACK_STOP;
                }
            } else {
                if (s->rep_ack_seq == s->cur_pack.seq) {
                    send_pack(s, ip, tcp, true);
                    if (s->sm.dst_closed) {
                        s->sm.sess_over = 1;
                    }
                    return PACK_SLIDE;
                }
            }
            return PACK_STOP;
        } else {
            tc_log_debug1(LOG_INFO, 0, "fin has cont:%u", ntohs(s->src_port));
            return PACK_CONTINUE;
        }
    } else {
        return PACK_STOP;
    }
}


static inline int 
continue_diag(tc_sess_t *s)
{
    if (s->req_con_ack_seq != s->req_con_cur_ack_seq) {
        s->cur_pack.new_req_flag = 1;
        tc_log_debug1(LOG_DEBUG, 0, "a new req,p:%u", ntohs(s->src_port));

        if (after(s->cur_pack.seq, s->req_con_snd_seq)) {
            tc_log_debug1(LOG_DEBUG, 0, "stop req,p:%u", ntohs(s->src_port));
            return PACK_STOP;
        }
    }

    return PACK_CONTINUE;
}


static bool
is_wait_greet(tc_sess_t *s)
{
    if (s->sm.need_rep_greet) {
        return true;
    }
    
    if (s->sm.req_ack_snd) {

        if (after(s->cur_pack.ack_seq, s->req_ack_snd_seq) && 
                s->cur_pack.seq == s->req_exp_seq) 
        {
            s->sm.need_rep_greet = 1;
            if (!s->sm.rcv_rep_greet) {
                tc_log_debug3(LOG_INFO, 0, "ack:%u, last ack:%u, wait:%u", 
                        s->cur_pack.ack_seq, s->req_ack_snd_seq, 
                        ntohs(s->src_port));
                return true;
            } else {
                s->sm.need_rep_greet = 0;
                return false;
            }
        }
    }

    return false;
}


static bool
prune_pack(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp, uint32_t diff)
{
    uint16_t        size_tcp, tot_len;
    unsigned char  *payload;

    tot_len  = ntohs(ip->tot_len);
    size_tcp = tcp->doff << 2;

    if (s->cur_pack.cont_len > diff) {
        ip->tot_len = htons(tot_len - diff);
        tcp->seq    = htonl(s->req_exp_seq);
        payload     = (unsigned char *) ((char *) tcp + size_tcp);
        memmove(payload, payload + diff, s->cur_pack.cont_len - diff);
        s->cur_pack.cont_len -= diff;
        tc_log_debug1(LOG_DEBUG, 0, "prune pack:%u", ntohs(s->src_port));
        return true;
    } else {
        return false;
    }
}


static int
check_wait_prev_pack(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp)
{
    int       diff;
    uint32_t  retransmit_seq;

    if (s->cur_pack.seq == s->req_exp_seq) {
        return PACK_CONTINUE;
    } else if (after(s->cur_pack.seq, s->req_exp_seq)) {
        tc_log_debug3(LOG_DEBUG, 0, "lost pack, seq:%u, expect:%u,p:%u",
                s->cur_pack.seq, s->req_exp_seq, ntohs(s->src_port));

        diff = s->cur_pack.seq - s->req_exp_seq;
        if (diff > MAX_SEQ_HOP) {
            s->sm.conflict = 1;
            s->req_hop_seq = s->cur_pack.seq;
        } else if (diff > MIN_SEQ_HOP) {
            if (s->sm.record_req_hop_seq) {
                if (s->req_hop_seq == s->cur_pack.seq) {
                    if (!s->sm.renew_hop && s->sm.rcv_rep_af_hop) {
                        s->sm.conflict = 1;
                    }
                }
            }

            if (s->sm.recheck_hop) {
                if (s->req_hop_seq != s->cur_pack.seq) {
                    s->sm.renew_hop = 1;
                }
                s->sm.recheck_hop = 0;
            }
            s->sm.record_req_hop_seq = 1;
            s->req_hop_seq = s->cur_pack.seq;
        }

        s->sm.pack_lost = 1;
        s->pack_lost_time = tc_time();
        return PACK_STOP;
    } else {
        retransmit_seq = s->req_exp_seq - s->cur_pack.cont_len;
        if (!after(s->cur_pack.seq, retransmit_seq)) {
            tc_log_debug2(LOG_DEBUG, 0, "exp seq:%u, clt retransmit:%u",
                    s->req_exp_seq, ntohs(s->src_port));
            if (tcp->fin) {
                s->sm.delay_snd = 1;
            }
            tc_stat.clt_con_retrans_cnt++;
            return PACK_SLIDE;
        } else {
            diff = s->req_exp_seq - s->cur_pack.seq;
            if (prune_pack(s, ip, tcp, diff)) {
                return PACK_CONTINUE;
            }
        }
        return PACK_STOP;
    }
}


static int
is_continuous_pack(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp)
{
    if (s->sm.candidate_rep_wait) {
        if (after(s->cur_pack.seq, s->req_con_snd_seq)) {
            send_pack(s, ip, tcp, true);
            tc_log_debug1(LOG_DEBUG, 0, "continuous:%u", ntohs(s->src_port));
            return PACK_NEXT;
        }
    }

    return PACK_CONTINUE;
}


static void
proc_clt_after_filter(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp)
{
    if (!s->sm.candidate_rep_wait) {
        if (s->sm.rtt_cal == RTT_FIRST_RECORED) {
            calculate_rtt(s);
        }

        if (s->cur_pack.cont_len > 0) {
            s->sm.candidate_rep_wait = 1;
#if (TC_PLUGIN)
            if (clt_settings.plugin && clt_settings.plugin->proc_auth) {
                clt_settings.plugin->proc_auth(s, ip, tcp);
            }
#endif
            send_pack(s, ip, tcp, true);
            return;
        } else if (s->sm.state == SYN_CONFIRM) {
            if (s->req_exp_seq == s->cur_pack.seq) {
                s->sm.state |= ESTABLISHED;
                send_pack(s, ip, tcp, true);
                return;
            }
        }
    }

    tc_log_debug1(LOG_DEBUG, 0, "drop pack:%u", ntohs(s->src_port));
}


/*
 * processing client packets
 * 
 */
static int
proc_clt_pack(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp)
{
    int       status;
    uint16_t  cont_len;
    uint32_t  srv_sk_buf_s;

    tc_log_debug1(LOG_DEBUG, 0, "proc clt pack:%u", ntohs(s->src_port));

    if (s->sm.state == SYN_SENT || s->sm.window_full) {
        return PACK_STOP;
    }

#if (TC_PLUGIN)
    if (clt_settings.plugin && clt_settings.plugin->adjust_clt_seq) {
        clt_settings.plugin->adjust_clt_seq(s, ip, tcp);
    }
#endif

    s->cur_pack.seq = ntohl(tcp->seq);
    s->cur_pack.ack_seq = ntohl(tcp->ack_seq);

    cont_len = TCP_PAYLOAD_LENGTH(ip, tcp);
    s->cur_pack.cont_len = cont_len;

    if (tcp->rst) {
        status = proc_clt_rst(s, ip, tcp);
        return status;
    }

    if (tcp->syn) {
        proc_clt_syn(s, ip, tcp);
        return PACK_SLIDE;
    }

    if (tcp->fin) {
        status = proc_clt_fin(s, ip, tcp);
        if (status != PACK_CONTINUE) {
            return status;
        }
    }

    if (s->sm.state < SYN_SENT) {
        s->sm.fake_syn = 1;
        fake_syn(s, ip, tcp);
        return PACK_STOP;
    }

    if (s->sm.state < SND_REQ && is_wait_greet(s)) {
        return PACK_STOP;
    }

    if (cont_len > 0) {
        s->req_con_ack_seq = s->req_con_cur_ack_seq;
        s->req_con_cur_ack_seq  = ntohl(tcp->ack_seq);
        tc_log_debug2(LOG_INFO, 0, "con:%d,p:%u", cont_len, ntohs(s->src_port));

        s->sm.state |= ESTABLISHED;

        srv_sk_buf_s = s->target_nxt_seq - s->rep_ack_seq  + cont_len;
        if (srv_sk_buf_s > s->peer_window) {
            tc_log_debug3(LOG_DEBUG, 0, "wait,srv_sk_buf_s:%u, win:%u, p:%u",
                    srv_sk_buf_s, s->peer_window, ntohs(s->src_port));
            s->sm.delay_snd = 1;
            return PACK_STOP;
        }

        s->cur_pack.new_req_flag = 0;
        if (s->sm.candidate_rep_wait) {
            status = continue_diag(s);
            if (status != PACK_CONTINUE) {
                return status;
            }
        }

        status = check_wait_prev_pack(s, ip, tcp);
        if (status != PACK_CONTINUE) {
            return status;
        }

        if (!s->cur_pack.new_req_flag) {
            status = is_continuous_pack(s, ip, tcp);
            if (status != PACK_CONTINUE) {
                return status;
            }
        }

        tc_log_debug1(LOG_INFO, 0, "new req from clt:%u", ntohs(s->src_port));
    }

    proc_clt_after_filter(s, ip, tcp);
    return PACK_NEXT;
}


uint32_t
get_tf_ip(uint16_t key) 
{
    uint16_t cnt;

    if (clt_settings.ip_tf[key] == 0) {
        cnt = clt_settings.ip_tf_cnt;
        clt_settings.ip_tf[key] = clt_settings.clt_tf_ip[cnt];
        cnt++;
        if (cnt >= clt_settings.clt_tf_ip_num) {
            cnt = 0;
        }

        clt_settings.ip_tf_cnt = cnt;
    }
    return clt_settings.ip_tf[key];
}


bool
tc_check_ingress_pack_needed(tc_iph_t *ip)
{
    bool        is_needed = false;
    uint16_t    size_ip, size_tcp, tot_len, cont_len, hlen, 
                key, frag_off, tf_key;
    uint64_t    sess_key;
    tc_tcph_t  *tcp;
    tc_sess_t  *s;

    tc_stat.captured_cnt++;

    if (ip->protocol != IPPROTO_TCP) {
        return is_needed;
    }

    size_ip   = ip->ihl << 2;
    if (size_ip < IPH_MIN_LEN) {
        tc_log_info(LOG_INFO, 0, "Invalid IP header length: %d", size_ip);
        return is_needed;
    }

    frag_off = ntohs(ip->frag_off);
    if (frag_off != IP_DF) {
        tc_stat.frag_cnt++;
    }

    tot_len  = ntohs(ip->tot_len);
    tcp      = (tc_tcph_t *) ((char *) ip + size_ip);
    size_tcp = tcp->doff << 2;
    if (size_tcp < TCPH_MIN_LEN) {
        tc_log_info(LOG_INFO, 0, "Invalid TCP header: %d bytes,pack len:%d",
                size_tcp, tot_len);
        return is_needed;
    }

    /* filter the packets we do care about */
    if (TC_CLT == check_pack_src(&(clt_settings.transfer), ip->daddr, 
                tcp->dest, CHECK_DEST)) 
    {
        if (!clt_settings.target_localhost) {
            if (ip->saddr == LOCALHOST) {
                if (clt_settings.localhost_tf_ip != 0) {
                    ip->saddr = clt_settings.localhost_tf_ip;
                }
            }
        } else {
            if (ip->saddr != LOCALHOST) {
                tc_log_info(LOG_WARN, 0, "not localhost source ip address");
                return is_needed;
            }
        }

        if (clt_settings.clt_tf_ip_num > 0) {
            tf_key = get_ip_key(ip->saddr);
            ip->saddr = get_tf_ip(tf_key);
        }

        hlen = size_tcp + size_ip;
        if (tot_len >= hlen) {

            if (clt_settings.gradully && clt_settings.percentage < 100) {
                if (tc_stat.start_pt) {
                    clt_settings.percentage = tc_time() - tc_stat.start_pt + 1;
                    if (clt_settings.percentage > 100) {
                        clt_settings.percentage = 100;
                    }
                } else {
                    clt_settings.percentage = 1;
                }
            }

            if (clt_settings.percentage) {
                key = 0xFFFF & (tcp->source + ip->saddr);
                key = ((key & 0xFF00) >> 8) + (key & 0x00FF);
                key = key % 100;
                if (key >= clt_settings.percentage) {
                    return is_needed;
                }
            }
            if (!tcp->syn) {
                cont_len  = tot_len - hlen;
                if (cont_len > 0) {
                    tc_stat.clt_cont_cnt++;
                } else {
                    sess_key =  get_key(ip->saddr, tcp->source);
                    s = hash_find(sess_table, sess_key);
                    if (s) {
                        if (!tcp->rst && !tcp->fin) {
                            if (s->sm.state >= ESTABLISHED) {
                                return is_needed;
                            }
                        }
                    }
                }
            } else {
                tc_stat.clt_syn_cnt++;
            }
            is_needed = true;
            tc_stat.clt_packs_cnt++;
        } else {
            tc_log_info(LOG_INFO, 0, "bad tot:%d, hlen:%d", tot_len, hlen);
        }
    } 

    return is_needed;
}


void
tc_output_stat(void)
{
    double    ratio;

    if (tc_stat.start_pt != 0) {
        tc_log_info(LOG_NOTICE, 0, "active:%u,rel:%llu,obs del:%llu,tw:%llu",
                sess_table->total, tc_stat.leave_cnt, tc_stat.obs_cnt, 
                tc_stat.time_wait_cnt);
        tc_log_info(LOG_NOTICE, 0, "conns:%llu,resp:%llu,c-resp:%llu",
                tc_stat.conn_cnt, tc_stat.resp_cnt, tc_stat.resp_cont_cnt);
        tc_log_info(LOG_NOTICE, 0, "resp fin:%llu,resp rst:%llu",
                tc_stat.resp_fin_cnt, tc_stat.resp_rst_cnt);
        tc_log_info(LOG_NOTICE, 0, "send:%llu,send content:%llu",
                tc_stat.packs_sent_cnt, tc_stat.con_packs_sent_cnt);
        tc_log_info(LOG_NOTICE, 0, "send syn:%llu, fin:%llu,reset:%llu",
                tc_stat.conn_try_cnt, tc_stat.fin_sent_cnt,
                tc_stat.rst_sent_cnt);
        tc_log_info(LOG_NOTICE, 0, "reconnect:%llu,for no syn:%llu",
                tc_stat.recon_for_closed_cnt, tc_stat.recon_for_no_syn_cnt);
        tc_log_info(LOG_NOTICE, 0, "retransmit:%llu", tc_stat.retrans_cnt);
        tc_log_info(LOG_NOTICE, 0, "recv packs after retransmission:%llu", 
                tc_stat.retrans_succ_cnt);
        tc_log_info(LOG_NOTICE, 0, "syn cnt:%llu,all clt:%llu,clt cont:%llu",
                tc_stat.clt_syn_cnt, tc_stat.clt_packs_cnt, 
                tc_stat.clt_cont_cnt);
        tc_log_info(LOG_NOTICE, 0, "total cont retransmit:%llu, frag:%llu",
                tc_stat.clt_con_retrans_cnt, tc_stat.frag_cnt);
        tc_log_info(LOG_NOTICE, 0, "total captured packets:%llu",
                tc_stat.captured_cnt);

        if ((tc_time() - tc_stat.start_pt) > 3) {
            if (sess_table->total > 0) {
                ratio = 100 * tc_stat.conn_cnt / sess_table->total;
                if (ratio < 80) {
                    tc_log_info(LOG_WARN, 0, 
                            "many connections can't be established");
                }
            }
        }
    } 
}


void
tc_interval_disp(tc_event_timer_t *ev)
{
    tc_output_stat();
    tc_event_update_timer(ev, OUTPUT_INTERVAL);
}


void 
tc_save_pack(tc_sess_t *s, link_list *list, tc_iph_t *ip, tc_tcph_t *tcp)
{
    unsigned char  *pkt = (unsigned char *) cp_fr_ip_pack(s->pool, ip);
    p_link_node     ln  = link_node_malloc(s->pool, pkt);

    if (ln != NULL) {
        ln->key = ntohl(tcp->seq);
        link_list_append_by_order(list, ln);
    }

    tc_log_debug4(LOG_INFO, 0, "ln:%llu, pkt:%llu, save:%u,p:%u", ln, pkt, 
            ln->key, ntohs(s->src_port));
}


static void 
proc_clt_pack_directly(tc_sess_t *s, tc_iph_t *ip, tc_tcph_t *tcp)
{
    int      diff;
    uint16_t cont_len;
    uint32_t seq;

    tc_log_debug_trace(LOG_DEBUG, 0, TC_CLT, ip, tcp);

    seq  = ntohl(tcp->seq);
    diff = tc_time() - s->create_time;
    if (diff < TCP_MS_TIMEOUT && (s->sm.state & SYN_SENT)) {
        if (before(seq, s->req_syn_seq)) {
            tc_log_debug1(LOG_INFO, 0, "timeout pack,p:%u", ntohs(s->src_port));
            return;
        }
    }

    tc_save_pack(s, s->slide_win_packs, ip, tcp);

    cont_len = TCP_PAYLOAD_LENGTH(ip, tcp);
    if (cont_len > 0) {
        if (s->sm.record_mcon_seq) {
            if (after(seq, s->max_con_seq)) {
                s->max_con_seq = seq;
            }
        } else {
            s->max_con_seq = seq;
            s->sm.record_mcon_seq = 1;
        }
    } else {
        if (!s->sm.fake_syn) {
            if (s->sm.rtt_cal == RTT_FIRST_RECORED) {
                calculate_rtt(s);
            }
        }
    }

    proc_clt_pack_from_buffer(s);
}


static bool 
proc_clt_pack_from_buffer(tc_sess_t *s)
{
    int           status;
    bool          pack_sent = false;
    uint16_t      size_ip;
    tc_iph_t     *ip;
    tc_tcph_t    *tcp;
    p_link_node   ln;

    tc_log_debug2(LOG_INFO, 0, "slide_win_packs size:%u, p:%u", 
            s->slide_win_packs->size, ntohs(s->src_port));

    if (s->prev_snd_node != NULL) {
        ln = link_list_get_next(s->slide_win_packs, s->prev_snd_node);
    } else {
        ln = link_list_first(s->slide_win_packs); 
    }

    while (ln ) {

        s->frame = ln->data;
        ip  = (tc_iph_t *) ((char *) s->frame + ETHERNET_HDR_LEN);
        size_ip    = ip->ihl << 2;
        tcp = (tc_tcph_t *) ((char *) ip + size_ip);
        s->cur_pack.cont_len = 0;

        status = proc_clt_pack(s, ip, tcp);

        if (status == PACK_STOP) {
            s->req_con_cur_ack_seq  = s->req_con_ack_seq;
            if (s->sm.conflict) {
                tc_log_debug1(LOG_INFO, 0, "conflict,p:%u", ntohs(s->src_port));
                remove_conflict_packs(s);
                s->sm.conflict = 0;
            }
            break;
        }

        pack_sent = true;
        s->prev_snd_node = ln;
        ln = link_list_get_next(s->slide_win_packs, ln);
        if (ln == NULL) {
            tc_log_debug1(LOG_INFO, 0, "empty slide,p:%u", ntohs(s->src_port));
            break;
        }

        if (status != PACK_NEXT) {
            break;
        }
    }

    return pack_sent;
}


bool
tc_proc_ingress(tc_iph_t *ip, tc_tcph_t *tcp)
{
    int          rtt;
    bool         larger_seq_detected;
    uint64_t     key;
    tc_sess_t   *s;

    if (tc_stat.start_pt == 0) {
        tc_stat.start_pt = tc_time();
    }

    if (clt_settings.factor) {
        tcp->source = get_port_from_shift(tcp->source,
                clt_settings.rand_port_shifted, clt_settings.factor);
    }

    key = get_key(ip->saddr, tcp->source);

    if (!tcp->syn) {

        larger_seq_detected = false;

        s = hash_find(sess_table, key);
        if (s) {
            if (s->sm.rcv_nxt_sess) {
                tc_log_debug_trace(LOG_INFO, 0, TC_CLT, ip, tcp);
                tc_log_debug1(LOG_INFO, 0, "drop next:%u", ntohs(s->src_port));
                return false;
            }
            if (s->sm.timeout) {
                if (after(ntohl(tcp->seq), s->req_con_snd_seq)) {
                    larger_seq_detected = true;
                } else {
                    sess_post_disp(s, true);
                    return false;
                }
            }
        } else if (clt_settings.only_replay_full) {
            return false;
        }

        if (s && !larger_seq_detected) {
            proc_clt_pack_directly(s, ip, tcp);
            if (!s->sm.timeout && s->sm.sess_over) {
                sess_post_disp(s, false);
            }
        } else {
            if (TCP_PAYLOAD_LENGTH(ip, tcp) > 0) {
#if (TC_PLUGIN)
                if (clt_settings.plugin && clt_settings.plugin->check_padding)
                {
                    if (!clt_settings.plugin->check_padding(ip, tcp)) {
                        return false;
                    }
                }
#endif
                rtt = 1;
                if (larger_seq_detected) {
                    rtt = s->rtt;
                    tc_log_debug1(LOG_INFO, 0, "del prev sess:%u", 
                            ntohs(s->src_port));
                    sess_post_disp(s, true);
                }
                s = sess_add(key, ip, tcp);
                if (s == NULL) {
                    return true;
                }
                s->rtt = rtt;
                proc_clt_pack_directly(s, ip, tcp);
            } else {
                return false;
            }
        }
    } else {
        s  = hash_find(sess_table, key);
        if (s) {
            if (s->sm.timeout) {
                sess_post_disp(s, true);
            } else {
                if (ntohl(tcp->seq) != s->req_syn_seq) {
                    s->sm.rcv_nxt_sess = 1;
                }
                return false;
            }
        } 

        s = sess_add(key, ip, tcp);
        if (s == NULL) {
            return true;
        }

#if (!TC_SINGLE)
        if (send_router_info(s, CLIENT_ADD)) {
            proc_clt_pack_directly(s, ip, tcp);
        }
#else
        proc_clt_pack_directly(s, ip, tcp);
#endif
    }

    return true;
}


static inline tc_sess_t *
sess_add(uint64_t key, tc_iph_t *ip, tc_tcph_t *tcp)
{
    tc_sess_t *s;

    s = sess_create(ip, tcp);
    if (s != NULL) {
        s->hash_key = key;
        if (!hash_add(sess_table, s->pool, key, s)) {
            tc_log_info(LOG_ERR, 0, "session item already exist");
        }
        tc_log_debug2(LOG_NOTICE, 0, "session key:%llu, p:%u", 
                s->hash_key, ntohs(s->src_port));
    }

    return s;
}

