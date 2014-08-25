
#ifndef  _UDP_SESSION_H_INC
#define  _UDP_SESSION_H_INC


/* global functions */
int  tc_init_sess_table();
void tc_dest_sess_table();
bool tc_proc_ingress(tc_iph_t *ip, tc_udpt_t *udp);
bool tc_proc_outgress(unsigned char *packet);
bool tc_check_ingress_pack_needed(tc_iph_t *ip);
void tc_interval_disp(tc_event_timer_t *evt);
void tc_output_stat();

#endif   /* ----- #ifndef _UDP_SESSION_H_INC ----- */

