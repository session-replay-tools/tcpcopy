
#ifndef  _UDP_SESSION_H_INC
#define  _UDP_SESSION_H_INC


/* global functions */
void init_for_sessions();
void destroy_for_sessions();
bool process(char *packet, int pack_src);
bool is_packet_needed(const char *packet);
void tc_interval_dispose(tc_event_timer_t *evt);
void output_stat();

#endif   /* ----- #ifndef _UDP_SESSION_H_INC ----- */

