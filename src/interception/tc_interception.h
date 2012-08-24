#ifndef  _INTERCEPTION_H_INC
#define  _INTERCEPTION_H_INC

int interception_init(tc_event_loop_t *event_loop, char *ip, uint16_t port);
void interception_run();
void interception_over();

void tc_msg_event_accept(tc_event_t *rev);
void tc_msg_event_process(tc_event_t *rev);
void tc_nl_event_process(tc_event_t *rev);

#endif /* _INTERCEPTION_H_INC */

