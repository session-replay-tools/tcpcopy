#ifndef  _INTERCEPTION_H_INC
#define  _INTERCEPTION_H_INC

int interception_init(tc_event_loop_t *event_loop, char *ip, uint16_t port);
void interception_run();
void interception_over();

#endif /* _INTERCEPTION_H_INC */

