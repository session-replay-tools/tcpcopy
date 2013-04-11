#ifndef  TC_INTERCEPTION_INCLUDED
#define  TC_INTERCEPTION_INCLUDED

int interception_init(tc_event_loop_t *event_loop, char *ip, uint16_t port);
void interception_run();
void interception_over();

#endif /* TC_INTERCEPTION_INCLUDED */

