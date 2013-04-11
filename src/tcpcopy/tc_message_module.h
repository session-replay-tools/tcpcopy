#ifndef TC_MESSAGE_MODULE_INCLUDED
#define TC_MESSAGE_MODULE_INCLUDED 

#include <xcopy.h>
#include <tcpcopy.h>

int tc_message_init(tc_event_loop_t *event_loop, uint32_t ip, uint16_t port);

#endif
