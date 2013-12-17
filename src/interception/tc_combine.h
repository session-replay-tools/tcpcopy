#ifndef  TC_COMBINE_INCLUDED
#define  TC_COMBINE_INCLUDED

#if (INTERCEPT_COMBINED)
void buffer_and_send(int fd, msg_server_t *msg);
void send_buffered_packets();
#endif


#endif /* TC_COMBINE_INCLUDED */

