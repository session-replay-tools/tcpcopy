#ifndef  TC_COMBINE_INCLUDED
#define  TC_COMBINE_INCLUDED

#if (INTERCEPT_COMBINED)
typedef struct aggregation_s{
    time_t         access_time;
    long           access_msec;
    unsigned char *cur_write;
    uint16_t       num;
    unsigned char  aggr_resp[COMB_LENGTH];
}aggregation_t;

void set_fd_valid(int fd, bool valid);
void buffer_and_send(int mfd, int fd, msg_server_t *msg);
void send_buffered_packets(time_t cur_time);
void release_combined_resouces();
#endif


#endif /* TC_COMBINE_INCLUDED */

