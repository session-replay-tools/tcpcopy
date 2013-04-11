#ifndef  TC_DELAY_INCLUDED
#define  TC_DELAY_INCLUDED

#include <xcopy.h>
#include <intercept.h>

void delay_table_init(size_t size);
void delay_table_delete_obsolete(time_t cur_time);  
void delay_table_add(uint64_t key, struct msg_server_s *);
void delay_table_send(uint64_t key, int fd);
void delay_table_del(uint64_t key);
void delay_table_destroy();

#endif /* TC_DELAY_INCLUDED */

