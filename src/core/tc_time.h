#ifndef __TIME_H__
#define __TIME_H__

#include <time.h>
#include <sys/time.h>

#define tc_time() tc_current_time_sec

extern volatile time_t tc_current_time_sec;
extern volatile long   tc_current_time_msec;

void tc_time_update(void);

#endif /* __TIME_H__ */
