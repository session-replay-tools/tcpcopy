#ifndef __TIME_H__
#define __TIME_H__

#include <xcopy.h>

#define TC_ERR_LOG_TIME_LEN (sizeof("2012-07-31 12:35:00 +999") - 1)

#define tc_time() tc_current_time_sec

extern volatile char      *tc_error_log_time;
extern volatile long       tc_current_time_msec;
extern volatile time_t     tc_current_time_sec;
extern volatile struct tm  tc_current_tm;

void tc_time_update(void);
void tc_localtime(time_t sec, struct tm *tm);

#endif /* __TIME_H__ */
