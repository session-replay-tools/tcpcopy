#ifndef __TC_TIME_H__
#define __TC_TIME_H__

#include <xcopy.h>

#define TC_ERR_LOG_TIME_LEN (sizeof("2012-07-31 12:35:00 +999") - 1)

#define tc_time() tc_current_time_sec

extern volatile int        tc_update_time;
extern volatile char      *tc_error_log_time;
extern volatile long       tc_current_time_msec;
extern volatile time_t     tc_current_time_sec;
extern volatile struct tm  tc_current_tm;

int tc_time_init(long msec);
void tc_time_update(void);
void tc_localtime(time_t sec, struct tm *tm);
void tc_time_sig_alarm(int sig);

#endif /* __TC_TIME_H__ */
