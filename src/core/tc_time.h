#ifndef TC_TIME_INCLUDED
#define TC_TIME_INCLUDED

#include <xcopy.h>

#define TC_ERR_LOG_TIME_LEN (sizeof("2012-07-31 12:35:00 +999") - 1)
#define TC_ERR_LOG_TIME_STR_LEN (TC_ERR_LOG_TIME_LEN + 1)

#define tc_time() tc_current_time_sec
#define tc_milliscond_time() tc_current_time_msec 
#define tc_time_diff(s1, ms1, s2, ms2) \
    (((s2) * 1000 + (ms2)) - ((s1) * 1000 + (ms1)))

extern volatile int        tc_update_time;
extern volatile char      *tc_error_log_time;
extern volatile long       tc_current_time_msec;
extern volatile time_t     tc_current_time_sec;
extern volatile struct tm  tc_current_tm;

int  tc_time_set_timer(long msec);
int  tc_time_remove_timer();
void tc_time_init();
void tc_time_update(void);
void tc_localtime(time_t sec, struct tm *tm);
void tc_time_sig_alarm(int sig);

#endif /* TC_TIME_INCLUDED */
