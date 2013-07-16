
#include <xcopy.h>

tc_atomic_t         tc_update_time;
volatile char      *tc_error_log_time;
volatile time_t     tc_current_time_sec;
volatile long       tc_current_time_msec;
volatile struct tm  tc_current_tm;

static char cache_err_log_time[TC_ERR_LOG_TIME_STR_LEN];

int
tc_time_set_timer(long msec)
{
    struct itimerval value;

    value.it_value.tv_sec = msec / 1000;
    value.it_value.tv_usec = (msec % 1000) * 1000;
    value.it_interval.tv_sec = msec / 1000;
    value.it_interval.tv_usec = (msec % 1000) * 1000;

    if (setitimer(ITIMER_REAL, &value, NULL) == -1) {
        tc_log_info(LOG_ERR, errno, "setitimer failed");   
        return TC_ERROR;
    }

    return TC_OK;
}

int
tc_time_remove_timer()
{
    if (setitimer(ITIMER_REAL, NULL, NULL) == -1) {
        tc_log_info(LOG_ERR, errno, "setitimer failed");   
        return TC_ERROR;
    }

    return TC_OK;
}

void 
tc_time_init()
{
    tc_update_time = 0;

    tc_time_update();
}

void
tc_time_update()
{
    long            msec;
    time_t          sec;
    struct tm       tm;
    struct timeval  tv;

    gettimeofday(&tv, NULL);

    sec = tv.tv_sec;
    msec = tv.tv_usec / 1000;

    tc_current_time_sec = sec;
    tc_current_time_msec = sec * 1000 + msec;

    tc_localtime(sec, &tm);

    snprintf(cache_err_log_time, TC_ERR_LOG_TIME_STR_LEN, 
            "%4d/%02d/%02d %02d:%02d:%02d +%03d",
            tm.tm_year, tm.tm_mon,
            tm.tm_mday, tm.tm_hour,
            tm.tm_min, tm.tm_sec,
            (int) msec);

    tc_current_tm = tm;
    tc_error_log_time = cache_err_log_time;
}

void
tc_localtime(time_t sec, struct tm *tm)
{
#if (HAVE_LOCALTIME_R)
    (void) localtime_r(&sec, tm);
#else
    struct tm *t;

    t = localtime(&sec);
    *tm = *t;
#endif

    tm->tm_mon++;
    tm->tm_year += 1900;
}

/* this is a signal handler */
void
tc_time_sig_alarm(int sig)
{
    tc_update_time = 1;
}

