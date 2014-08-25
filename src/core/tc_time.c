
#include <xcopy.h>

volatile char      *tc_error_log_time;
volatile time_t     tc_current_time_sec;
volatile long       tc_current_time_msec;
volatile struct tm  tc_current_tm;

static char cache_err_log_time[TC_ERR_LOG_TIME_STR_LEN];

void 
tc_time_init(void)
{
    tc_time_update();
}


void
tc_time_update()
{
    int             status;
    long            msec;
    time_t          sec;
    struct tm       tm;
    struct timeval  tv;

    status = gettimeofday(&tv, NULL);
    if (status >= 0) {
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

    } else {
        tc_log_info(LOG_ERR, errno, "gettimeofday failed");
    }
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

