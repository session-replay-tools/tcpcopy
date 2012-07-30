
#include <xcopy.h>

volatile time_t tc_current_time_sec;
volatile long   tc_current_time_msec;

void tc_time_update()
{
    long            msec;
    time_t          sec;
    struct timeval  tv;

    gettimeofday(&tv, NULL);

    sec = tv.tv_sec;
    msec = tv.tv_usec / 1000;

    tc_current_time_sec = sec;
    tc_current_time_msec = sec * 1000 + msec;
}
