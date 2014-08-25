#ifndef  TC_SIGNAL_INCLUDED
#define  TC_SIGNAL_INCLUDED

#include <xcopy.h>

typedef struct signal_s{
    char *signame;
    int   signo;
    int   flags;
    void  (*handler)(int signo);
}signal_t;

int set_signal_handler(signal_t *signals);
int sigignore(int sig);

#endif /* TC_SIGNAL_INCLUDED */

