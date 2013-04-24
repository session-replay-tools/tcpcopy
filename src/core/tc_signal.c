
#include <xcopy.h>

int
sigignore(int sig)
{
    struct sigaction sa;

    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;

    if (sigemptyset(&sa.sa_mask) == -1 || sigaction(sig, &sa, 0) == -1) {
        return -1;
    }

    return 0;
}

int
set_signal_handler(signal_t *signals)
{
    signal_t *sig;

    for (sig = signals; sig->signo != 0; sig++) {
        int status;
        struct sigaction sa;

        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sig->handler;
        sa.sa_flags = sig->flags;
        sigemptyset(&sa.sa_mask);

        status = sigaction(sig->signo, &sa, NULL);
        if (status < 0) {
            tc_log_info(LOG_ERR, 0, "sigaction(%s) failed: %s", sig->signame,
                      strerror(errno));
            return -1;
        }
    }

    return 0;
}

