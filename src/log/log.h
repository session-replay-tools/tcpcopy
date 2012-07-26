#ifndef  _LOG_H_INC
#define  _LOG_H_INC

#include "config.h"

void log_init();
void log_end();

void log_info(int level, const char *fmt, ...);

#if (TCPCOPY_DEBUG)

#define tc_log_debug0(level, fmt)                                       \
    log_info(level, (const char *) fmt)

#define tc_log_debug1(level, fmt, a1)                                   \
    log_info(level, (const char *) fmt, a1)

#define tc_log_debug2(level, fmt, a1, a2)                               \
    log_info(level, (const char *) fmt, a1, a2)

#define tc_log_debug3(level, fmt, a1, a2, a3)                           \
    log_info(level, (const char *) fmt, a1, a2, a3)

#define tc_log_debug4(level, fmt, a1, a2, a3, a4)                       \
    log_info(level, (const char *) fmt, a1, a2, a3, a4)

#define tc_log_debug5(level, fmt, a1, a2, a3, a4, a5)                   \
    log_info(level, (const char *) fmt, a1, a2, a3, a4, a5)

#define tc_log_debug6(level, fmt, a1, a2, a3, a4, a5, a6)               \
    log_info(level, (const char *) fmt, a1, a2, a3, a4, a5, a6)

#define tc_log_debug7(level, fmt, a1, a2, a3, a4, a5, a6, a7)           \
    log_info(level, (const char *) fmt, a1, a2, a3, a4, a5, a6, a7)

#else

#define tc_log_debug0(level, fmt)
#define tc_log_debug1(level, fmt, a1)
#define tc_log_debug2(level, fmt, a1, a2)
#define tc_log_debug3(level, fmt, a1, a2, a3)
#define tc_log_debug4(level, fmt, a1, a2, a3, a4)
#define tc_log_debug5(level, fmt, a1, a2, a3, a4, a5)
#define tc_log_debug6(level, fmt, a1, a2, a3, a4, a5, a6)
#define tc_log_debug7(level, fmt, a1, a2, a3, a4, a5, a6, a7)

#endif /* TCPCOPY_DEBUG */

#endif /* _LOG_H_INC */


