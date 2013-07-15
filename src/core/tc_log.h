#ifndef  TC_LOG_INCLUDED
#define  TC_LOG_INCLUDED

#include <xcopy.h>

#define LOG_STDERR            0
#define LOG_EMERG             1
#define LOG_ALERT             2
#define LOG_CRIT              3
#define LOG_ERR               4
#define LOG_WARN              5
#define LOG_NOTICE            6
#define LOG_INFO              7
#define LOG_DEBUG             8

#define LOG_MAX_LEN        2048

int tc_log_init();
void tc_log_end();

void tc_log_info(int level, int err, const char *fmt, ...);
void tc_log_trace(int level, int err, int flag, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header);
#if (TCPCOPY_UDP)
void tc_log_udp_trace(int level, int err, int flag, tc_ip_header_t *ip_header,
        tc_udp_header_t *udp_header);
#endif

#if (TCPCOPY_DEBUG)

#define tc_log_debug0(level, err, fmt)                                       \
    tc_log_info(level, err, (const char *) fmt)

#define tc_log_debug1(level, err, fmt, a1)                                   \
    tc_log_info(level, err, (const char *) fmt, a1)

#define tc_log_debug2(level, err, fmt, a1, a2)                               \
    tc_log_info(level, err, (const char *) fmt, a1, a2)

#define tc_log_debug3(level, err, fmt, a1, a2, a3)                           \
    tc_log_info(level, err, (const char *) fmt, a1, a2, a3)

#define tc_log_debug4(level, err, fmt, a1, a2, a3, a4)                       \
    tc_log_info(level, err, (const char *) fmt, a1, a2, a3, a4)

#define tc_log_debug5(level, err, fmt, a1, a2, a3, a4, a5)                   \
    tc_log_info(level, err, (const char *) fmt, a1, a2, a3, a4, a5)

#define tc_log_debug6(level, err, fmt, a1, a2, a3, a4, a5, a6)               \
    tc_log_info(level, err, (const char *) fmt, a1, a2, a3, a4, a5, a6)

#define tc_log_debug7(level, err, fmt, a1, a2, a3, a4, a5, a6, a7)           \
    tc_log_info(level, err, (const char *) fmt, a1, a2, a3, a4, a5, a6, a7)

#define tc_log_debug8(level, err, fmt, a1, a2, a3, a4, a5, a6, a7, a8)       \
    tc_log_info(level, err, (const char *) fmt, a1, a2, a3, a4, a5, a6, a7, a8)

#define tc_log_debug_trace(level, err, flag, ip_header, tcp_header)          \
    tc_log_trace(level, err, flag, ip_header, tcp_header)

#else

#define tc_log_debug0(level, err, fmt)
#define tc_log_debug1(level, err, fmt, a1)
#define tc_log_debug2(level, err, fmt, a1, a2)
#define tc_log_debug3(level, err, fmt, a1, a2, a3)
#define tc_log_debug4(level, err, fmt, a1, a2, a3, a4)
#define tc_log_debug5(level, err, fmt, a1, a2, a3, a4, a5)
#define tc_log_debug6(level, err, fmt, a1, a2, a3, a4, a5, a6)
#define tc_log_debug7(level, err, fmt, a1, a2, a3, a4, a5, a6, a7)
#define tc_log_debug8(level, err, fmt, a1, a2, a3, a4, a5, a6, a7, a8)
#define tc_log_debug_trace(level, err, flag, ip_header, tcp_header)

#endif /* TCPCOPY_DEBUG */

#endif /* TC_LOG_INCLUDED */


