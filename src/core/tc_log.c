
#include <xcopy.h>

static int log_fd = -1;

typedef struct {
    char *level;
    int   len;
} tc_log_level_t;

static tc_log_level_t tc_log_levels[] = {
    { "[unknown]", 9 }, 
    { "[emerg]", 7 },
    { "[alert]", 7 },
    { "[crit]", 6 },
    { "[error]", 7 },
    { "[warn]", 6 },
    { "[notice]", 8},
    { "[info]", 6},
    { "[debug]", 7 }
};

int
tc_vscnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
    int i;

    /*
     * Attention for vsnprintf: http://lwn.net/Articles/69419/
     */
    i = vsnprintf(buf, size, fmt, args);

    if (i <= 0) {
        return 0;
    }

    if (i < size) {
        return i;
    }

    return size - 1;
}

int
tc_scnprintf(char *buf, size_t size, const char *fmt, ...)
{
    va_list args;
    int i;

    va_start(args, fmt);
    i = tc_vscnprintf(buf, size, fmt, args);
    va_end(args);

    return i;
}

int
tc_log_init(const char *file)
{
    log_fd = open((file == NULL ? "error.log" : file),
                  O_RDWR|O_CREAT|O_APPEND, 0644);

    if (log_fd == -1) {
        fprintf(stderr, "Open log file error: %s\n", strerror(errno));
    }

    return log_fd;
}

void
tc_log_end()
{
    if (log_fd != -1) {
        close(log_fd);
    }

    log_fd = -1;
}

void
tc_log_info(int level, int err, const char *fmt, ...)
{
    char            buffer[LOG_MAX_LEN], *p;
    size_t          n, len;
    va_list         args;
    tc_log_level_t *ll;

    if (log_fd == -1) {
        return;
    }

#if (TCPCOPY_DEBUG)
    tc_time_update();
#endif

    ll = &tc_log_levels[level];

    p = buffer;

    p = tc_cpymem(p, tc_error_log_time, TC_ERR_LOG_TIME_LEN);
    *p++ = ' ';

    p = tc_cpymem(p, ll->level, ll->len);
    *p++ = ' ';

    n = len = TC_ERR_LOG_TIME_LEN + ll->len + 2;
    va_start(args, fmt);
    len += tc_vscnprintf(p, LOG_MAX_LEN - n, fmt, args);
    va_end(args);

    if (len <= n) {
        return;
    }

    p = buffer + len;

    if (err > 0) {
        len += tc_scnprintf(p, LOG_MAX_LEN - len, " (%s)", strerror(err));
        if (len < (p - buffer)) {
            return;
        }

        p = buffer + len;
    }

    *p++ = '\n';

    write(log_fd, buffer, p - buffer);
}

void
tc_log_trace(int level, int err, int flag, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    char           *tmp_buf, src_ip[1024], dst_ip[1024];
    uint32_t        pack_size;
    unsigned int    seq, ack_seq;
    struct in_addr  src_addr, dst_addr;

    src_addr.s_addr = ip_header->saddr;
    tmp_buf = inet_ntoa(src_addr);
    strcpy(src_ip, tmp_buf);

    dst_addr.s_addr = ip_header->daddr;
    tmp_buf = inet_ntoa(dst_addr);
    strcpy(dst_ip, tmp_buf);

    pack_size = ntohs(ip_header->tot_len);
    seq = ntohl(tcp_header->seq);
    ack_seq = ntohl(tcp_header->ack_seq);

    if (BACKEND_FLAG == flag) {
        tc_log_info(level, err,
                    "from bak:%s:%u-->%s:%u,len %u,seq=%u,ack=%u",
                    src_ip, ntohs(tcp_header->source), dst_ip,
                    ntohs(tcp_header->dest), pack_size, seq, ack_seq);

    } else if (CLIENT_FLAG == flag) {
        tc_log_info(level, err,
                    "recv clt:%s:%u-->%s:%u,len %u,seq=%u,ack=%u",
                    src_ip, ntohs(tcp_header->source), dst_ip,
                    ntohs(tcp_header->dest), pack_size, seq, ack_seq);

    } else if (TO_BAKEND_FLAG == flag) {
        tc_log_info(level, err,
                    "to bak:%s:%u-->%s:%u,len %u,seq=%u,ack=%u",
                    src_ip, ntohs(tcp_header->source), dst_ip,
                    ntohs(tcp_header->dest), pack_size, seq, ack_seq);

    } else if (RESERVED_CLIENT_FLAG == flag) {
        tc_log_info(level, err,
                    "reserved clt:%s:%u-->%s:%u,len %u,seq=%u,ack=%u",
                    src_ip, ntohs(tcp_header->source), dst_ip,
                    ntohs(tcp_header->dest), pack_size, seq, ack_seq);

    } else if (FAKED_CLIENT_FLAG == flag) {
        tc_log_info(level, err,
                    "fake clt:%s:%u-->%s:%u,len %u,seq=%u,ack=%u",
                    src_ip, ntohs(tcp_header->source), dst_ip,
                    ntohs(tcp_header->dest), pack_size, seq, ack_seq);

    } else if (UNKNOWN_FLAG == flag) {
        tc_log_info(level, err,
                    "unknown packet:%s:%u-->%s:%u,len %u,seq=%u,ack=%u",
                    src_ip, ntohs(tcp_header->source), dst_ip,
                    ntohs(tcp_header->dest), pack_size,
                    seq, ack_seq);

    } else {
        tc_log_info(level, err,
                    "strange %s:%u-->%s:%u,length %u,seq=%u,ack=%u",
                    src_ip, ntohs(tcp_header->source), dst_ip,
                    ntohs(tcp_header->dest), pack_size,
                    seq, ack_seq);
    }
}

#if (TCPCOPY_UDP)
void
tc_log_udp_trace(int level, int err, int flag, tc_ip_header_t *ip_header,
        tc_udp_header_t *udp_header)
{
    char           *tmp_buf, src_ip[1024], dst_ip[1024];
    uint32_t        pack_size;
    struct in_addr  src_addr, dst_addr;

    src_addr.s_addr = ip_header->saddr;
    tmp_buf = inet_ntoa(src_addr);
    strcpy(src_ip, tmp_buf);

    dst_addr.s_addr = ip_header->daddr;
    tmp_buf = inet_ntoa(dst_addr);
    strcpy(dst_ip, tmp_buf);

    pack_size       = ntohs(ip_header->tot_len);

    tc_log_info(level, err, "from client %s:%u-->%s:%u,len %u",
            src_ip, 
            ntohs(udp_header->source),
            dst_ip,
            ntohs(udp_header->dest),
            pack_size);

}
#endif

