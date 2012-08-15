
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
    char            buffer[2048], *p;
    size_t          n;
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

    va_start(args, fmt);
    n = vsprintf(p, fmt, args);
    va_end(args);

    if (n < 0) {
        return;
    }

    p += n;

    if (err > 0) {
        n = sprintf(p, " (%s)", strerror(err));
        if (n < 0) {
            return;
        }

        p += n;
    }

    *p++ = '\n';

    write(log_fd, buffer, p - buffer);
}

void
tc_log_trace(int level, int err, int flag, struct iphdr *ip_header,
        struct tcphdr *tcp_header)
{
    char           *tmp_buf, src_ip[1024], dst_ip[1024];
    uint16_t        window;
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

    /* Strange here, not using ntohs */
    window = tcp_header->window;

    if (BACKEND_FLAG == flag) {
        tc_log_info(level, err,
                    "from bak:%s:%u-->%s:%u,len %u ,seq=%u,ack=%u,win:%u",
                    src_ip, ntohs(tcp_header->source), dst_ip,
                    ntohs(tcp_header->dest), pack_size, seq, ack_seq, window);

    } else if (CLIENT_FLAG == flag) {
        tc_log_info(level, err,
                    "recv clt:%s:%u-->%s:%u,len %u ,seq=%u,ack=%u,win:%u",
                    src_ip, ntohs(tcp_header->source), dst_ip,
                    ntohs(tcp_header->dest), pack_size, seq, ack_seq, window);

    } else if (TO_BAKEND_FLAG == flag) {
        tc_log_info(level, err,
                    "to bak:%s:%u-->%s:%u,len %u ,seq=%u,ack=%u,win:%u",
                    src_ip, ntohs(tcp_header->source), dst_ip,
                    ntohs(tcp_header->dest), pack_size, seq, ack_seq, window);

    } else if (FAKED_CLIENT_FLAG == flag) {
        tc_log_info(level, err,
                    "fake clt:%s:%u-->%s:%u,len %u,seq=%u,ack=%u,win:%u",
                    src_ip, ntohs(tcp_header->source), dst_ip,
                    ntohs(tcp_header->dest), pack_size, seq, ack_seq, window);

    } else if (UNKNOWN_FLAG == flag) {
        tc_log_info(level, err,
                    "unkown packet:%s:%u-->%s:%u,len %u,seq=%u,ack=%u",
                    src_ip, ntohs(tcp_header->source), dst_ip,
                    ntohs(tcp_header->dest), pack_size, seq, ack_seq);

    } else{
        tc_log_info(level, err,
                    "strange %s:%u-->%s:%u,length %u,seq=%u,ack=%u",
                    src_ip, ntohs(tcp_header->source), dst_ip,
                    ntohs(tcp_header->dest), pack_size, seq, ack_seq);
    }
}

