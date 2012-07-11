#include "xcopy.h"

/* Strace packet info for debug */
void strace_pack(int level, int flag,
        struct iphdr *ip_header, struct tcphdr *tcp_header)
{

    struct in_addr src_addr, dst_addr;
    char           *tmp_buf, src_ip[1024], dst_ip[1024];
    unsigned int   seq, ack_seq;
    uint32_t       pack_size;
    uint16_t       window;

    if(g_log_level < level){
        return;
    }

    src_addr.s_addr = ip_header->saddr;
    tmp_buf         = inet_ntoa(src_addr);
    strcpy(src_ip, tmp_buf);
    dst_addr.s_addr = ip_header->daddr;
    tmp_buf         = inet_ntoa(dst_addr);
    strcpy(dst_ip, tmp_buf);
    pack_size       = ntohs(ip_header->tot_len);
    seq             = ntohl(tcp_header->seq);
    ack_seq         = ntohl(tcp_header->ack_seq);
    /* Strange here, not using ntohs */
    window          = tcp_header->window;

    if(BACKEND_FLAG == flag){
        log_info(level, "from bak:%s:%u-->%s:%u,len %u ,seq=%u,ack=%u,win:%u",
                src_ip, ntohs(tcp_header->source), dst_ip,
                ntohs(tcp_header->dest), pack_size, seq, ack_seq, window);

    }else if(CLIENT_FLAG == flag){
        log_info(level, "recv clt:%s:%u-->%s:%u,len %u ,seq=%u,ack=%u,win:%u",
                src_ip, ntohs(tcp_header->source), dst_ip,
                ntohs(tcp_header->dest), pack_size, seq, ack_seq, window);

    }else if(TO_BAKEND_FLAG == flag){
        log_info(level, "to bak:%s:%u-->%s:%u,len %u ,seq=%u,ack=%u,win:%u",
                src_ip, ntohs(tcp_header->source), dst_ip,
                ntohs(tcp_header->dest), pack_size, seq, ack_seq, window);

    }else if(FAKED_CLIENT_FLAG == flag){
        log_info(level, "fake clt:%s:%u-->%s:%u,len %u,seq=%u,ack=%u,win:%u",
                src_ip, ntohs(tcp_header->source), dst_ip,
                ntohs(tcp_header->dest), pack_size, seq, ack_seq, window);
    }else if(UNKNOWN_FLAG == flag){
        log_info(level, "unkown packet:%s:%u-->%s:%u,len %u,seq=%u,ack=%u",
                src_ip, ntohs(tcp_header->source), dst_ip,
                ntohs(tcp_header->dest), pack_size, seq, ack_seq);
    }else{
        log_info(level, "strange %s:%u-->%s:%u,length %u,seq=%u,ack=%u",
                src_ip, ntohs(tcp_header->source), dst_ip,
                ntohs(tcp_header->dest), pack_size, seq, ack_seq);
    }
}

