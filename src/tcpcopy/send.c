
#include <xcopy.h>
#include <tcpcopy.h>

static int                 sock;
static struct sockaddr_in  dst_addr;

int 
send_init()
{
    int n = 1;

    /*
     * On Linux when setting the protocol as IPPROTO_RAW,
     * then by default the kernel sets the IP_HDRINCL option and 
     * thus does not prepend its own IP header. 
     */
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock > 0) {
        tc_log_info(LOG_NOTICE, 0, "create raw output socket successfully");
    } else {
        tc_log_info(LOG_ERR, 0, "it can't create raw output socket");
    } 

    /*
     * Tell the IP layer not to prepend its own header.
     * It does not need setting for linux,but *BSD needs
     */
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &n, sizeof(n)) < 0) {
        tc_log_info(LOG_ERR, errno, "IP_HDRINCL");
        exit(1);  
    }

    dst_addr.sin_family = AF_INET;

    return 0;
}

int
send_close()
{
    if (sock > 0) {
        close(sock);
        sock = -1;
    }

    return 0;
}

/*
 * Send the ip packet to the remote test server
 * (It will not go through ip fragmentation)
 */
ssize_t
send_ip_packet(struct iphdr *ip_header, uint16_t tot_len)
{

    ssize_t send_len = 0;

    if (sock > 0) {
        dst_addr.sin_addr.s_addr = ip_header->daddr;

        /*
         * The IP layer isn't involved at all. This has one negative effect 
         * in result(although in performance it's better): 
         * No IP fragmentation will take place if needed. 
         * This means that a raw packet larger than the MTU of the 
         * interface will probably be discarded. Instead ip_local_error(), 
         * which does general sk_buff cleaning,is called and an error EMSGSIZE 
         * is returned. On the other hand, normal raw socket frag.
         */
        send_len = sendto(sock, (void *)ip_header, tot_len, 0,
                (struct sockaddr *)&dst_addr, sizeof(dst_addr));

        if (-1 == send_len) {
            tc_log_info(LOG_ERR, errno, "send to");
        }

    }

    return send_len;
}

