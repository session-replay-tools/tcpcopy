#ifndef TC_SOCKET_INCLUDED
#define TC_SOCKET_INCLUDED

#if (INTERCEPT_NFQUEUE)
#include <libnetfilter_queue/libnetfilter_queue.h>
#endif
#include <xcopy.h>

#define TC_INVALID_SOCKET -1
#define TC_IPQ_NLMSG_LEN (sizeof(struct ipq_packet_msg) + NLMSG_LENGTH(0))

#define tc_nl_packet_id(buf) \
    ((struct ipq_packet_msg *) NLMSG_DATA((struct nlmsghdr *) (buf)))->packet_id
#define tc_nl_ip_header(buf) \
    ((tc_ip_header_t *) \
     ((struct ipq_packet_msg *) NLMSG_DATA((struct nlmsghdr *) (buf)))->payload)

#define tc_socket_close(fd) close(fd)
#define tc_socket_accept(fd) accept(fd, NULL, NULL) 

#if (TCPCOPY_PCAP)
int tc_pcap_socket_in_init(pcap_t **pd, char *device, char *pcap_filter);
#endif
int tc_raw_socket_in_init(int type);

int tc_raw_socket_out_init();
int tc_raw_socket_send(int fd, void *buf, size_t len, uint32_t ip);

#if (!INTERCEPT_NFQUEUE)
int tc_nl_socket_init();
int tc_nl_socket_recv(int fd, char *buffer, size_t len);

#else
int tc_nfq_socket_init(struct nfq_handle **h, struct nfq_q_handle **qh,
        nfq_callback *cb);
int tc_nfq_socket_recv(int fd, char *buffer, size_t len, int *rv);
#endif

int tc_socket_init();
int tc_socket_set_nonblocking(int fd);
int tc_socket_set_nodelay(int fd);
int tc_socket_connect(int fd, uint32_t ip, uint16_t port);
int tc_socket_listen(int fd, const char *bind_ip, uint16_t port);
int tc_socket_recv(int fd, char *buffer, ssize_t len);
int tc_socket_send(int fd, char *buffer, size_t len);

#endif /* TC_SOCKET_INCLUDED */
