#ifndef TC_SOCKET_INCLUDED
#define TC_SOCKET_INCLUDED

#define TC_INVALID_SOCK -1

#include <xcopy.h>

#define tc_socket_close(fd) close(fd)

#if (TC_PCAP)
int tc_pcap_socket_in_init(pcap_t **pd, char *device, 
        int snap_len, int buf_size, char *pcap_filter);
#endif
int tc_raw_socket_in_init(int type);

int tc_raw_socket_out_init(void);
int tc_raw_socket_snd(int fd, void *buf, size_t len, uint32_t ip);

#if (TC_PCAP_SND)
int tc_pcap_snd_init(char *if_name, int mtu);
int tc_pcap_snd(unsigned char *frame, size_t len);
int tc_pcap_over(void);
#endif

int tc_socket_init(void);
int tc_socket_set_nonblocking(int fd);
int tc_socket_set_nodelay(int fd);
int tc_socket_connect(int fd, uint32_t ip, uint16_t port);
int tc_socket_rcv(int fd, char *buffer, ssize_t len);
#if (TC_COMBINED)
int tc_socket_cmb_rcv(int fd, int *num, char *buffer);
#endif
int tc_socket_snd(int fd, char *buffer, int len);

#endif /* TC_SOCKET_INCLUDED */

