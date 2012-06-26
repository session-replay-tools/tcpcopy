#include "nl.h"

static int sock_init(int protocol)
{
	int sock = socket(AF_NETLINK, SOCK_RAW, protocol);
	if(-1 == sock){
		perror("socket:");
		log_info(LOG_ERR,"create netlink socket error:%s",
				strerror(errno));
		sync(); 
		exit(errno);
	}
	return sock;
}

/* initiate for netlink socket */
int nl_init(int protocol, int groups)
{
	int rcvbuf = 1048576;
	int sock = sock_init(protocol);
	setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
	return sock;
}

/* set mode for netlink socket*/
void nl_set_mode(int sock, uint8_t mode, size_t range)
{
	struct sockaddr_nl  addr;
	struct nlmsghdr     *nl_header;
	struct ipq_mode_msg *mode_data;
	unsigned char       buf1[128];

	memset(buf1, 0, 128);
	memset(&addr, 0, sizeof(addr));

	addr.nl_family = AF_NETLINK;
	addr.nl_pid    = 0;
	addr.nl_groups = 0;

	nl_header = (struct nlsmghdr *)buf1;
	/* It must be ipq_peer_msg, not ipq_mode_msg */
	nl_header->nlmsg_len   = NLMSG_LENGTH(sizeof(struct ipq_peer_msg));
	nl_header->nlmsg_flags = NLM_F_REQUEST;
	nl_header->nlmsg_type  = IPQM_MODE;
	nl_header->nlmsg_pid   = getpid();
	mode_data = NLMSG_DATA(nl_header);
	mode_data->value = mode;
	mode_data->range = range;
	if(sendto(sock, (void *)nl_header, nl_header->nlmsg_len,0,
				(struct sockaddr *)&addr, sizeof(struct sockaddr_nl)) < 0){
		perror("cannot set mode:");
		log_info(LOG_ERR,
				"can not set mode for netlink,check if ip queue is up:%s",
				strerror(errno));
		sync(); 
		exit(errno);
	}else{
		log_info(LOG_NOTICE, "sendto for ip queue is ok");
	}
}

/* receive message from netlink socket*/
ssize_t nl_recv(int sock, void *buffer, size_t length)
{
	ssize_t recv_len = recv(sock, buffer, length, 0);
	if(recv_len < 0){
		log_info(LOG_ERR,"recv length less than 0 for netlink");
		return -1;
	}
	if((size_t)recv_len < sizeof(struct nlmsghdr)){
		log_info(LOG_ERR,"recv length not right for netlink");
		return -1;
	}
	return recv_len;
}

/* get payload of netlink message */
void *nl_get_payload(void *buf){
	return NLMSG_DATA((struct nlmsghdr *)(buf));
}

