#include <limits.h>
#include <netinet/in.h>
#include "nl.h"
#include "../log/log.h"

static int sock_init(int protocol){
	int sock = socket(AF_NETLINK,SOCK_RAW,protocol);
	if(sock == -1){
		perror("socket:");
		logInfo(LOG_ERR,"create netlink socket error");
		exit(errno);
	}
	return sock;
}

static void sock_bind(int sock,int groups){
	struct sockaddr_nl addr;
	memset(&addr,0,sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = getpid();
	addr.nl_groups = groups;
	if(bind(sock,(struct sockaddr *)&addr, sizeof(addr)) < 0){
		logInfo(LOG_ERR,"it can not bind for netlink");
		perror("bind:");
		exit(errno);
	}
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  nl_init
 *  Description:  init for netlink
 * =====================================================================================
 */
int nl_init(int protocol,int groups){
	int sock = sock_init(protocol);
	sock_bind(sock,groups);
	int rcvbuf = 1024*1024;
	setsockopt(sock,SOL_SOCKET,SO_RCVBUF,&rcvbuf,sizeof(rcvbuf));
	return sock;
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  nl_set_mode
 *  Description:  set mode for netlink
 * =====================================================================================
 */
void nl_set_mode(int sock,uint8_t mode,size_t range){
	struct {
		struct nlmsghdr head;
		ipq_peer_msg_t  body;
	}req;
	memset(&req, 0, sizeof(req));
	req.head.nlmsg_len = NLMSG_LENGTH(sizeof(req));
	req.head.nlmsg_flags = NLM_F_REQUEST;
	req.head.nlmsg_type = IPQM_MODE;
	req.head.nlmsg_pid = getpid();
	//here we drop the packet for default because of verdict in ipq_peer_msg_t
	//set zero
	req.body.msg.mode.value = mode;
	req.body.msg.mode.range = range;
	struct sockaddr_nl addr;
	memset(&addr,0,sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;
	addr.nl_groups = 0;
	if(sendto(sock, &req, req.head.nlmsg_len,0,
				(struct sockaddr *)&addr,sizeof(addr)) < 0){
		perror("cannot set mode:");
		logInfo(LOG_ERR,"it can not set mode for netlink");
		exit(errno);
	}
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  nl_recv
 *  Description:  recv message from netlink
 * =====================================================================================
 */
ssize_t nl_recv(int sock,void *buffer,size_t length){
	ssize_t recvlen = recv(sock,buffer,length,0);
	if(recvlen <0 ){
		logInfo(LOG_ERR,"recv length less than 0 for netlink");
		return -1;
	}
	if((size_t)recvlen < sizeof(struct nlmsghdr)){
		logInfo(LOG_ERR,"recv length not right for netlink");
		return -1;
	}
	return recvlen;
}


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  nl_payload
 *  Description:  
 * =====================================================================================
 */
void *nl_payload(void *buf){
	return NLMSG_DATA((struct nlmsghdr *)(buf));
}


