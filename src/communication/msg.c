#include "msg.h"
#include "../log/log.h"

static int tcp_sock_init(){
	int sock;
	if((sock = socket(AF_INET,SOCK_STREAM,0))<0){          
		perror("socket:");                                        
		logInfo(LOG_ERR,"socket create error");
		exit(errno);
	}
	return sock;
}

static void connect_to_server(int sock,uint32_t ip){
	struct sockaddr_in remote_addr;                           
	memset(&remote_addr,0,sizeof(remote_addr));               
	remote_addr.sin_family = AF_INET;                         
	remote_addr.sin_addr.s_addr = ip;                
	remote_addr.sin_port = htons(SERVER_PORT);                       
	if(connect(sock,(struct sockaddr *)&remote_addr,sizeof(remote_addr)) == -1){
		perror("connect to remote:");                         
		logInfo(LOG_ERR,"it can not connect to remote server");
		exit(errno);
	}   
}

static void set_sock_no_delay(int sock){                              
	int flag = 1;
	if(setsockopt(sock,IPPROTO_TCP,TCP_NODELAY,(char *)&flag,sizeof(flag)) == -1){                                       
		perror("setsockopt:");
		logInfo(LOG_ERR,"setsocket error when setting TCP_NODELAY");
		exit(errno);
	} 
}

int msg_copyer_init(uint32_t receiver_ip){
	int sock  = tcp_sock_init();
	connect_to_server(sock,receiver_ip);
	set_sock_no_delay(sock);
	return sock;
}

static void sock_bind(int sock){
	struct sockaddr_in local_addr;
	memset(&local_addr,0,sizeof(local_addr));
	local_addr.sin_port = ntohs(SERVER_PORT);
	if(bind(sock,(struct sockaddr *)&local_addr,sizeof(local_addr))==-1){
		perror("can not bind:");
		logInfo(LOG_ERR,"it can not bind address");
		exit(errno);
	}
}

static void sock_listen(int sock){
	if(listen(sock,5)==-1){
		perror("sock listen:");
		logInfo(LOG_ERR,"it can not listen");
		exit(errno);
	}
}

static struct receiver_msg_st r_msg;
struct receiver_msg_st * msg_copyer_recv(int sock){
	size_t len =0;
	while(len != sizeof(struct receiver_msg_st)){
		ssize_t ret = recv(sock,(char *)&r_msg+len,sizeof(struct receiver_msg_st)-len,0);
		if(ret == 0){
			logInfo(LOG_DEBUG,"recv length is zero when in msg_copyer_recv");
			close(sock);
			return NULL;
		}else if(ret == -1){
			continue;
		}else{
			len += ret;
		}
	}
	return &r_msg;
}

struct copyer_msg_st c_msg;
struct copyer_msg_st *msg_receiver_recv(int sock){
	size_t len = 0;
	while(len != sizeof(struct copyer_msg_st)){
		ssize_t ret = recv(sock,(char *)&c_msg+len,sizeof(struct copyer_msg_st)-len,0);
		if(ret == 0){
			logInfo(LOG_DEBUG,"recv length is zero when in msg_receiver_recv");
			return NULL;
		}else if(ret == -1){
			continue;
		}else{
			len += ret;
		}
	}
	return &c_msg;
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  msg_receiver_init
 *  Description:  init msg receiver 
 * =====================================================================================
 */
int msg_receiver_init(){
	int sock = tcp_sock_init();
	sock_bind(sock);
	sock_listen(sock);
	return sock;
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  msg_copyer_send
 *  Description:  send msg for backend
 * =====================================================================================
 */
int msg_copyer_send(int sock,uint32_t c_ip,uint16_t c_port,uint16_t type){
	struct copyer_msg_st buf;
	buf.client_ip = c_ip;
	buf.client_port = c_port;
	buf.type = type;
	ssize_t sendlen = send(sock,(const void *)&buf,sizeof(buf),0);
	if(sendlen != sizeof(buf)){
		logInfo(LOG_WARN,"send length:%ld,buffer size:%u",
				sendlen,sizeof(buf));
		return -1;
	}
	return sendlen;
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  msg_receiver_send
 *  Description:  send msg for tcpcopy
 * =====================================================================================
 */
int msg_receiver_send(int sock,struct receiver_msg_st * msg){
	ssize_t sendlen = send(sock,(const void *)msg,
			sizeof(struct receiver_msg_st),0);
	if(sendlen!=-1)
	{
		if(sendlen != sizeof(*msg)){
			logInfo(LOG_NOTICE,"send length is not equal to msg size:%u",
					sendlen);	
			return -1;
		}
	}
	return sendlen;
}


