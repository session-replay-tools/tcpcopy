#include "msg.h"

static int tcp_sock_init()
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if( sock < 0){          
        perror("socket:");                                        
        log_info(LOG_ERR, "socket create error:%s", strerror(errno));
        sync();
        exit(errno);
    }else{
        log_info(LOG_NOTICE, "socket created successfully");
    }
    return sock;
}

static void connect_to_server(int sock, uint32_t ip, uint16_t port)
{
    struct sockaddr_in remote_addr;                           
    socklen_t          length;

    memset(&remote_addr, 0, sizeof(remote_addr));               
    remote_addr.sin_family = AF_INET;                         
    remote_addr.sin_addr.s_addr = ip;                
    remote_addr.sin_port = htons(port);                       
    length = (socklen_t)(sizeof(remote_addr));
    if(connect(sock, (struct sockaddr *)&remote_addr, length) == -1){
        perror("connect to remote:");                         
        log_info(LOG_ERR, "it can not connect to remote server:%s",
                strerror(errno));
        sync(); 
        exit(errno);
    }   
}

static void set_sock_no_delay(int sock)
{                              
    int flag = 1;
    socklen_t length = (socklen_t)(sizeof(flag));
    if(setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, length) 
            == -1){
        perror("setsockopt:");
        log_info(LOG_ERR, "setsocket error when setting TCP_NODELAY:%s",
                strerror(errno));
        sync(); 
        exit(errno);
    } 
}

int msg_client_init(uint32_t server_ip, uint16_t port)
{
    int sock  = tcp_sock_init();
    connect_to_server(sock, server_ip, port);
    set_sock_no_delay(sock);
    return sock;
}

static void sock_bind(int sock, const char *binded_ip, uint16_t port)
{
    struct sockaddr_in local_addr;
    socklen_t          length; 

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_port   = ntohs(port);
    local_addr.sin_family = AF_INET;
    if(binded_ip != NULL){
        /* Set binded ip for security reasons */
        inet_aton(binded_ip, &local_addr.sin_addr);
    }
    length = (socklen_t)(sizeof(local_addr));
    if(bind(sock, (struct sockaddr *)&local_addr, length) == -1){
        perror("can not bind:");
        log_info(LOG_ERR, "it can not bind address:%s", strerror(errno));
        sync(); 
        exit(errno);
    }else{
        log_info(LOG_NOTICE, "it binds address successfully");
    }
}

static void sock_listen(int sock)
{
    if(listen(sock, 5) == -1){
        perror("sock listen:");
        log_info(LOG_ERR, "it can not listen:%s", strerror(errno));
        sync(); 
        exit(errno);
    }else{
        log_info(LOG_NOTICE, "it listens successfully");
    }
}

/* Init msg server */
int msg_server_init(const char *binded_ip, uint16_t port)
{
    int sock = tcp_sock_init();
    sock_bind(sock, binded_ip, port);
    sock_listen(sock);
    return sock;
}


static struct msg_server_s s_msg;

/* Receive a server message */
struct msg_server_s *msg_client_recv(int sock)
{
    size_t  len = 0;
    ssize_t ret;
    while(len != sizeof(struct msg_server_s)){
        ret = recv(sock, (char *)&s_msg + len,
                sizeof(struct msg_server_s) - len, 0);
        if(0 == ret){
            log_info(LOG_DEBUG, "recv length is zero in msg_client_recv");
            (void)close(sock);
            return NULL;
        }else if(-1 == ret){
            continue;
        }else{
            len += ret;
        }
    }
    return &s_msg;
}

static struct msg_client_s c_msg;

/* Receive a client message */
struct msg_client_s *msg_server_recv(int sock)
{
    size_t  len = 0;
    ssize_t ret;
    while(len != sizeof(struct msg_client_s)){
        ret = recv(sock, (char *)&c_msg + len,
                sizeof(struct msg_client_s) - len, 0);
        if(0 == ret){
            log_info(LOG_DEBUG, "recv len is zero in msg_server_recv");
            return NULL;
        }else if(-1 == ret){
            continue;
        }else{
            len += ret;
        }
    }
    return &c_msg;
}

/* Send a message to backend */
int msg_client_send(int sock, uint32_t c_ip, uint16_t c_port, uint16_t type)
{
    struct msg_client_s buf;
    ssize_t send_len, buf_len = (ssize_t)(sizeof(buf));
    buf.client_ip   = c_ip;
    buf.client_port = c_port;
    buf.type = type;
    send_len = send(sock, (const void *)&buf, sizeof(buf), 0);
    if(send_len != buf_len){
        log_info(LOG_WARN, "send length:%ld,buffer size:%ld",
                send_len, buf_len);
        return -1;
    }
    return (int)send_len;
}

/* Send a message to client */
int msg_server_send(int sock, struct msg_server_s *msg)
{
    ssize_t send_len, msg_len  = (ssize_t)(sizeof(struct msg_server_s));
    send_len = send(sock, (const void *)msg, (size_t)msg_len, 0);
    if(send_len != -1){
        if(send_len != msg_len){
            log_info(LOG_NOTICE, "send len is not equal to msg size:%u",
                    send_len);  
            return -1;
        }
    }
    return (int)send_len;
}

