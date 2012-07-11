#include "../core/xcopy.h"
#include "../communication/msg.h"
#include "../event/select_server.h"
#include "router.h"
#include "delay.h"
#include "nl_firewall.h"
#include "interception.h"

static int    firewall_sock;
static int    msg_listen_sock;
static time_t last_clean_time;

static void set_sock_no_delay(int sock)
{
    int flag = 1;
    if(setsockopt(sock, IPPROTO_TCP,TCP_NODELAY, (char *)&flag,
                sizeof(flag)) == -1){
        perror("setsockopt:");
        log_info(LOG_ERR, "setsockopt error:%s", strerror(errno));
        sync(); 
        exit(errno);
    }else{
        log_info(LOG_NOTICE, "setsockopt ok");
    }
    return;
}

#if (DEBUG_TCPCOPY)
static void output_debug(int level, struct iphdr *ip_header)
{
    size_t        size_ip;
    struct tcphdr *tcp_header;
    size_ip    = ip_header->ihl<<2;
    tcp_header = (struct tcphdr*)((char *)ip_header + size_ip);
    strace_pack(level, BACKEND_FLAG, ip_header, tcp_header);
}
#endif

static uint32_t seq = 1;
static unsigned char buffer[128];

static int dispose_netlink_packet(int verdict, unsigned long packet_id)
{
    struct nlmsghdr        *nl_header = (struct nlmsghdr*)buffer;
    struct ipq_verdict_msg *ver_data;
    struct sockaddr_nl      addr;

    /*
     * The IPQM_VERDICT message is used to communicate with
     * the kernel ip queue module.
     */
    nl_header->nlmsg_type  = IPQM_VERDICT;
    nl_header->nlmsg_len   = NLMSG_LENGTH(sizeof(struct ipq_verdict_msg));
    nl_header->nlmsg_flags = (NLM_F_REQUEST);
    nl_header->nlmsg_pid   = getpid();
    nl_header->nlmsg_seq   = seq++;
    ver_data = (struct ipq_verdict_msg *)NLMSG_DATA(nl_header);
    ver_data->value = verdict;
    ver_data->id    = packet_id;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family  = AF_NETLINK;
    addr.nl_pid     = 0;
    addr.nl_groups  = 0;

    /*
     * In an effort to keep packets properly ordered,
     * the impelmentation of the protocol requires that
     * the user space application send an IPQM_VERDICT message
     * after every IPQM PACKET message is received.
     *
     */
    if(sendto(firewall_sock, (void *)nl_header, nl_header->nlmsg_len, 0,
                (struct sockaddr *)&addr, sizeof(struct sockaddr_nl)) < 0){
        perror("unable to send mode message");
        log_info(LOG_ERR, "unable to send mode message:%s", strerror(errno));
        sync(); 
        exit(0);
    }

    return 1;
}

static void interception_process(int fd)
{
    int                    diff, new_fd, i, pass_through_flag = 0;
    time_t                 now;
    unsigned long          packet_id;
    struct iphdr           *ip_header;
    struct msg_client_s    *c_msg;

    if(fd == msg_listen_sock){
        new_fd = accept(msg_listen_sock, NULL, NULL);   
        set_sock_no_delay(new_fd);
        if(new_fd != -1){
            select_server_add(new_fd);
        }
    }else if(fd == firewall_sock){
        packet_id = 0;
        ip_header = nl_firewall_recv(firewall_sock, &packet_id);
        if(ip_header != NULL){
            /* Check if it is the valid user to pass through firewall */
            for(i = 0; i < srv_settings.passed_ips.num; i++){
                if(srv_settings.passed_ips.ips[i] == ip_header->daddr){
                    pass_through_flag = 1;
                    break;
                }
            }
            if(pass_through_flag){
                /* Pass through the firewall */
                dispose_netlink_packet(NF_ACCEPT, packet_id);   
            }else{
                router_update(ip_header);
                now  = time(0);
                diff = now - last_clean_time;
                if(diff > CHECK_INTERVAL){
                    route_delete_obsolete(now);
                    delay_table_delete_obsolete(now);
                    last_clean_time = now;
                }
#if (DEBUG_TCPCOPY)
                output_debug(LOG_DEBUG, ip_header);
#endif
                 /* Drop the packet */
                dispose_netlink_packet(NF_DROP, packet_id);     
            }
        }
    }else{
        c_msg = msg_server_recv(fd);
        if(c_msg){
            if(c_msg->type == CLIENT_ADD){
#if (DEBUG_TCPCOPY)
                log_info(LOG_NOTICE, "add client router:%u", 
                        ntohs(c_msg->client_port));
#endif
                router_add(c_msg->client_ip, c_msg->client_port, fd);
            }else if(c_msg->type == CLIENT_DEL){
#if (DEBUG_TCPCOPY)
                log_info(LOG_NOTICE, "del client router:%u", 
                        ntohs(c_msg->client_port));
#endif
                router_del(c_msg->client_ip, c_msg->client_port);
            }
        }else{
            close(fd);
            select_server_del(fd);
            log_info(LOG_NOTICE, "close sock:%d", fd);
        }
    }
}

/* Initiate for tcpcopy server */
void interception_init(uint16_t port)
{
    delay_table_init(srv_settings.hash_size);
    router_init(srv_settings.hash_size << 1);
    select_server_set_callback(interception_process);
    msg_listen_sock = msg_server_init(srv_settings.binded_ip, port);
    log_info(LOG_NOTICE, "msg listen socket:%d", msg_listen_sock);
    select_server_add(msg_listen_sock);
    firewall_sock = nl_firewall_init();
    log_info(LOG_NOTICE, "firewall socket:%d", firewall_sock);
    select_server_add(firewall_sock);
}


/* Main procedure for interception */
void interception_run()
{
    select_server_run();
}

/* Clear resources for interception */
void interception_over()
{
    if(firewall_sock != -1){
        close(firewall_sock);
        firewall_sock = -1;
        log_info(LOG_NOTICE, "firewall sock is closed");
    }

    if(msg_listen_sock != -1){
        close(msg_listen_sock);
        msg_listen_sock = -1;
        log_info(LOG_NOTICE, "msg listen sock is closed");
    }
    router_destroy();
    delay_table_destroy();
}

