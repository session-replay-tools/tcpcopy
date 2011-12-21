#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include "../log/log.h"
#include "session.h"

static int sock;
static struct sockaddr_in toaddr;

int send_init()
{
	//On Linux when setting the protocol as IPPROTO_RAW,
	//then by default the kernel sets the IP_HDRINCL option and 
	//thus does not prepend its own IP header. 
	sock = socket(AF_INET, SOCK_RAW,IPPROTO_RAW);
	if (sock>0) 
	{
		logInfo(LOG_INFO,"create ip raw socket successfully");
	} 
	else 
	{
		logInfo(LOG_ERR,"it can't create ip raw socket for sending packets");
	} 
	int n=1; 
	//tell the IP layer not to prepend its own header
	//it does not need setting for linux,but *BSD needs 
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &n, sizeof(n)) < 0) {  
		perror("IP_HDRINCL");  
		exit(1);  
	} 
	toaddr.sin_family = AF_INET;
	toaddr.sin_addr.s_addr = remote_ip;

	return 0;
}

int send_close()
{
	if(sock>0)
	{
		close(sock);
		sock=-1;
	}
	return 0;
}


/**
 * sending one ip packet(it will not go through ip fragmentation))
 */
uint32_t send_ip_packet(struct iphdr* ip_header,uint16_t tot_len)
{
	//the IP layer isn't involved at all. This has one negative effect in result
	//(although in performance it's better): no IP fragmentation will take place
	//if needed. This means that a raw packet larger than the MTU of the 
	//interface will probably be discarded. Instead ip_local_error(), 
	//which does general sk_buff cleaning,is called and an error EMSGSIZE 
	//is returned. On the other hand, normal raw socket frag
	//if tot_len is more than 1500,it will fail
	int send_len=0;
	if(sock > 0)
	{
		send_len = sendto(sock,(char *)ip_header,tot_len,0,
				(struct sockaddr *)&toaddr,sizeof(toaddr));
		if(-1 == send_len)
		{
			logInfo(LOG_ERR,"sock is:%u",sock);
			perror("send to");
		}
	}
	return send_len;

}

