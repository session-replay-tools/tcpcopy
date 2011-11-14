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
	}
	return 0;
}

static unsigned short csum (unsigned short *packet, int packlen) 
{ 
	register unsigned long sum = 0; 
	while (packlen > 1) {
		sum+= *(packet++); 
		packlen-=2; 
	} 
	if (packlen > 0) 
		sum += *(unsigned char *)packet; 
	while (sum >> 16) 
		sum = (sum & 0xffff) + (sum >> 16); 
	return (unsigned short) ~sum; 
} 

static unsigned short buf[2048]; 
static unsigned short tcpcsum(unsigned char *iphdr,unsigned short *packet,
		int packlen) 
{ 
	unsigned short res; 
	memcpy(buf,iphdr+12,8); 
	*(buf+4)=htons((unsigned short)(*(iphdr+9))); 
	*(buf+5)=htons((unsigned short)packlen); 
	memcpy(buf+6,packet,packlen); 
	res = csum(buf,packlen+12); 
	return res; 
} 

/**
 * sending one ip packet(it will not go through fragmentation))
 */
uint32_t send_ip_packet(uint64_t fake_ip_addr,
		unsigned char *data,uint32_t ack_seq,uint32_t* nextSeq,
		uint32_t* sendConPackets)
{
	if(! data)
	{
		logInfo(LOG_ERR,"error ip data is null");
		return 0;
	}
	struct iphdr *ip_header = (struct iphdr *)data;
	uint16_t size_ip = ip_header->ihl<<2;
	struct tcphdr *tcp_header = (struct tcphdr *)(data+size_ip);
	tcp_header->dest = remote_port;
	ip_header->daddr = remote_ip;
	if(fake_ip_addr!=0)
	{
		tcp_header->seq=htonl(*nextSeq);
		ip_header->saddr= fake_ip_addr;
		if(tcp_header->syn)
		{
			*nextSeq=*nextSeq+1;
		}
		if(tcp_header->fin)
		{
			*nextSeq=*nextSeq+1;
		}
	}else
	{
		*nextSeq=ntohl(tcp_header->seq);
		if(tcp_header->syn)
		{
			*nextSeq=*nextSeq+1;
		}
		else if(tcp_header->fin)
		{
			*nextSeq=*nextSeq+1;
		}
	}
	if(tcp_header->ack)
	{
		tcp_header->ack_seq = ack_seq;
	}
	tcp_header->check = 0;
	uint16_t size_tcp= tcp_header->doff<<2;
	uint16_t tot_len  = ntohs(ip_header->tot_len);
	uint16_t contenLen=tot_len-size_ip-size_tcp;
	if(contenLen>0)
	{
		*nextSeq=*nextSeq+contenLen;
		*sendConPackets=*sendConPackets+1;
	}
	tcp_header->check = tcpcsum((unsigned char *)ip_header,
			(unsigned short *)tcp_header,tot_len-size_ip);
	ip_header->check = 0;
	//for linux 
	//The two fields that are always filled in are: the IP checksum 
	//(hopefully for us - it saves us the trouble) and the total length, 
	//iph->tot_len, of the datagram 
	ip_header->check = csum((unsigned short *)ip_header,size_ip); 
	outputPacketForDebug(LOG_DEBUG,SERVER_BACKEND_FLAG,ip_header,tcp_header);
	//the IP layer isn't involved at all. This has one negative effect in result
	//(although in performance it's better): no IP fragmentation will take place
	//if needed. This means that a raw packet larger than the MTU of the 
	//interface will probably be discarded. Instead ip_local_error(), 
	//which does general sk_buff cleaning,is called and an error EMSGSIZE 
	//is returned. On the other hand, normal raw socket frag
	//if tot_len is more than 1500,it will fail
	int send_len = sendto(sock,(char *)ip_header,tot_len,0,
			(struct sockaddr *)&toaddr,sizeof(toaddr));
	if(send_len == -1)
	{
		perror("send to");
		logInfo(LOG_ERR,"send to backend error,tot_len is:%d,contentlen:%d",
				tot_len,contenLen);
	}
	return send_len;

}

