#include <map>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdarg.h>
#include "session.h"
#include "send.h"
#include "../communication/msg.h"
#include "../log/log.h"
#include "address.h"

#ifdef TCPCOPY_MYSQL_ADVANCED 
#include "../mysql/protocol.h"
#endif


using std::map;

uint32_t localhost_ip;
uint32_t sample_ip;
uint32_t client_ip;
uint32_t remote_ip;
uint16_t local_port;
uint16_t remote_port;
uint16_t port_shift_factor;
uint16_t rand_shift_port;
virtual_ip_addr local_ips;


typedef map<uint64_t,session_st> SessContainer;
#if (TCPCOPY_MYSQL_ADVANCED)
typedef map<uint64_t,struct iphdr *> AuthPackContainer;
#endif
typedef map<uint64_t,uint32_t> IPContainer;
typedef map<uint16_t,dataContainer*> MysqlContainer;

typedef map<uint64_t,session_st>::iterator SessIterator;
#if (TCPCOPY_MYSQL_ADVANCED)
typedef map<uint64_t,struct iphdr *>::iterator AuthPackIterator;
#endif
typedef map<uint64_t,uint32_t>::iterator IPIterator;
typedef map<uint16_t,dataContainer*>::iterator MysqlIterator;

static SessContainer sessions;
static IPContainer trueIPContainer;
static MysqlContainer mysqlContainer;
#if (TCPCOPY_MYSQL_ADVANCED)
static AuthPackContainer firAuthPackContainer;
static AuthPackContainer secAuthPackContainer;
#endif
static uint64_t synTotal=0;
static uint64_t totalClientPackets=0;
static uint64_t activeCount=0;
static uint64_t enterCount=0;
static uint64_t leaveCount=0;
static uint64_t deleteObsoCount=0;
static uint64_t totalReconnectForClosed=0;
static uint64_t totalReconnectForNoSyn=0;
static uint64_t timeCount=0;
static uint64_t totalResponses=0;
static uint64_t totalRetransmitSuccess=0;
static uint64_t totalRequests=0;
static uint64_t totalConnections=0;
static uint64_t bakTotal=0;
static uint64_t clientTotal=0;
static uint64_t sendPackets=0;
static uint64_t globalSendConPackets=0;
static uint64_t globalConPackets=0;
static uint32_t global_total_seq_omit=0;
static double bakTotalTimes=0;
static double clientTotalTimes=0;
static struct iphdr *fir_auth_user_pack=NULL;
static time_t lastCheckDeadSessionTime=0;


/**
 * output packet info for debug
 */
void outputPacketForDebug(int level,int flag,struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
	if(global_out_level < level)
	{
		return;
	}
	struct in_addr srcaddr;
	struct in_addr destaddr;
	srcaddr.s_addr=ip_header->saddr;
	destaddr.s_addr=ip_header->daddr;
	char* tmpbuf=inet_ntoa(srcaddr);
	char sbuf[1024];
	memset(sbuf,0,1024);
	strcpy(sbuf,tmpbuf);
	char dbuf[1024];
	memset(dbuf,0,1024);
	tmpbuf=inet_ntoa(destaddr);
	strcpy(dbuf,tmpbuf);
	uint32_t packSize=ntohs(ip_header->tot_len);
	unsigned int seq=ntohl(tcp_header->seq);
	unsigned int ack_seq=ntohl(tcp_header->ack_seq);
	uint16_t window=tcp_header->window;
	if(BACKEND_FLAG==flag)
	{
		logInfo(level,"from bak:%s:%u-->%s:%u,len %u ,seq=%u,ackseq=%u,win:%u",
				sbuf,ntohs(tcp_header->source),dbuf,
				ntohs(tcp_header->dest),packSize,seq,ack_seq,window);
	}else if(CLIENT_FLAG==flag)
	{
		logInfo(level,"recv client:%s:%u-->%s:%u,len %u ,seq=%u,ack_seq=%u",
				sbuf,ntohs(tcp_header->source),dbuf,ntohs(tcp_header->dest),
				packSize,seq,ack_seq);
	}else if(SERVER_BACKEND_FLAG==flag)
	{
		logInfo(level,"to backend: %s:%u-->%s:%u,len %u ,seq=%u,ack_seq=%u",
				sbuf,ntohs(tcp_header->source),dbuf,ntohs(tcp_header->dest),
				packSize,seq,ack_seq);
	}else if(RESERVE_CLIENT_FLAG==flag)
	{
		logInfo(level,"send buf packet %s:%u-->%s:%u,len %u,seq=%u,ack_seq=%u",
				sbuf,ntohs(tcp_header->source),dbuf,ntohs(tcp_header->dest),
				packSize,seq,ack_seq);
	}else if(FAKE_CLIENT_FLAG==flag)
	{
		logInfo(level,"faked cli pack %s:%u-->%s:%u,len %u,seq=%u,ack_seq=%u",
				sbuf,ntohs(tcp_header->source),dbuf,ntohs(tcp_header->dest),
				packSize,seq,ack_seq);
	}else if(UNKNOWN_FLAG==flag)
	{
		logInfo(level,"unkown packet %s:%u-->%s:%u,len %u,seq=%u,ack_seq=%u",
				sbuf,ntohs(tcp_header->source),dbuf,ntohs(tcp_header->dest),
				packSize,seq,ack_seq);
	}else
	{
		logInfo(level,"%s:%u-->%s:%u,length %u,seq=%u,ack_seq=%u",
				sbuf,ntohs(tcp_header->source),dbuf,ntohs(tcp_header->dest),
				packSize,seq,ack_seq);
	}
}

/**
 * clear timeout tcp sessions
 */
static int clearTimeoutTcpSessions()
{
	/*
	 * we clear old sessions that recv no content response for 
	 * more than one minute. this may be a problem 
	 * for keepalive connections.
	 * so we adopt a naive method to distinguish between short-lived 
	 * and long-lived sessions(one connection represents one session)
	 */
	time_t current=time(0);
	time_t normalBase=current-60;
	time_t keepaliveBase=current-120;
	time_t tmpBase=0;
	double ratio=100.0*enterCount/(totalRequests+1);
	size_t MAXPACKETS=200;
	size_t size=0;
#if (TCPCOPY_MYSQL_BASIC)
	MAXPACKETS=2000;
#endif
	if(ratio<10)
	{
		normalBase=keepaliveBase;
		logInfo(LOG_NOTICE,"keepalive connection global");
	}
	logInfo(LOG_WARN,"session size:%u",sessions.size());
	for(SessIterator p=sessions.begin();p!=sessions.end();)
	{
		double diff=current-p->second.lastSendClientContentTime;
		if(diff < 30)
		{
#if (TCPCOPY_MYSQL_BASIC)
			logInfo(LOG_WARN,"diff < 30:%u",p->second.client_port);
#endif
			size_t unsendContPackets=0;
			size_t reqContentPackets=p->second.reqContentPackets;
			size_t sendConPackets=p->second.sendConPackets;
			if(reqContentPackets>=sendConPackets)
			{
				unsendContPackets=reqContentPackets-sendConPackets;
			}
			if(unsendContPackets<MAXPACKETS)
			{
				p++;
				continue;
			}else
			{
				logInfo(LOG_WARN,"still live,but too many unsend packets:%u",
						p->second.client_port);
			}
		}

		if(p->second.isKeepalive)
		{
			tmpBase=keepaliveBase;
		}else
		{
			tmpBase=normalBase;
		}
		size=p->second.unsend.size();
		if(size>MAXPACKETS)
		{
			if(!p->second.candidateErased)
			{
				p->second.candidateErased=1;
				logInfo(LOG_WARN,"unsend:candidate erased:%u,p:%u",
						size,p->second.client_port);
				p++;
				continue;
			}
			deleteObsoCount++;
			if(!p->second.isStatClosed)
			{
				p->second.isStatClosed=1;
			}
			activeCount--;
			logInfo(LOG_WARN,"It has too many unsend packets:%u,p:%u",
					size,p->second.client_port);
			leaveCount++;
			sessions.erase(p++);
			continue;
		}
		size=p->second.lostPackets.size();
		if(size>MAXPACKETS)
		{
			if(!p->second.candidateErased)
			{
				logInfo(LOG_WARN,"lostPackets:set candidate erased");
				p->second.candidateErased=1;
				p++;
				continue;
			}
			deleteObsoCount++;
			if(!p->second.isStatClosed)
			{
				p->second.isStatClosed=1;
			}
			activeCount--;
			logInfo(LOG_WARN,"It has too many lost packets:%u,p:%u",
					size,p->second.client_port);
			leaveCount++;
			sessions.erase(p++);
			continue;
		}
		size=p->second.handshakePackets.size();
		if(size>MAXPACKETS)
		{
			if(!p->second.candidateErased)
			{
				logInfo(LOG_WARN,"handshake:set candidate erased");
				p->second.candidateErased=1;
				p++;
				continue;
			}
			deleteObsoCount++;
			if(!p->second.isStatClosed)
			{
				p->second.isStatClosed=1;
			}
			activeCount--;
			logInfo(LOG_WARN,"It has too many handshake packets:%u,p:%u",
					size,p->second.client_port);
			leaveCount++;
			sessions.erase(p++);
			continue;
		}
		size=p->second.unAckPackets.size();
		if(size>MAXPACKETS)
		{
			if(!p->second.candidateErased)
			{
				logInfo(LOG_WARN,"handshake:set candidate erased");
				p->second.candidateErased=1;
				p++;
				continue;
			}
			deleteObsoCount++;
			if(!p->second.isStatClosed)
			{
				p->second.isStatClosed=1;
			}
			activeCount--;
			logInfo(LOG_WARN,"It has too many unAckPackets packets:%u,p:%u",
					size,p->second.client_port);
			leaveCount++;
			sessions.erase(p++);
			continue;
		}
		size=p->second.nextSessionBuffer.size();
		if(size>MAXPACKETS)
		{
			if(!p->second.candidateErased)
			{
				logInfo(LOG_WARN,"handshake:set candidate erased");
				p->second.candidateErased=1;
				p++;
				continue;
			}
			deleteObsoCount++;
			if(!p->second.isStatClosed)
			{
				p->second.isStatClosed=1;
			}
			activeCount--;
			logInfo(LOG_WARN,"It has too many future packets:%u,p:%u",
					size,p->second.client_port);
			leaveCount++;
			sessions.erase(p++);
			continue;
		}
#if (TCPCOPY_MYSQL_BASIC)
		size=p->second.mysqlSpecialPackets.size();
		if(size>MAXPACKETS)
		{
			if(!p->second.candidateErased)
			{
				logInfo(LOG_WARN,"mysql:set candidate erased");
				p->second.candidateErased=1;
				p++;
				continue;
			}
			deleteObsoCount++;
			if(!p->second.isStatClosed)
			{
				p->second.isStatClosed=1;
			}
			activeCount--;
			logInfo(LOG_WARN,"It has too many mysql packets:%u,p:%u",
					size,p->second.client_port);
			leaveCount++;
			sessions.erase(p++);
			continue;
		}
#endif
		if(p->second.lastRecvRespContentTime<tmpBase)
		{
			if(!p->second.candidateErased)
			{
				p->second.candidateErased=1;
				p++;
				continue;
			}
			deleteObsoCount++;
			if(!p->second.isStatClosed)
			{
				p->second.isStatClosed=1;
			}
			activeCount--;
			logInfo(LOG_NOTICE,"session timeout,p:%u",
					p->second.client_port);
			leaveCount++;
			size=p->second.unsend.size();
			if(size>10)
			{
				logInfo(LOG_WARN,"timeout unsend number:%u,p:%u",
						size,p->second.client_port);
			}
			sessions.erase(p++);
		}else
		{
			p++;
		}
	}
	return 0;
}

static int sendDeadTcpPacketsForSessions()
{
	logInfo(LOG_NOTICE,"sendDeadTcpPacketsForSessions");
	for(SessIterator p=sessions.begin();p!=sessions.end();p++)
	{
		if(p->second.checkSendingDeadReqs())
		{
			logInfo(LOG_WARN,"send dead reqs from global");
			p->second.sendReservedPackets();
		}else
		{
			if(p->second.retransmitSynTimes<=3)
			{
				p->second.retransmitPacket();
			}
		}
	}
}

static unsigned int seed=0;
static uint16_t getPortRandomAddition()
{
	if(0==seed)
	{
		struct timeval tp;
		gettimeofday(&tp,NULL);
		seed=tp.tv_usec;
	}
	uint16_t tmp_port_addition=(uint16_t)(4096*(rand_r(&seed)/(RAND_MAX+1.0)));
	tmp_port_addition=tmp_port_addition+1024;
	return tmp_port_addition;
}

static bool checkLocalIPValid(uint32_t ip)
{
	bool result=false;
	int i=0;
	for(;i<local_ips.num;i++)
	{
		if(ip==local_ips.ips[i])
		{
			result=true;
			break;
		}
	}
	return result;
}


static struct timeval getTime()
{
	struct timeval tp; 
	gettimeofday(&tp,NULL);
	return tp; 
}

static inline uint32_t minus_1(uint32_t seq)
{
	return htonl(ntohl(seq)-1);
}

static inline uint32_t plus_1(uint32_t seq)
{
	return htonl(ntohl(seq)+1);
}

/**
 * copy the ip packet
 */
static unsigned char* copy_ip_packet(struct iphdr *ip_header)
{
	uint16_t tot_len = ntohs(ip_header->tot_len);
	unsigned char *data = (unsigned char *)malloc(tot_len);
	if(data)
	{
		memcpy(data,ip_header,tot_len);
	}
	return data;
}

/**
 * here we adopt a naive method to recognize a retransmission packet
 * TODO to be optimized later
 */
static bool checkRetransmission(struct tcphdr *tcp_header,uint32_t oldSeq)
{
	uint32_t curSeq=ntohl(tcp_header->seq);
	if(curSeq<=oldSeq)
	{
		return true;
	}
	return false;
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
	if(packlen>4084)
	{
		logInfo(LOG_ERR,"packet is too long:%d",packlen);
		return 0;
	}
	memcpy(buf,iphdr+12,8); 
	*(buf+4)=htons((unsigned short)(*(iphdr+9))); 
	*(buf+5)=htons((unsigned short)packlen); 
	memcpy(buf+6,packet,packlen); 
	res = csum(buf,packlen+12); 
	return res; 
} 

/**
 * wrap the logInfo function 
 */
void session_st::selectiveLogInfo(int level,const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	if(logLevel!=global_out_level)
	{
		logRecordNum++;
		if(logRecordNum<100000)
		{
			logInfoForSel(LOG_WARN, fmt, args);
		}
	}else
	{
		logInfoForSel(level, fmt, args);
	}
	va_end(args);
}

/**
 * check if tcp seq is valid 
 */
static bool checkTcpSeg(struct tcphdr *tcp_header,uint32_t oldSeq)
{
	uint32_t curSeq=ntohl(tcp_header->seq);
	if(curSeq<=oldSeq)
	{
#if (DEBUG_TCPCOPY)
		logInfo(LOG_INFO,"current seq %u ,last seq:%u from client",
				curSeq,oldSeq);
#endif
		return false;
	}
	return true;
}

uint32_t session_st::wrap_send_ip_packet(uint64_t fake_ip_addr,
		unsigned char *data,uint32_t ack_seq,int isSave)
{
	if(!data)
	{
		selectiveLogInfo(LOG_ERR,"error ip data is null");
		return 0;
	}
	struct iphdr *ip_header = (struct iphdr *)data;
	uint16_t size_ip = ip_header->ihl<<2;
	struct tcphdr *tcp_header = (struct tcphdr *)(data+size_ip);

	if(isSave)
	{
		unAckPackets.push_back(copy_ip_packet(ip_header));
	}
	tcp_header->dest = remote_port;
	ip_header->daddr = remote_ip;
	if(fake_ip_addr!=0)
	{
		tcp_header->seq=htonl(nextSeq);
		tcp_header->source=fake_client_port;
		ip_header->saddr= fake_ip_addr;
		if(tcp_header->syn)
		{
			nextSeq=nextSeq+1;
		}
		if(tcp_header->fin)
		{
			nextSeq=nextSeq+1;
		}
	}else
	{
		nextSeq=ntohl(tcp_header->seq);
		if(tcp_header->syn)
		{
			nextSeq=nextSeq+1;
		}
		else if(tcp_header->fin)
		{
			nextSeq=nextSeq+1;
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
		lastSendClientContentTime=time(0);
		nextSeq=nextSeq+contenLen;
		sendConPackets=sendConPackets+1;
		if(isSave)
		{
			globalSendConPackets=globalSendConPackets+1;
		}else
		{
			isNewRetransmit=1;
		}
	}

	tcp_header->check = tcpcsum((unsigned char *)ip_header,
			(unsigned short *)tcp_header,tot_len-size_ip);
	ip_header->check = 0;
	//for linux 
	//The two fields that are always filled in are: the IP checksum 
	//(hopefully for us - it saves us the trouble) and the total length, 
	//iph->tot_len, of the datagram 
	ip_header->check = csum((unsigned short *)ip_header,size_ip); 
#if (DEBUG_TCPCOPY)
	outputPacket(LOG_DEBUG,SERVER_BACKEND_FLAG,ip_header,tcp_header);
#endif
	sendPackets++;
	uint32_t sendLen=send_ip_packet(ip_header,tot_len);
	if(-1==sendLen)
	{
		logInfo(LOG_ERR,"send to backend error,tot_len is:%d,contentlen:%d",
				tot_len,contenLen);
	}
}

/**
 * check if the packet has lost a previous packet
 */
bool session_st::checkPacketLost(struct iphdr* ip_header,
		struct tcphdr *tcp_header,uint32_t oldSeq)
{
	uint32_t curSeq=ntohl(tcp_header->seq);
	if(curSeq>oldSeq)
	{
		if(sendReservedPackets()>0)
		{
			unsend.push_back(copy_ip_packet(ip_header));
		}else
		{
#if (DEBUG_TCPCOPY)
			selectiveLogInfo(LOG_INFO,"seq in the packet:%u,expected seq:%u",
					curSeq,oldSeq);
#endif
			return true;
		}
	}
	return false;
}

/**
 * send reserved lost packets
 */
int session_st::sendReservedLostPackets()
{
	/* TODO sort the lostPackets */
	/* if not sorted,the following logic will not work for long requests */

	while(true)
	{
		int count=0;
		for(dataIterator iter=lostPackets.begin();iter!=lostPackets.end();)
		{
			unsigned char *data =*iter;
			struct iphdr *ip_header=(struct iphdr*)((char*)data);
			uint32_t size_ip = ip_header->ihl<<2;
			struct tcphdr* tcp_header = (struct tcphdr*)((char *)ip_header
					+size_ip);
			uint32_t size_tcp = tcp_header->doff<<2;
			uint32_t packSize=ntohs(ip_header->tot_len);
			uint32_t contSize=packSize-size_tcp-size_ip;
			uint32_t currentSeq=ntohl(tcp_header->seq);	
			if(nextSeq==currentSeq)
			{
				if(contSize==0)
				{
#if (DEBUG_TCPCOPY)
					selectiveLogInfo(LOG_NOTICE,"error info in lostPackets:%u",
							client_port);
#endif
				}else
				{
					isWaitResponse=1;
					isPartResponse=0;
					isResponseCompletely=0;
				}
#if (DEBUG_TCPCOPY)
				selectiveLogInfo(LOG_DEBUG,"send reserved packets for lost:%u",
						client_port);
#endif
				wrap_send_ip_packet(fake_ip_addr,data,virtual_next_sequence,1);
				if(contSize>0)
				{
					lastReqContSeq=ntohl(tcp_header->seq);
				}
				count++;
				free(data);
				lostPackets.erase(iter++);
			}else
			{
#if (DEBUG_TCPCOPY)
				selectiveLogInfo(LOG_DEBUG,"cant send packets for lost:%u",
						client_port);
#endif
				iter++;
			}
		}
		if(count==0)
		{
			break;
		}
	}
	if(lostPackets.empty())
	{
		isWaitPreviousPacket=0;
	}

	return 0;
}

/**
 * retransmit the packets to backend
 * here we only retransmit only one packet for one time
 */
int session_st::retransmitPacket()
{
	int needPause=0;
	int isSuccessful=0;
	uint32_t destSeq=nextSeq;
	dataContainer buffered;

	while(! unAckPackets.empty()&&!needPause)
	{
		unsigned char *data = unAckPackets.front();
		struct iphdr *ip_header=(struct iphdr*)((char*)data);
		uint32_t size_ip = ip_header->ihl<<2;
		struct tcphdr* tcp_header = (struct tcphdr*)((char *)ip_header+size_ip);
		if(SYN_SEND==virtual_status)
		{
			wrap_send_ip_packet(fake_ip_addr,(unsigned char *)ip_header,
				virtual_next_sequence,0);
			retransmitSynTimes++;
			break;
		}
		uint32_t size_tcp = tcp_header->doff<<2;
		uint32_t packSize=ntohs(ip_header->tot_len);
		uint32_t contSize=packSize-size_tcp-size_ip;
		uint32_t curSeq=ntohl(tcp_header->seq);  
		if(!isSuccessful)
		{
			if(curSeq==lastAckFromResponse)
			{
				isSuccessful=true;
			}else if(curSeq<lastAckFromResponse)
			{
				free(data);
				unAckPackets.pop_front();
			}else
			{
				logInfo(LOG_NOTICE,"no retransmission packets:%u",client_port);
				needPause=1;
			}
		}
		if(isSuccessful)
		{
			if(curSeq<destSeq)
			{
				wrap_send_ip_packet(fake_ip_addr,data,virtual_next_sequence,0);
				buffered.push_back(data);
				unAckPackets.pop_front();
			}else
			{
				needPause=1;	
			}
		}
	}
	
	if(!buffered.empty())
	{
		dataIterator unAckIter=unAckPackets.begin();
		for(dataIterator iter=buffered.begin();iter!=buffered.end();iter++) 
		{
			unAckPackets.insert(unAckIter,*iter);
		}
	}

	return isSuccessful;

}

/**
 * update retransmission packets
 */
int session_st::updateRetransmissionPackets()
{
	while(! unAckPackets.empty())
	{
		unsigned char *data = unAckPackets.front();
		struct iphdr *ip_header=(struct iphdr*)((char*)data);
		uint32_t size_ip = ip_header->ihl<<2;
		struct tcphdr* tcp_header = (struct tcphdr*)((char *)ip_header+size_ip);
		uint32_t curSeq=ntohl(tcp_header->seq);  
		if(curSeq<lastAckFromResponse)
		{
			free(data);
			unAckPackets.pop_front();
		}else
		{
			break;
		}
	}
	return 1;
}


/**
 * check if it needs sending dead requests
 */
bool session_st::checkSendingDeadReqs()
{
	time_t now=time(0);
	int diff=now-lastSendClientContentTime;
	size_t unsendContPackets=0;
	if(reqContentPackets>=sendConPackets)
	{
		unsendContPackets=reqContentPackets-sendConPackets;
	}
	if(diff < 2)
	{
		if(unsendContPackets<5)
		{
#if (DEBUG_TCPCOPY) 
			selectiveLogInfo(LOG_DEBUG,"f port:%u,sent=%u,tot co reqs:%u",
					client_port,sendConPackets,reqContentPackets);
#endif
			return false;
		}
	}
	if(isPartResponse)
	{
		if(unsendContPackets>0)
		{
			selectiveLogInfo(LOG_WARN,"to back:%u,size=%u,send:%u,totCRq=%u",
					client_port,lastRespPacketSize,sendConPackets,
					reqContentPackets);
		}else
		{
#if (DEBUG_TCPCOPY)
			selectiveLogInfo(LOG_DEBUG,"reqs to back:%u,psize=%u",
					client_port,lastRespPacketSize);
#endif
		}
		isWaitResponse=0;
		isPartResponse=0;
		isResponseCompletely=0;
		return true;
	}
	return false;
}

/**
 * check if the reserved container has content packet unsent
 */
bool session_st::checkReservedContainerHasContent()
{
#if (DEBUG_TCPCOPY)
	selectiveLogInfo(LOG_DEBUG,"checkReservedContainerHasContent");
#endif
	for(dataIterator iter=unsend.begin();iter!=unsend.end();iter++)
	{
		unsigned char *data =*iter;
		struct iphdr *ip_header=(struct iphdr*)((char*)data);
		uint32_t size_ip = ip_header->ihl<<2;
		struct tcphdr* tcp_header = (struct tcphdr*)((char *)ip_header+size_ip);
		uint32_t size_tcp = tcp_header->doff<<2;
		uint32_t packSize=ntohs(ip_header->tot_len);
		uint32_t contSize=packSize-size_tcp-size_ip;
		if(contSize>0)
		{
			return true;
		}
	}
	return false;
}


/**
 * send reserved packets to backend
 */
int session_st::sendReservedPackets()
{
	int needPause=0;
	int mayPause=0;
	unsigned char* prevPacket=NULL;
	uint32_t prePackSize=0;
	int count=0;
	bool isOmitTransfer=0;
	uint32_t curAck=0;
#if (TCPCOPY_MYSQL_ADVANCED)
	unsigned char* payload=NULL;
#endif

#if (DEBUG_TCPCOPY)
	selectiveLogInfo(LOG_DEBUG,"sendResPas port:%u,sent=%u,tot co reqs:%u",
	client_port,sendConPackets,reqContentPackets);
	selectiveLogInfo(LOG_DEBUG,"send reserved packets,port:%u",client_port);
#endif
	while(! unsend.empty()&&!needPause)
	{
		unsigned char *data = unsend.front();
		struct iphdr *ip_header=(struct iphdr*)((char*)data);
		uint32_t size_ip = ip_header->ihl<<2;
		struct tcphdr* tcp_header = (struct tcphdr*)((char *)ip_header+size_ip);
		uint32_t size_tcp = tcp_header->doff<<2;
		uint32_t packSize=ntohs(ip_header->tot_len);
		uint32_t contSize=packSize-size_tcp-size_ip;
		if(contSize>0)
		{
#if (TCPCOPY_MYSQL_BASIC)
			if(!isGreeingReceived)
			{
				break;
			}
#if (TCPCOPY_MYSQL_ADVANCED) 
			if(!isFirstAuthSent)
			{
				if(isGreeingReceived)
				{
					logInfo(LOG_WARN,"a mysql login req from reserved");
					payload=(unsigned char*)((char*)tcp_header+size_tcp);
					int result=change_client_auth_content(payload,contSize,
							password,scrambleBuf);
					outputPacketForDebug(LOG_WARN,CLIENT_FLAG,
								ip_header,tcp_header);
					if(!result)
					{
						isOmitTransfer=1;
						over_flag=1;
						logInfo(LOG_WARN,"it is strange here");
						needPause=1;
						break;
					}
					isFirstAuthSent=1;
					uint64_t value=get_ip_port_value(ip_header->saddr,
							tcp_header->source);
					AuthPackIterator iter = firAuthPackContainer.find(value);
					if(iter != firAuthPackContainer.end())
					{
						struct iphdr *packet=iter->second;
						free(packet);
						logInfo(LOG_WARN,"free value for fir auth:%llu",value);
					}
					struct iphdr *packet=NULL;
					packet=(struct iphdr*)copy_ip_packet(ip_header);
					firAuthPackContainer[value]=packet;
					logInfo(LOG_WARN,"set value for fir auth:%llu",value);
				}
			}else if(isFirstAuthSent&&isNeedSecondAuth)
			{
				logInfo(LOG_WARN,"a mysql second login req from reserved");
				payload=(unsigned char*)((char*)tcp_header+size_tcp);
				char encryption[16];
				memset(encryption,0,16);
				memset(seed323,0,SEED_323_LENGTH+1);
				memcpy(seed323,scrambleBuf,SEED_323_LENGTH);
				new_crypt(encryption,password,seed323);
				logInfo(LOG_WARN,"change second req:%u",client_port);
				change_client_second_auth_content(payload,contSize,encryption);
				isNeedSecondAuth=0;
				outputPacketForDebug(LOG_WARN,CLIENT_FLAG,ip_header,
						tcp_header);
				uint64_t value=get_ip_port_value(ip_header->saddr,
						tcp_header->source);
				AuthPackIterator iter = secAuthPackContainer.find(value);
				if(iter != secAuthPackContainer.end())
				{
					struct iphdr *packet=iter->second;
					free(packet);
					logInfo(LOG_WARN,"free sec auth packet from reserved:%llu",
							value);
				}
				struct iphdr *packet=NULL;
				packet=(struct iphdr*)copy_ip_packet(ip_header);
				secAuthPackContainer[value]=packet;
				logInfo(LOG_WARN,"set sec auth packet:%llu",value);
			}
#endif

#endif
			curAck=ntohl(tcp_header->ack_seq);
			if(mayPause)
			{
				if(curAck!=lastAck)
				{
#if (DEBUG_TCPCOPY)
					selectiveLogInfo(LOG_DEBUG,"cease to send:%u",
							client_port);
#endif
					break;
				}
			}
#if (DEBUG_TCPCOPY)
			selectiveLogInfo(LOG_DEBUG,"set mayPause true");
#endif
			mayPause=1;
			isWaitResponse=1;
			isPartResponse=0;
			isResponseCompletely=0;
			isRequestBegin=1;
			isRequestComletely=0;
			lastReqContSeq=ntohl(tcp_header->seq);
			lastAck=ntohl(tcp_header->ack_seq);
		}else if(tcp_header->rst){
			if(isWaitResponse)
			{
				break;
			}
			reset_flag=1;
			isOmitTransfer=0;
#if (DEBUG_TCPCOPY)
			selectiveLogInfo(LOG_DEBUG,"send reset packet to backend:%u",
					client_port);
#endif
			needPause=1;
		}else if(tcp_header->fin)
		{
			if(isWaitResponse)
			{
				break;
			}
			needPause=1;
			isOmitTransfer=1;
		}else if(0==contSize&&isWaitResponse)
		{
#if (DEBUG_TCPCOPY)
			selectiveLogInfo(LOG_DEBUG,"omit tranfer:size 0 and wait resp:%u",
					client_port);
#endif
			isOmitTransfer=1;
		}else if (0 == contSize)
		{
			if(SYN_CONFIRM != virtual_status)
			{
#if (DEBUG_TCPCOPY)
				selectiveLogInfo(LOG_DEBUG,"omit tranfer:notsynack,%u",
						client_port);
#endif
				isOmitTransfer=1;
			}
			if(isRequestBegin)
			{
				isOmitTransfer=1;
				isRequestBegin=0;
				isRequestComletely=1;
			}
		}

		if(!isOmitTransfer)
		{
			count++;
			wrap_send_ip_packet(fake_ip_addr,data,virtual_next_sequence,1);
		}
		free(data);
		unsend.pop_front();
		if(isOmitTransfer)
		{
			if(isWaitResponse)
			{
#if (DEBUG_TCPCOPY)
				selectiveLogInfo(LOG_DEBUG,"cease to send reserved packs:%u",
						client_port);
#endif
				break;
			}
		}
		isOmitTransfer=0;
	}
	return count;
}

/**
 * save header info for later use
 */
void session_st::save_header_info(struct iphdr *ip_header,
		struct tcphdr *tcp_header){                                      
	client_ip_id = ip_header->id;
	tcp_header->window=65535;
}

/**
 * wrap the outputPacketForDebug function 
 */
void session_st::outputPacket(int level,int flag,struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
	if(logLevel!=global_out_level)
	{
		outputPacketForDebug(LOG_WARN,flag,ip_header,tcp_header);
	}else
	{
		outputPacketForDebug(level,flag,ip_header,tcp_header);
	}
}


/**
 * send faked syn packet for backend for intercepting already connected packets
 */
void session_st::sendFakedSynToBackend(struct iphdr* ip_header,
		struct tcphdr* tcp_header)
{
	isHalfWayIntercepted=1;
	isBackSynReceived=0;

	unsigned char fake_syn_buf[FAKE_SYN_BUF_SIZE];
	memset(fake_syn_buf,0,FAKE_SYN_BUF_SIZE);
	struct iphdr *f_ip_header = (struct iphdr *)fake_syn_buf;
	struct tcphdr *f_tcp_header = (struct tcphdr *)(fake_syn_buf+20);

#if (DEBUG_TCPCOPY)
	selectiveLogInfo(LOG_DEBUG,"sendFakedSynToBackend:%u",client_port);
	selectiveLogInfo(LOG_DEBUG,"unsend size:%u",unsend.size());
#endif
	f_ip_header->version = 4;
	f_ip_header->ihl = 5;
	f_ip_header->tot_len = htons(FAKE_SYN_BUF_SIZE);
	f_ip_header->frag_off = 64; 
	f_ip_header->ttl = 64; 
	f_ip_header->protocol = 6;
	f_ip_header->id= htons(client_ip_id+2);;
	f_ip_header->saddr = ip_header->saddr;
	f_ip_header->daddr = ip_header->daddr;
	f_tcp_header->doff= 8;
	f_tcp_header->source = tcp_header->source;
	f_tcp_header->dest= tcp_header->dest;
	f_tcp_header->syn=1;
	f_tcp_header->seq = minus_1(tcp_header->seq);
	f_tcp_header->window= 65535;
	virtual_next_sequence=tcp_header->seq;
	unsigned char *data=copy_ip_packet(f_ip_header);
	handshakePackets.push_back(data);
#if (TCPCOPY_MYSQL_BASIC)
	isPureRequestBegin=1;
	struct iphdr *fir_auth_packet=fir_auth_user_pack;
#if (TCPCOPY_MYSQL_ADVANCED)
	struct iphdr *sec_auth_packet=NULL;
	uint64_t value=get_ip_port_value(ip_header->saddr,
			tcp_header->source);
	AuthPackIterator authIter= firAuthPackContainer.find(value);
	if(authIter!= firAuthPackContainer.end())
	{
		fir_auth_packet=authIter->second;
	}
	AuthPackIterator secAuthIter=secAuthPackContainer.find(value);
	if(secAuthIter != secAuthPackContainer.end())
	{
		sec_auth_packet=secAuthIter->second;
	}
#endif
	if(fir_auth_packet)
	{
		struct iphdr* fir_ip_header=NULL;
		struct tcphdr* fir_tcp_header=NULL;
		fir_ip_header=(struct iphdr*)copy_ip_packet(fir_auth_packet);
		fir_ip_header->saddr=f_ip_header->saddr;
		size_t size_ip= fir_ip_header->ihl<<2;
		size_t total_len= ntohs(fir_ip_header->tot_len);
		fir_tcp_header=(struct tcphdr*)((char *)fir_ip_header+size_ip);
		size_t size_tcp= fir_tcp_header->doff<<2;
		size_t fir_cont_len=total_len-size_ip-size_tcp;
		fir_tcp_header->source=f_tcp_header->source;
		unsend.push_back((unsigned char*)fir_ip_header);
		total_seq_omit=global_total_seq_omit;
#if (TCPCOPY_MYSQL_ADVANCED)
		struct iphdr* sec_ip_header=NULL;
		struct tcphdr* sec_tcp_header=NULL;
		size_t sec_cont_len=0;
		if(sec_auth_packet!=NULL)
		{
			sec_ip_header=(struct iphdr*)copy_ip_packet(sec_auth_packet);
			sec_ip_header->saddr=f_ip_header->saddr;
			size_ip= sec_ip_header->ihl<<2;
			total_len= ntohs(sec_ip_header->tot_len);
			sec_tcp_header=(struct tcphdr*)((char *)sec_ip_header+size_ip);
			size_tcp= sec_tcp_header->doff<<2;
			sec_cont_len=total_len-size_ip-size_tcp;
			sec_tcp_header->source=f_tcp_header->source;
			unsend.push_back((unsigned char*)sec_ip_header);
			logInfo(LOG_WARN,"set second auth for no skip");
		}else
		{
			logInfo(LOG_WARN,"no sec auth packet here");
		}
#endif
#if (TCPCOPY_MYSQL_ADVANCED)
		uint32_t total_cont_len=fir_cont_len+sec_cont_len;	
#else
		uint32_t total_cont_len=fir_cont_len;
#endif
		MysqlIterator mysqlIter=mysqlContainer.find(client_port);
		dataContainer* datas=NULL;
		struct iphdr* tmp_ip_header=NULL;
		struct tcphdr* tmp_tcp_header=NULL;
		//TODO to be removed later
		if(mysqlIter!= mysqlContainer.end())
		{
			datas=mysqlIter->second;
			//check if we insert COM_STMT_PREPARE statements 
			for(dataIterator iter=datas->begin();
					iter!=datas->end();iter++)
			{
				unsigned char *data =*iter;
				tmp_ip_header=(struct iphdr *)data;
				size_ip= tmp_ip_header->ihl<<2;
				total_len= ntohs(tmp_ip_header->tot_len);
				tmp_tcp_header=(struct tcphdr*)((char *)tmp_ip_header
						+size_ip); 
				size_tcp= tmp_tcp_header->doff<<2;
				size_t tmpContentLen=total_len-size_ip-size_tcp;
				total_cont_len+=tmpContentLen;
			}
		}

#if (DEBUG_TCPCOPY)
		selectiveLogInfo(LOG_INFO,"total len needs to be subtracted:%u",
				total_cont_len);
#endif
		f_tcp_header->seq=htonl(ntohl(f_tcp_header->seq)-total_cont_len);
		fir_tcp_header->seq=plus_1(f_tcp_header->seq);
#if (TCPCOPY_MYSQL_ADVANCED)
		if(sec_tcp_header!=NULL)
		{
			sec_tcp_header->seq=htonl(ntohl(fir_tcp_header->seq)+fir_cont_len);
		}
#endif
#if (TCPCOPY_MYSQL_ADVANCED)
		uint32_t baseSeq=ntohl(fir_tcp_header->seq)+fir_cont_len+sec_cont_len;
#else
		uint32_t baseSeq=ntohl(fir_tcp_header->seq)+fir_cont_len;
#endif
		if(mysqlIter!= mysqlContainer.end())
		{
			datas=mysqlIter->second;
			//check if we insert COM_STMT_PREPARE statements 
			for(dataIterator iter=datas->begin();
					iter!=datas->end();iter++)
			{
				unsigned char *data =*iter;
				tmp_ip_header=(struct iphdr *)data;
				tmp_ip_header=(struct iphdr*)copy_ip_packet(tmp_ip_header);
				size_ip= tmp_ip_header->ihl<<2;
				total_len= ntohs(tmp_ip_header->tot_len);
				tmp_tcp_header=(struct tcphdr*)((char *)tmp_ip_header
						+size_ip); 
				size_tcp= tmp_tcp_header->doff<<2;
				size_t tmpContentLen=total_len-size_ip-size_tcp;
				tmp_tcp_header->seq=htonl(baseSeq);
				unsend.push_back((unsigned char*)tmp_ip_header);
				total_cont_len+=tmpContentLen;
				baseSeq+=tmpContentLen;
			}
		}
	}else
	{
		logInfo(LOG_WARN,"no auth packets here");
	}
#endif

#if (DEBUG_TCPCOPY)
	outputPacket(LOG_DEBUG,FAKE_CLIENT_FLAG,f_ip_header,f_tcp_header);
	selectiveLogInfo(LOG_DEBUG,"send faked syn to back,client win:%u",
			f_tcp_header->window);
#endif
	wrap_send_ip_packet(fake_ip_addr,fake_syn_buf,virtual_next_sequence,1);
}

/**
 * send faked syn ack packet to backend for handshake
 */
void session_st::sendFakedSynAckToBackend(struct iphdr* ip_header,
		struct tcphdr* tcp_header)
{
	unsigned char fake_ack_buf[40];
	memset(fake_ack_buf,0,40);
	struct iphdr *f_ip_header = (struct iphdr *)fake_ack_buf;
	struct tcphdr *f_tcp_header = (struct tcphdr *)(fake_ack_buf+20);
#if (DEBUG_TCPCOPY)
	selectiveLogInfo(LOG_DEBUG,"sendFakedSynAckToBackend:%u",client_port);
#endif
	f_ip_header->version = 4;
	f_ip_header->ihl = 5;
	f_ip_header->tot_len = htons(40);
	f_ip_header->frag_off = 64; 
	f_ip_header->ttl = 64; 
	f_ip_header->protocol = 6;
	f_ip_header->id= htons(client_ip_id+2);;
	f_ip_header->saddr = client_ip_addr;
	f_ip_header->daddr = local_dest_ip_addr; 
	f_tcp_header->doff= 5;
	f_tcp_header->source = tcp_header->dest;
	f_tcp_header->dest= local_port;
	f_tcp_header->ack=1;
	f_tcp_header->ack_seq = virtual_next_sequence;
	f_tcp_header->seq = tcp_header->ack_seq;
	f_tcp_header->window= 65535;
	unsigned char *data=copy_ip_packet(f_ip_header);
	handshakePackets.push_back(data);
#if (DEBUG_TCPCOPY)
	outputPacket(LOG_DEBUG,FAKE_CLIENT_FLAG,f_ip_header,f_tcp_header);
#endif
	wrap_send_ip_packet(fake_ip_addr,fake_ack_buf,virtual_next_sequence,1);
}

/**
 * send faked ack packet to backend 
 */
void session_st::sendFakedAckToBackend(struct iphdr* ip_header,
		struct tcphdr* tcp_header,bool changeSeq)
{
	unsigned char fake_ack_buf[40];
	memset(fake_ack_buf,0,40);
	struct iphdr *f_ip_header = (struct iphdr *)fake_ack_buf;
	struct tcphdr *f_tcp_header = (struct tcphdr *)(fake_ack_buf+20);
	f_ip_header->version = 4;
	f_ip_header->ihl = 5;
	f_ip_header->tot_len = htons(40);
	f_ip_header->frag_off = 64; 
	f_ip_header->ttl = 64; 
	f_ip_header->protocol = 6;
	f_ip_header->id= htons(client_ip_id+2);;
	f_ip_header->saddr = ip_header->daddr;
	f_tcp_header->doff= 5;
	f_tcp_header->source = tcp_header->dest;
	f_tcp_header->ack=1;
	f_tcp_header->ack_seq = virtual_next_sequence;
	if(changeSeq)
	{
		f_tcp_header->seq = htonl(nextSeq);
	}else
	{
		f_tcp_header->seq = tcp_header->ack_seq;
	}
	f_tcp_header->window= 65535;
#if (DEBUG_TCPCOPY)
	selectiveLogInfo(LOG_INFO,"send faked ack to backend,client win:%u",
			f_tcp_header->window);
#endif
	wrap_send_ip_packet(fake_ip_addr,fake_ack_buf,virtual_next_sequence,1);
}

/**
 * send faked fin to backend according to the backend packet
 */
void session_st::sendFakedFinToBackend(struct iphdr* ip_header,
		struct tcphdr* tcp_header)
{
#if (DEBUG_TCPCOPY)
	selectiveLogInfo(LOG_DEBUG,"send faked fin To Back:%u",client_port);
#endif
	unsigned char fake_fin_buf[40];
	memset(fake_fin_buf,0,40);
	struct iphdr *f_ip_header = (struct iphdr *)fake_fin_buf;
	struct tcphdr *f_tcp_header = (struct tcphdr *)(fake_fin_buf+20);
	f_ip_header->version = 4;
	f_ip_header->ihl = 5;
	f_ip_header->tot_len = htons(40);
	f_ip_header->frag_off = 64; 
	f_ip_header->ttl = 64; 
	f_ip_header->protocol = 6;
	f_ip_header->id= htons(client_ip_id+2);;
	f_ip_header->saddr = ip_header->daddr;
	f_tcp_header->doff= 5;
	f_tcp_header->source = tcp_header->dest;
	f_tcp_header->rst=1;
	f_tcp_header->ack=1;
	reset_flag=1;
	uint16_t size_ip = ip_header->ihl<<2; 
	uint16_t size_tcp= tcp_header->doff<<2;
	uint16_t tot_len  = ntohs(ip_header->tot_len);
	uint16_t contenLen=tot_len-size_ip-size_tcp;
	uint32_t seq=ntohl(tcp_header->seq);
	uint32_t expectedSeq=ntohl(virtual_next_sequence);
	if(contenLen>0){   
		uint32_t next_ack= htonl(seq+contenLen); 
		f_tcp_header->ack_seq = next_ack;
	}else
	{
		if(isClientClosed&&!isTestConnClosed)
		{
			if(seq>expectedSeq)
			{
				logInfo(LOG_NOTICE,"set virtual_next_sequence larger");
				virtual_next_sequence=tcp_header->seq;
				isTestConnClosed=true;
			}
			f_tcp_header->fin =0;
		}
		f_tcp_header->ack_seq = virtual_next_sequence;
	}
	f_tcp_header->seq = tcp_header->ack_seq;
	f_tcp_header->window= 65535;
	wrap_send_ip_packet(fake_ip_addr,fake_fin_buf,virtual_next_sequence,1);
}

/**
 * send faked fin to backend according to the client packet
 */
void session_st::sendFakedFinToBackByCliePack(struct iphdr* ip_header,
		struct tcphdr* tcp_header)
{
#if (DEBUG_TCPCOPY)
	selectiveLogInfo(LOG_DEBUG,"send faked fin To Back from cli pack:%u",
			client_port);
#endif
	unsigned char fake_fin_buf[40];
	memset(fake_fin_buf,0,40);
	struct iphdr *f_ip_header = (struct iphdr *)fake_fin_buf;
	struct tcphdr *f_tcp_header = (struct tcphdr *)(fake_fin_buf+20);
	f_ip_header->version = 4;
	f_ip_header->ihl = 5;
	f_ip_header->tot_len = htons(40);
	f_ip_header->frag_off = 64; 
	f_ip_header->ttl = 64; 
	f_ip_header->protocol = 6;
	f_ip_header->id= htons(client_ip_id+2);;
	f_ip_header->saddr = ip_header->saddr;
	f_tcp_header->doff= 5;
	f_tcp_header->source = tcp_header->source;
	f_tcp_header->fin =1;
	f_tcp_header->rst =1;
	f_tcp_header->ack=1;
	
	f_tcp_header->ack_seq = virtual_next_sequence;
	if(isClientClosed)
	{
		f_tcp_header->seq =htonl(nextSeq-1); 
	}else
	{
		f_tcp_header->seq =htonl(nextSeq); 
	}
	f_tcp_header->window= 65535;
	wrap_send_ip_packet(fake_ip_addr,fake_fin_buf,virtual_next_sequence,1);
}

/**
 * establish a connection for intercepting already connected packets
 */
void session_st::establishConnectionForNoSynPackets(struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
#if (TCPCOPY_MYSQL_BASIC)
	selectiveLogInfo(LOG_WARN,"establish conn for already connected:%u",
			client_port);
#else
	selectiveLogInfo(LOG_DEBUG,"establish conn for already connected:%u",
			client_port);
#endif
	int sock=address_find_sock(tcp_header->dest);
	if(-1 == sock)
	{
		selectiveLogInfo(LOG_WARN,"sock invalid in est Conn for NoSynPacks");
		outputPacket(LOG_WARN,CLIENT_FLAG,ip_header,tcp_header);
		return;
	}
	int result=msg_copyer_send(sock,ip_header->saddr,
			tcp_header->source,CLIENT_ADD);
	if(-1 == result)
	{
		selectiveLogInfo(LOG_ERR,"msg copyer send error");
		return;
	}
	sendFakedSynToBackend(ip_header,tcp_header);
	isSynIntercepted=1;
	activeCount++;
	totalReconnectForNoSyn++;

}

/**
 * establish a connection for already closed connection
 * Attension:
 *   if the server does the active close,it lets a client and server 
 *   continually reuse the same port number at each end for successive 
 *   incarnations of the same connection
 */
void session_st::establishConnectionForClosedConn()
{
#if (DEBUG_TCPCOPY)
	selectiveLogInfo(LOG_INFO,"reestablish connection for keepalive:%u",
			client_port);
#endif
	size_t size=handshakePackets.size();
	if(size!=handshakeExpectedPackets)
	{
		selectiveLogInfo(LOG_WARN,"hand Packets size not expected:%u,exp:%u",
				size,handshakeExpectedPackets);
	}else
	{
		unsigned char *data = handshakePackets.front();
		struct iphdr *ip_header = (struct iphdr*)data;
		unsigned char* tmpData=copy_ip_packet(ip_header);
		ip_header=(struct iphdr*)tmpData;
		size_t size_ip = ip_header->ihl<<2;
		struct tcphdr *tcp_header = (struct tcphdr*)((char *)ip_header+size_ip);
		int sock=address_find_sock(local_port);
		if(-1 == sock)
		{
			free(tmpData);
			selectiveLogInfo(LOG_WARN,"sock invalid estConnForClosedConn");
#if (DEBUG_TCPCOPY)
			outputPacket(LOG_INFO,CLIENT_FLAG,ip_header,tcp_header);
#endif
			return;
		}
		if(0 == fake_ip_addr)
		{
			client_ip_addr=ip_header->saddr;
		}else
		{
#if (DEBUG_TCPCOPY)
			selectiveLogInfo(LOG_DEBUG,"erase fake_ip_addr");
#endif
			trueIPContainer.erase(get_ip_port_value(fake_ip_addr,
						tcp_header->source));
		}
		fake_ip_addr=ip_header->saddr;
		uint16_t tmp_port_addition=getPortRandomAddition();
		uint16_t transfered_port=ntohs(tcp_header->source);
		if(transfered_port<=(65535-tmp_port_addition))
		{
			transfered_port=transfered_port+tmp_port_addition;
		}else
		{
			transfered_port=32768+tmp_port_addition;
		}
		tcp_header->source=htons(transfered_port);
		fake_client_port=htons(transfered_port);
#if (TCPCOPY_MYSQL_ADVANCED)
		selectiveLogInfo(LOG_WARN,"change port");
#endif
#if (DEBUG_TCPCOPY)
		selectiveLogInfo(LOG_INFO,"change port,add port:%u",tmp_port_addition);
#endif
		uint64_t key=get_ip_port_value(fake_ip_addr,tcp_header->source);
		trueIPContainer[key]=client_ip_addr;

		ip_header->saddr=fake_ip_addr;
		int result=msg_copyer_send(sock,ip_header->saddr,
				tcp_header->source,CLIENT_ADD);
		if(-1 == result)
		{
			free(tmpData);
			selectiveLogInfo(LOG_ERR,"msg copyer send error");
			return;
		}
		wrap_send_ip_packet(fake_ip_addr,data,virtual_next_sequence,1);
		isSynIntercepted=1;
		free(tmpData);
		//push remaining packets in handshakePackets to unsend
		int i=0;
		for(dataIterator iter=handshakePackets.begin();
				iter!=handshakePackets.end();iter++)
		{
			if(i>0)
			{
				unsigned char *data =*iter;
				ip_header=(struct iphdr *)data;
				ip_header->saddr=fake_ip_addr;
				size_ip = ip_header->ihl<<2;
				tcp_header=(struct tcphdr*)((char *)ip_header+size_ip);
				tcp_header->source=fake_client_port;
				unsend.push_back(copy_ip_packet(ip_header));
			}
			i++;
		}
		totalReconnectForClosed++;
	}
}

/**
 * check if the packet is needed for reconnection by mysql tcpcopy
 */
bool session_st::checkMysqlPacketNeededForReconnection(struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
	uint32_t size_ip = ip_header->ihl<<2;
	uint32_t size_tcp = tcp_header->doff<<2;
	uint32_t packSize=ntohs(ip_header->tot_len);
	uint32_t contSize=packSize-size_tcp-size_ip;

	if(contSize>0)
	{
		unsigned char* payload;
		payload=(unsigned char*)((char*)tcp_header+size_tcp);
		//skip  Packet Length
		payload=payload+3;
		//skip  Packet Number
		payload=payload+1;
		unsigned char command=payload[0];
		if(COM_STMT_PREPARE == command||
				(hasPrepareStat&&isExcuteForTheFirstTime))
		{
			if(COM_STMT_PREPARE == command)
			{
				hasPrepareStat=1;
			}else
			{
				if(COM_QUERY == command&&hasPrepareStat)
				{
					if(numberOfExcutes>0)
					{
						isExcuteForTheFirstTime=0;
					}
					numberOfExcutes++;
				}
				if(!isExcuteForTheFirstTime)
				{
					return false;
				}
			}
			unsigned char *data=copy_ip_packet(ip_header);
			mysqlSpecialPackets.push_back(data);
#if (DEBUG_TCPCOPY)
			selectiveLogInfo(LOG_WARN,"push back necc statement:%u",
					client_port);
#endif
			MysqlIterator iter=mysqlContainer.find(client_port);
			dataContainer* datas=NULL;
			if(iter!= mysqlContainer.end())
			{
				datas=iter->second;
			}else
			{
				datas=new dataContainer();
				mysqlContainer[client_port]=datas;
			}
			data=copy_ip_packet(ip_header);
			datas->push_back(data);

			return true;
		}
	}
	return false;
}

/**
 * check if the packet is the right packet for  starting a new session 
 * by mysql tcpcopy
 */
static bool checkPacketPaddingForMysql(struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
	uint32_t size_ip = ip_header->ihl<<2;
	uint32_t size_tcp = tcp_header->doff<<2;
	uint32_t packSize=ntohs(ip_header->tot_len);
	uint32_t contSize=packSize-size_tcp-size_ip;

	if(contSize>0)
	{
		unsigned char* payload;
		payload=(unsigned char*)((char*)tcp_header+size_tcp);
		//skip  Packet Length
		payload=payload+3;
		unsigned char packetNumber=payload[0];
		//if it is the second authenticate_user,then skip it
		if(0!=packetNumber)
		{
			return false;
		}
		//skip Packet Number
		payload=payload+1;
		unsigned char command=payload[0];
		if(COM_QUERY == command)
		{
#if (DEBUG_TCPCOPY)
			logInfo(LOG_DEBUG,"this is query command");
#endif
			return true;
		}
	}
	return false;
}

/**
 * check if the packet is the right packet for noraml tcpcopy
 */
static bool checkPacketPadding(struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
	uint32_t size_ip = ip_header->ihl<<2;
	uint32_t size_tcp = tcp_header->doff<<2;
	uint32_t packSize=ntohs(ip_header->tot_len);
	uint32_t contSize=packSize-size_tcp-size_ip;

	if(contSize>0)
	{
		return true;
	}
	return false;

}

/**
 * processing backend packets
 */
void session_st::update_virtual_status(struct iphdr *ip_header,
		struct tcphdr* tcp_header)
{
#if (DEBUG_TCPCOPY)
	outputPacket(LOG_DEBUG,BACKEND_FLAG,ip_header,tcp_header);
#endif
	if( tcp_header->rst)
	{
		reset_flag = true;
#if (DEBUG_TCPCOPY)
		selectiveLogInfo(LOG_INFO,"reset from backend:%u",client_port);
#endif
		return;
	}
	virtual_ack = tcp_header->ack_seq;
	uint32_t ack=ntohl(tcp_header->ack_seq);
	uint32_t tot_len = ntohs(ip_header->tot_len);
	uint32_t size_ip = ip_header->ihl<<2;
	uint32_t size_tcp = tcp_header->doff<<2;
	uint32_t contSize=tot_len-size_tcp-size_ip;
	time_t current=time(0);
#if (TCPCOPY_MYSQL_ADVANCED)
	unsigned char* payload=NULL;
#endif
	if(contSize>0)
	{
		if(isNewRetransmit)
		{
			totalRetransmitSuccess++;
			isNewRetransmit=0;
		}
		respContentPackets++;
		lastRecvRespContentTime=current;
	}
	if(ack > nextSeq)
	{
#if (DEBUG_TCPCOPY)
		selectiveLogInfo(LOG_INFO,"ack back more than nextSeq:%u,%u,p:%u",
				ack,nextSeq,client_port);
#endif
		if(!isBackSynReceived)
		{
#if (DEBUG_TCPCOPY)
			selectiveLogInfo(LOG_INFO,"not recv back syn,p:%u",client_port);
#endif
			reset_flag = true;
			return;
		}
		nextSeq=ack;
	}else if(ack <nextSeq)
	{
#if (DEBUG_TCPCOPY)
		selectiveLogInfo(LOG_INFO,"ack back less than nextSeq:%u,%u, p:%u",
				ack,nextSeq,client_port);
#endif
		if(!isBackSynReceived)
		{
			virtual_next_sequence =tcp_header->seq;
			sendFakedFinToBackend(ip_header,tcp_header);
			isFakedSendingFinToBackend=1;
			isClientClosed=1;
			return;
		}
		if(isClientClosed&&!tcp_header->fin)
		{
			sendFakedFinToBackend(ip_header,tcp_header);
			return;
		}else
		{
			/* simulaneous close*/
			if(isClientClosed&&tcp_header->fin)
			{
				simulClosing=1;
			}
		}
		if(0 == contSize&&!tcp_header->fin)
		{
			if(lastAckFromResponse!=0)
			{
				if(ack==lastAckFromResponse)
				{
					lastSameAckTotal++;
					if(lastSameAckTotal>1)
					{
						/* it needs retransmission*/
						selectiveLogInfo(LOG_WARN,"backend lost packets:%u",
								client_port);
						if(!alreadyRetransmit)
						{
							if(!retransmitPacket())
							{
								sendFakedFinToBackend(ip_header,tcp_header);
								isFakedSendingFinToBackend=1;
								isClientClosed=1;
							}
							alreadyRetransmit=1;
						}else
						{
							selectiveLogInfo(LOG_WARN,"omit retransmit:%u",
								client_port);
						}
						return;
					}
				}else
				{
					lastSameAckTotal=0;
					alreadyRetransmit=0;
#if (DEBUG_TCPCOPY)
					selectiveLogInfo(LOG_DEBUG,"ack is not equal to last ack");
#endif
				}
			}else
			{
#if (DEBUG_TCPCOPY)
				selectiveLogInfo(LOG_DEBUG,"lastSameAckTotal is zero");
#endif
			}
		}
	}
	lastAckFromResponse=ack;
	updateRetransmissionPackets();

	if( tcp_header->syn)
	{
		if(isBackSynReceived)
		{
#if (DEBUG_TCPCOPY)
			selectiveLogInfo(LOG_DEBUG,"recv syn from back again");
#endif
		}else
		{
			totalConnections++;
			isBackSynReceived=1;
#if (DEBUG_TCPCOPY)
			selectiveLogInfo(LOG_DEBUG,"recv syn from back:%u",
					client_port);
#endif
		}
		virtual_next_sequence = plus_1(tcp_header->seq);
		virtual_status = SYN_CONFIRM;
		if(isHalfWayIntercepted)
		{
			sendFakedSynAckToBackend(ip_header,tcp_header);
			sendReservedPackets();
		}else
		{
			sendReservedPackets();
		}
		lastRespPacketSize=tot_len;
		return;
	}
	else if(tcp_header->fin)
	{
#if (DEBUG_TCPCOPY)
		selectiveLogInfo(LOG_INFO,"recv fin from back:%u",client_port);
#endif
		isTestConnClosed=1;
		isWaitResponse=0;
		isTrueWaitResponse=0;
		isResponseCompletely=1;
		virtual_status  |= SERVER_FIN;
		if(contSize>0)
		{
			virtual_next_sequence=htonl(ntohl(tcp_header->seq)+contSize+1);
		}else
		{
			virtual_next_sequence = plus_1(tcp_header->seq);
		}
		sendFakedAckToBackend(ip_header,tcp_header,simulClosing);
		if(!isClientClosed)
		{
			/* send constructed server fin to the backend */
			sendFakedFinToBackend(ip_header,tcp_header);
			isFakedSendingFinToBackend=1;
			virtual_status |= CLIENT_FIN;
			confirmed=1;
		}else
		{
			over_flag=1;
		}
		return;
	}else if(tcp_header->ack)
	{
		if(isClientClosed&&isTestConnClosed)
		{
			over_flag=1;
			return;
		}
		if(isWaitResponse)
		{
			if(!isTrueWaitResponse)
			{
				totalRequests++;
			}
			isTrueWaitResponse=1;
		}
		
	}
	if(!isBackSynReceived)
	{
		virtual_next_sequence =tcp_header->seq;;
		sendFakedFinToBackend(ip_header,tcp_header);
		isFakedSendingFinToBackend=1;
		isClientClosed=1;
		return;
	}
	uint32_t next_seq = htonl(ntohl(tcp_header->seq)+contSize);
	bool isGreetReceivedPacket=0; 
	
#if (DEBUG_TCPCOPY)
	selectiveLogInfo(LOG_DEBUG,"cont size:%d",contSize);
#endif
	//it is nontrivial to check if the packet is the last packet of response
	//the following is not 100 percent right here
	if(contSize>0)
	{
		virtual_next_sequence =next_seq;
		if(isClientClosed)
		{
			sendFakedFinToBackend(ip_header,tcp_header);
			return;
		}

		if(!candidateErased)
		{
#if (TCPCOPY_MYSQL_BASIC)
			if(!isGreeingReceived)
			{
#if (DEBUG_TCPCOPY)
				selectiveLogInfo(LOG_INFO,"recv greeting from back");
#endif
				contPacketsFromGreet=0;
				isGreeingReceived=1;
				isGreetReceivedPacket=1;
#if (TCPCOPY_MYSQL_ADVANCED) 
				payload=(unsigned char*)((char*)tcp_header+
						sizeof(struct tcphdr));
				memset(scrambleBuf,0,SCRAMBLE_LENGTH+1);
				int result=parse_handshake_init_content(payload,
						contSize,scrambleBuf);
				selectiveLogInfo(LOG_WARN,"scramble:%s,p:%u",
						scrambleBuf,client_port);
				if(!result)
				{
					if(contSize>11)
					{
						outputPacketForDebug(LOG_WARN,BACKEND_FLAG,
								ip_header,tcp_header);
						selectiveLogInfo(LOG_WARN,"port:%u,payload:%s",
								client_port,(char*)(payload+11));
					}
					over_flag=1;
					return;
				}
#endif
			}else{
#if (TCPCOPY_MYSQL_ADVANCED) 
				if(0==contPacketsFromGreet)
				{
#if (DEBUG_TCPCOPY)
					selectiveLogInfo(LOG_INFO,"check if needs second auth");
#endif
					payload=(unsigned char*)((char*)tcp_header+
							sizeof(struct tcphdr));
					if(isLastDataPacket(payload))
					{
						outputPacketForDebug(LOG_WARN,BACKEND_FLAG,
								ip_header,tcp_header);
						selectiveLogInfo(LOG_WARN,"it needs second auth:%u",
								client_port);
						isNeedSecondAuth=1;
					}
				}
#endif
				contPacketsFromGreet++;
			}
#endif
			isPartResponse=1;

			{
#if (DEBUG_TCPCOPY)
				selectiveLogInfo(LOG_DEBUG,"receive from backend");
#endif
#if (!TCPCOPY_MYSQL_BASIC)
				sendFakedAckToBackend(ip_header,tcp_header,true);
#endif
				if(isWaitResponse||isGreetReceivedPacket)
				{
#if (DEBUG_TCPCOPY)
					selectiveLogInfo(LOG_DEBUG,"receive back server's resp");
#endif
					totalResponses++;
					isResponseCompletely=1;
					isWaitResponse=0;
					isTrueWaitResponse=0;
					virtual_next_sequence =next_seq;
					virtual_status = SEND_RESPONSE_CONFIRM;
					responseReceived++;
					sendReservedPackets();
					lastRespPacketSize=tot_len;
					return;
				}
			}
		}
	}else
	{
		if(isClientClosed&&!isTestConnClosed)
		{
			sendFakedFinToBackend(ip_header,tcp_header);
		}
	}
	virtual_next_sequence= next_seq;
	if(candidateErased)
	{
		if(!isClientClosed)
		{
#if (DEBUG_TCPCOPY)
			selectiveLogInfo(LOG_INFO,"candidate erased true:%u",
					client_port);
#endif
			/* send constructed server fin to the backend */
			sendFakedFinToBackend(ip_header,tcp_header);
			isFakedSendingFinToBackend=1;
			isClientClosed=1;
#if (DEBUG_TCPCOPY)
			selectiveLogInfo(LOG_INFO,"set client closed flag:%u",
					client_port);
#endif
		}
	}
	lastRespPacketSize=tot_len;

}

/**
 * processing client packets
 * TODO
 * TCP is always allowed to send 1 byte of data 
 * beyond the end of a closed window which confuses tcpcopy
 * It will be resolved later
 * 
 */
void session_st::process_recv(struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
#if (DEBUG_TCPCOPY)
	outputPacket(LOG_DEBUG,CLIENT_FLAG,ip_header,tcp_header);
#endif	
	if(SYN_SEND==virtual_status)
	{
		time_t now=time(0);
		int diff=now-createTime;
		if(diff>3)
		{
			//retransmit the first syn packet 
			retransmitPacket();
			createTime=now;
		}
	}
	if(hasMoreNewSession)
	{
		nextSessionBuffer.push_back(copy_ip_packet(ip_header));

#if (DEBUG_TCPCOPY)
		logInfo(LOG_INFO,"buffer the packet for next session:%u",client_port);
#endif
		return;
	}

	uint16_t tot_len = ntohs(ip_header->tot_len);
	uint32_t size_ip = ip_header->ihl<<2;
	uint32_t size_tcp = tcp_header->doff<<2;
	uint32_t contSize=tot_len-size_tcp-size_ip;
#if (TCPCOPY_MYSQL_BASIC)
	unsigned char* payload=NULL;
#endif
	if(contSize>0)
	{
		globalConPackets++;
	}
	//check if it needs sending fin to backend
	if(candidateErased)
	{
		if(!isClientClosed)
		{
			sendFakedFinToBackByCliePack(ip_header,tcp_header);
			isClientClosed=1;
#if (DEBUG_TCPCOPY)
			selectiveLogInfo(LOG_INFO,"set client closed flag:%u",
					client_port);
#endif
		}else
		{
			sendFakedFinToBackByCliePack(ip_header,tcp_header);
		}
		return;
	}
	local_dest_ip_addr=ip_header->daddr;
	if(0 == fake_ip_addr)
	{
		client_ip_addr=ip_header->saddr;
	}
	if(isPureRequestBegin)
	{
		uint32_t seq=ntohl(tcp_header->seq)-total_seq_omit;
		tcp_header->seq=htonl(seq);
	}
	save_header_info(ip_header,tcp_header);
	if(fake_ip_addr!=0||fake_client_port!=0)
	{
		ip_header->saddr=fake_ip_addr;
		tcp_header->seq=htonl(nextSeq);
		tcp_header->source=fake_client_port;
	}
	//processing the reset packet
	if(tcp_header->rst)
	{
		isClientReset=1;
#if (DEBUG_TCPCOPY)
		selectiveLogInfo(LOG_INFO,"reset from client");
#endif
		if(isWaitResponse)
		{
#if (DEBUG_TCPCOPY)
			selectiveLogInfo(LOG_INFO,"push reset pack from cli");
#endif
			unsend.push_back(copy_ip_packet(ip_header));
		}else
		{
			wrap_send_ip_packet(fake_ip_addr,(unsigned char *) ip_header,
					virtual_next_sequence,1);
			reset_flag = 1;
		}
		return;
	}
	/* processing the syn packet */
	if(tcp_header->syn)
	{
		isSynIntercepted=1;
		client_port=ntohs(tcp_header->source);
#if (DEBUG_TCPCOPY)
		logInfo(LOG_INFO,"syn port:%u",client_port);
#endif
#if (TCPCOPY_MYSQL_BASIC)
		/* remove old mysql info*/
		MysqlIterator iter=mysqlContainer.find(client_port);
		dataContainer* datas=NULL;
		if(iter!= mysqlContainer.end())
		{
			datas=iter->second;
			for(dataIterator subIter=datas->begin();
					subIter!=datas->end();)
			{
				free(*(subIter++));
			}
			mysqlContainer.erase(iter);
			delete(datas);
#if (DEBUG_TCPCOPY)
			selectiveLogInfo(LOG_INFO,"remove old mysql info");
#endif
		}
#endif
		unsigned char *data=copy_ip_packet(ip_header);
		handshakePackets.push_back(data);
		wrap_send_ip_packet(fake_ip_addr,(unsigned char *)ip_header,
				virtual_next_sequence,1);
		return;
	}
	if(0 == client_port)
	{
		client_port=ntohs(tcp_header->source);
	}
	/* processing the fin packet */
	if(tcp_header->fin)
	{
#if (DEBUG_TCPCOPY)
		selectiveLogInfo(LOG_DEBUG,"recv fin packet from cli");
#endif
		if(contSize>0)
		{
#if (DEBUG_TCPCOPY)
			selectiveLogInfo(LOG_INFO,"fin has content");
#endif
		}else
		{
			if(isFakedSendingFinToBackend)
			{
				return;
			}
			/* client sends fin ,and the server acks it */
			if(virtual_ack == tcp_header->seq)
			{
				if(isWaitResponse)
				{
#if (DEBUG_TCPCOPY)
					selectiveLogInfo(LOG_DEBUG,"push back packet");
#endif
					unsend.push_back(copy_ip_packet(ip_header));
				}else
				{
					while(! unsend.empty())
					{
						unsigned char *data = unsend.front();
						free(data);
						unsend.pop_front();
					}
					wrap_send_ip_packet(fake_ip_addr,(unsigned char *)ip_header,
							virtual_next_sequence,1);
					virtual_status |= CLIENT_FIN;
					confirmed=1;
					isClientClosed=1;
#if (DEBUG_TCPCOPY)
					selectiveLogInfo(LOG_INFO,"set client closed flag:%u",
							client_port);
#endif
				}
			}
			else
			{
#if (DEBUG_TCPCOPY)
				selectiveLogInfo(LOG_DEBUG,"push back packet");
#endif
				unsend.push_back(copy_ip_packet(ip_header));
				if(checkSendingDeadReqs())
				{
					sendReservedPackets();
				}
			}
			return;
		}
	}


	uint32_t tmpLastAck=lastAck;
	bool isNewRequest=0;
	bool isNeedOmit=0;
	if(!isSynIntercepted)
	{
		isHalfWayIntercepted=1;
	}
#if (TCPCOPY_MYSQL_BASIC)
	if(isSynIntercepted)
	{
		if(!isGreeingReceived&&isHalfWayIntercepted)
		{
			if(contSize>0)
			{
				reqContentPackets++;
			}
#if (DEBUG_TCPCOPY)
			selectiveLogInfo(LOG_DEBUG,"push back pack for half");
#endif
			unsend.push_back(copy_ip_packet(ip_header));
			return;
		}
		if(0==contSize&&!isGreeingReceived)
		{
#if (DEBUG_TCPCOPY)
			selectiveLogInfo(LOG_DEBUG,"push back ack for not recv greet");
#endif
			unsend.push_back(copy_ip_packet(ip_header));
			return;
		}
	}
#endif
	if(contSize>0)
	{
		reqContentPackets++;
#if (TCPCOPY_MYSQL_BASIC)
		if(!isHalfWayIntercepted)
		{
#if (TCPCOPY_MYSQL_ADVANCED)
			if(!isFirstAuthSent)
			{
				if(isGreeingReceived)
				{
					logInfo(LOG_WARN,"a mysql login request from main");
					payload=(unsigned char*)((char*)tcp_header+size_tcp);
					int result=change_client_auth_content(payload,contSize,
							scrambleBuf,password);
					outputPacketForDebug(LOG_WARN,CLIENT_FLAG,
							ip_header,tcp_header);
					logInfo(LOG_WARN,"password:%s,p:%u",password,client_port);
					if(!result)
					{
						logInfo(LOG_WARN,"it should never reach here");
						over_flag=1;
						return;
					}
					isFirstAuthSent=1;

					uint64_t value=get_ip_port_value(ip_header->saddr,
							tcp_header->source);
					AuthPackIterator iter = firAuthPackContainer.find(value);
					if(iter != firAuthPackContainer.end())
					{
						struct iphdr *packet=iter->second;
						free(packet);
						logInfo(LOG_WARN,"free value for fir auth:%llu",value);
					}
					struct iphdr *packet=NULL;
					packet=(struct iphdr*)copy_ip_packet(ip_header);
					firAuthPackContainer[value]=packet;
					logInfo(LOG_WARN,"set value for fir auth:%llu",value);

				}
			}else if(isFirstAuthSent&&isNeedSecondAuth)
			{
				logInfo(LOG_WARN,"a mysql second login req from reserved:%u",
						client_port);
				payload=(unsigned char*)((char*)tcp_header+size_tcp);
				char encryption[16];
				memset(encryption,0,16);
				memset(seed323,0,SEED_323_LENGTH+1);
				memcpy(seed323,scrambleBuf,SEED_323_LENGTH);
				new_crypt(encryption,password,seed323);
				logInfo(LOG_WARN,"change second request:%u",client_port);
				change_client_second_auth_content(payload,contSize,encryption);
				isNeedSecondAuth=0;
				outputPacketForDebug(LOG_WARN,CLIENT_FLAG,ip_header,
						tcp_header);
				uint64_t value=get_ip_port_value(ip_header->saddr,
						tcp_header->source);
				AuthPackIterator iter = secAuthPackContainer.find(value);
				if(iter != secAuthPackContainer.end())
				{
					struct iphdr *packet=iter->second;
					free(packet);
					logInfo(LOG_WARN,"free sec auth packet from main:%llu",
							value);
				}
				struct iphdr *packet=NULL;
				packet=(struct iphdr*)copy_ip_packet(ip_header);
				secAuthPackContainer[value]=packet;
				logInfo(LOG_WARN,"set sec auth packet from main:%llu",value);
			}
#endif
#if (!TCPCOPY_MYSQL_ADVANCED)
			if(!isPureRequestBegin)
			{
				//check if mysql protocol validation ends?
				payload=(unsigned char*)((char*)tcp_header+size_tcp);
				//skip  Packet Length
				payload=payload+3;
				unsigned char packetNumber=payload[0];
				//if it is the second authenticate_user,then skip it
				if(3==packetNumber)
				{
					isNeedOmit=1;
					isPureRequestBegin=1;
#if (DEBUG_TCPCOPY)
					selectiveLogInfo(LOG_INFO,"this is the sec auth packet");
#endif
				}
				if(0==packetNumber)
				{
					isPureRequestBegin=1;
#if (DEBUG_TCPCOPY)
					selectiveLogInfo(LOG_INFO,"it has no sec auth packet");
#endif
				}
			}
#else
			isPureRequestBegin=1;
#endif
			if(isNeedOmit)
			{
				selectiveLogInfo(LOG_NOTICE,"omit sec validation for mysql");
				total_seq_omit=contSize;
				global_total_seq_omit=total_seq_omit;
				reqContentPackets--;
				return;
			}
			if(!isPureRequestBegin)
			{
				handshakeExpectedPackets++;
				unsigned char *data=copy_ip_packet(ip_header);
				handshakePackets.push_back(data);

				if(!fir_auth_user_pack)
				{
					fir_auth_user_pack=(struct iphdr*)copy_ip_packet(ip_header);
#if (DEBUG_TCPCOPY)
					selectiveLogInfo(LOG_INFO,"set global fir auth packet");
#endif
				}
				if(isGreeingReceived)
				{
					isLoginReceived=1;
					loginCanSendFlag=1;
				}else
				{
					if(!isLoginReceived)
					{
						isLoginReceived=1;
#if (DEBUG_TCPCOPY)
						selectiveLogInfo(LOG_DEBUG,"push back mysql login req");
#endif
						unsend.push_back(copy_ip_packet(ip_header));
						return;
					}
				}
			}
			checkMysqlPacketNeededForReconnection(ip_header,tcp_header);
			if(!isGreeingReceived)
			{
#if (DEBUG_TCPCOPY)
				selectiveLogInfo(LOG_DEBUG,"push back client packs for mysql");
#endif
				unsend.push_back(copy_ip_packet(ip_header));
				return;
			}
		}
#endif
		if(isWaitResponse)
		{
			double diff=time(0)-lastSendClientContentTime;
			if(diff>300)
			{	
				//if the sesssion recv no response for more than 5 min
				//then enter the suicide process
				logLevel=LOG_DEBUG;
				selectiveLogInfo(LOG_WARN,"no res back,req:%u,res:%u,p:%u",
						reqContentPackets,respContentPackets,client_port);
				if(reqContentPackets>sendConPackets)
				{
					size_t diffReqCont=reqContentPackets-sendConPackets;
					if(diffReqCont>200)
					{
						selectiveLogInfo(LOG_WARN,"lost packets:%u,p:%u",
								diffReqCont,client_port);
						over_flag=1;
						return;
					}
				}
			}
		}
	}
	/* data packet or the third packet */
	if(virtual_status ==SYN_SEND)
	{
		if(!isSynIntercepted)
		{
			establishConnectionForNoSynPackets(ip_header,tcp_header);
			unsend.push_back(copy_ip_packet(ip_header));
			return;
		}
		if(!isHalfWayIntercepted&&
				handshakePackets.size()<handshakeExpectedPackets)
		{
#if (DEBUG_TCPCOPY)
			selectiveLogInfo(LOG_DEBUG,"buffer the handshake packet");
#endif
			unsigned char *data=copy_ip_packet(ip_header);
			handshakePackets.push_back(data);
		}
		//when client sends multi-packets more quickly than the local network
		unsend.push_back(copy_ip_packet(ip_header));
#if (DEBUG_TCPCOPY)
		selectiveLogInfo(LOG_DEBUG,"SYN_SEND push back the packet from cli");
#endif
	}
	else
	{
		if(tcp_header->ack)
		{
			isRequestComletely=1;
			isRequestBegin=0;
		}

		if(contSize>0)
		{
			lastAck=ntohl(tcp_header->ack_seq);
			if(lastAck!=tmpLastAck)
			{
				isNewRequest=1;
				isRequestComletely=0;
				isRequestBegin=1;
			}
#if (DEBUG_TCPCOPY)
			selectiveLogInfo(LOG_DEBUG,"check it is a http request");
#endif
			if(isTestConnClosed)
			{
				//if the connection to the backend is closed,then we 
				//reestablish the connection and 
				//we reserve all comming packets for later disposure
#if (TCPCOPY_MYSQL_BASIC)
				if(checkPacketPaddingForMysql(ip_header,tcp_header))
				{
#if (DEBUG_TCPCOPY)
					selectiveLogInfo(LOG_WARN,"init session");
#endif
					initSessionForKeepalive();
					establishConnectionForNoSynPackets(ip_header,
							tcp_header);
					unsend.push_back(copy_ip_packet(ip_header));
				}
#else
#if (DEBUG_TCPCOPY)
				selectiveLogInfo(LOG_INFO,"init session");
#endif
				initSessionForKeepalive();
				establishConnectionForClosedConn();
				unsend.push_back(copy_ip_packet(ip_header));
#endif
				return;
			}
			if(!isSynIntercepted)
			{
				establishConnectionForNoSynPackets(ip_header,tcp_header);
				unsend.push_back(copy_ip_packet(ip_header));
				return;
			}
			if(checkRetransmission(tcp_header,lastReqContSeq))
			{
				reqContentPackets--;
#if (DEBUG_TCPCOPY)
				selectiveLogInfo(LOG_DEBUG,"it is a retransmit from client");
#endif
				return;
			}else
			{
				if(isWaitResponse)
				{
					bool savePacket=0;
					if(isNewRequest&&checkTcpSeg(tcp_header,lastReqContSeq))
					{
						savePacket=1;
					}else
					{
						size_t baseConPackets=reqContentPackets-1;
						if(sendConPackets<baseConPackets)
						{
#if (DEBUG_TCPCOPY)
							selectiveLogInfo(LOG_INFO,
									"it has reserved cont packs:%u,%u",
									sendConPackets,baseConPackets);
#endif
							if(checkReservedContainerHasContent())
							{
#if (DEBUG_TCPCOPY)
								selectiveLogInfo(LOG_INFO,"save pack");
#endif
								savePacket=1;
							}
						}
					}
					if(savePacket)
					{
#if (DEBUG_TCPCOPY)
						selectiveLogInfo(LOG_DEBUG,"push back the packet");
#endif
						unsend.push_back(copy_ip_packet(ip_header));
						if(checkSendingDeadReqs())
						{
							sendReservedPackets();
						}
						return;
					}
				}
				if(!isTrueWaitResponse)
				{
					if(checkPacketLost(ip_header,tcp_header,nextSeq))
					{
						if(checkReservedContainerHasContent())
						{
#if (DEBUG_TCPCOPY)
							selectiveLogInfo(LOG_DEBUG,"push back the pack");
#endif
							unsend.push_back(copy_ip_packet(ip_header));
							return;
						}
						lostPackets.push_back(copy_ip_packet(ip_header));
#if (DEBUG_TCPCOPY)
						selectiveLogInfo(LOG_DEBUG,"lost and need prev pack");
#endif
						isWaitPreviousPacket=1;
						return;
					}
					if(isWaitPreviousPacket)
					{
						//we do not support session when  two packets are 
						//lost and retransmitted
						wrap_send_ip_packet(fake_ip_addr,
								(unsigned char *)ip_header,
								virtual_next_sequence,1);
						sendReservedLostPackets();
						isWaitResponse=1;
						isResponseCompletely=0;
						isPartResponse=0;
						return;
					}
				}
				virtual_status=SEND_REQUEST;
				if(isWaitResponse&&checkTcpSeg(tcp_header,lastReqContSeq)&&
						!isNewRequest)
				{
					isSegContinue=1;
					wrap_send_ip_packet(fake_ip_addr,
							(unsigned char *)ip_header,virtual_next_sequence,1);
#if (DEBUG_TCPCOPY)
					selectiveLogInfo(LOG_DEBUG,"it is a continuous http req");
#endif
				}
				lastReqContSeq=ntohl(tcp_header->seq);
				if(isSegContinue)
				{
					isSegContinue=0;
					return;
				}else
				{
					requestProcessed++;
					if(requestProcessed>30)
					{
						isKeepalive=1;
					}
#if (DEBUG_TCPCOPY)
					selectiveLogInfo(LOG_DEBUG,"a new request from client");
#endif
				}
			}
		}else
		{
			if(handshakePackets.size()<handshakeExpectedPackets)
			{
				unsigned char *data=copy_ip_packet(ip_header);
				handshakePackets.push_back(data);
			}
		}
		if(isWaitResponse)
		{
			unsend.push_back(copy_ip_packet(ip_header));
#if (DEBUG_TCPCOPY)
			selectiveLogInfo(LOG_DEBUG,"wait backent server's response");
#endif
			if(checkSendingDeadReqs())
			{
				sendReservedPackets();
			}
		}else
		{
			if(isClientClosed)
			{
				unsend.push_back(copy_ip_packet(ip_header));
#if (DEBUG_TCPCOPY)
				selectiveLogInfo(LOG_DEBUG,"save ack for server fin");
#endif
				if(checkSendingDeadReqs())
				{
					sendReservedPackets();
				}
			}else
			{
				if(SEND_REQUEST==virtual_status)
				{
					isWaitResponse=1;
					isPartResponse=0;
					isResponseCompletely=0;
				}
				if(!isResponseCompletely)
				{
					wrap_send_ip_packet(fake_ip_addr,
							(unsigned char *)ip_header,virtual_next_sequence,1);
				}
			}
		}
	}
}

void session_st::restoreBufferedSession()
{
	unsigned char *data = unsend.front();
	unsend.pop_front();
	struct iphdr *ip_header=(struct iphdr*)((char*)data);
	uint32_t size_ip = ip_header->ihl<<2;
	struct tcphdr* tcp_header = (struct tcphdr*)((char *)ip_header+size_ip);
	process_recv(ip_header,tcp_header);
	free(data);
}

/**
 * filter packets 
 */
bool isPacketNeeded(const char *packet)
{
	bool isNeeded=0;
	struct tcphdr *tcp_header;
	struct iphdr *ip_header;
	uint32_t size_ip;
	uint32_t size_tcp;

	ip_header = (struct iphdr*)packet;
	//check if it is a tcp packet
	if(ip_header->protocol != IPPROTO_TCP)
	{
		return isNeeded;
	}

	size_ip = ip_header->ihl<<2;
	uint32_t packSize=ntohs(ip_header->tot_len);
	if (size_ip < 20) {
		logInfo(LOG_WARN,"Invalid IP header length: %d", size_ip);
		return isNeeded;
	}
	tcp_header = (struct tcphdr*)((char *)ip_header+size_ip);
	size_tcp = tcp_header->doff<<2;
	if (size_tcp < 20) {
		logInfo(LOG_WARN,"Invalid TCP header length: %d bytes,packet len:%d",
				size_tcp,packSize);
		return isNeeded;
	}
	//here we filter the packets we do care about
	{
		//because it may use several virtual ip addresses 
		if(checkLocalIPValid(ip_header->daddr) && 
				(tcp_header->dest==local_port))
		{
			isNeeded=1;
			if(tcp_header->syn)
			{
				synTotal++;
			}
			totalClientPackets++;
		}
	}
	return isNeeded;
}

/**
 * the main procedure for processing the filtered packets
 */
void process(char *packet)
{
	struct tcphdr *tcp_header=NULL;
	struct iphdr *ip_header=NULL;
	uint32_t size_ip;
	bool reusePort=0;
	time_t now=time(0);
	timeCount++;

	if(timeCount%20000==0)
	{
		//this is for checking memory leak
		logInfo(LOG_WARN,
				"activeCount:%llu,total syns:%llu,rel reqs:%llu,obs del:%llu",
				activeCount,enterCount,leaveCount,deleteObsoCount);
		logInfo(LOG_WARN,"total conns:%llu,total reqs:%llu,total resps:%llu",
				totalConnections,totalRequests,totalResponses);
		if(bakTotal>0)
		{
			logInfo(LOG_WARN,"bakTotal:%llu,bakTotalTimes:%f,avg=%f",
					bakTotal,bakTotalTimes,bakTotalTimes/bakTotal);
		}
		logInfo(LOG_WARN,"clientTotal:%llu,clientTotalTimes:%f,avg=%f",
				clientTotal,clientTotalTimes,clientTotalTimes/clientTotal);
		logInfo(LOG_WARN,"send Packets:%llu,send content packets:%llu",
				sendPackets,globalSendConPackets);
		logInfo(LOG_WARN,"total cont Packs from cli:%llu",globalConPackets);
		clearTimeoutTcpSessions();
		double ratio=0;
		if(enterCount>0)
		{
			ratio=100.0*totalConnections/enterCount;
		}else
		{
			ratio=100.0*totalConnections/(enterCount+1);
		}
		if(ratio<80)
		{
			logInfo(LOG_WARN,"many connections can't be established");
		}
		logInfo(LOG_NOTICE,"total successful retransmit:%llu",
				totalRetransmitSuccess);
		logInfo(LOG_NOTICE,"syn total:%llu,all client packets:%llu",
				synTotal,totalClientPackets);
	}
	if(lastCheckDeadSessionTime>0)
	{
		double diff=now-lastCheckDeadSessionTime;
		if(diff>2)
		{
			if(sessions.size()>0)
			{
				sendDeadTcpPacketsForSessions();
				lastCheckDeadSessionTime=now;
			}
		}
	}

	ip_header = (struct iphdr*)packet;
	size_ip = ip_header->ihl<<2;
	tcp_header = (struct tcphdr*)((char *)ip_header+size_ip);

	if((ip_header->saddr==remote_ip) && (tcp_header->source==remote_port) )
	{
		//when the packet comes from the targeted test machine
		uint32_t clientIP=ip_header->daddr;
		uint64_t key=get_ip_port_value(ip_header->daddr,tcp_header->dest);
		{
			//try to find session through fake ip
			IPIterator ipIter=trueIPContainer.find(key);
			if(ipIter!= trueIPContainer.end())
			{
				clientIP=ipIter->second;
			}
		}
		SessIterator iter = sessions.find(get_ip_port_value(clientIP,
					tcp_header->dest));
		if(iter != sessions.end())
		{
			iter->second.confirmed=0;
			iter->second.lastUpdateTime=now;
			struct timeval start=getTime();
			bakTotal++;
			iter->second.update_virtual_status(ip_header,tcp_header);
			struct timeval end=getTime();
			bakTotalTimes+=end.tv_sec-start.tv_sec;
			bakTotalTimes+=(end.tv_usec-start.tv_usec)/1000000.0;
			if( iter->second.is_over())
			{
				if(iter->second.hasMoreNewSession)
				{
					iter->second.initForNextSession();
					logInfo(LOG_NOTICE,"init for next session from backend");
					iter->second.restoreBufferedSession();
					return;
				}else
				{
					if(!iter->second.isStatClosed)
					{
						iter->second.isStatClosed=1;
					}
					activeCount--;
					leaveCount++;
					sessions.erase(iter);
				}
			}
		}else
		{
			//it may happen when the last packet comes from backend
		}
	}
	else if(checkLocalIPValid(ip_header->daddr) && 
			(tcp_header->dest==local_port))
	{
		//when the packet comes from client
		lastCheckDeadSessionTime=now;
		if(port_shift_factor)
		{
			uint16_t tmp_port_addition=(2048<<port_shift_factor)+rand_shift_port;
			uint16_t transfered_port=ntohs(tcp_header->source);
			if(transfered_port<=(65535-tmp_port_addition))
			{
				transfered_port=transfered_port+tmp_port_addition;
			}else
			{
				transfered_port=1024+tmp_port_addition;
			}
			tcp_header->source=htons(transfered_port);
		}
		uint64_t value=get_ip_port_value(ip_header->saddr,tcp_header->source);
		if(tcp_header->syn)
		{
			activeCount++;
			enterCount++;
			SessIterator iter = sessions.find(value);
			if(iter != sessions.end())
			{
				//check if it is a duplicate syn
				int diff=now-iter->second.createTime;
				if(tcp_header->seq==iter->second.synSeq)
				{
					enterCount--;
#if (DEBUG_TCPCOPY)
					logInfo(LOG_INFO,"duplicate syn,time diff:%d",diff);
					outputPacketForDebug(LOG_INFO,CLIENT_FLAG,ip_header,
							tcp_header);
#endif
					return;
				}else
				{
					//buffer the next session to current session
					iter->second.hasMoreNewSession=1;
					iter->second.nextSessionBuffer.push_back
						(copy_ip_packet(ip_header));
#if (DEBUG_TCPCOPY)
					logInfo(LOG_INFO,"buffer the new session");
					outputPacketForDebug(LOG_INFO,CLIENT_FLAG,ip_header,
							tcp_header);
#endif
					return;
				}

			}
			int sock=address_find_sock(tcp_header->dest);
			if(-1 == sock)
			{
				logInfo(LOG_WARN,"sock is invalid in process");
				outputPacketForDebug(LOG_WARN,CLIENT_FLAG,ip_header,tcp_header);
				return;
			}
			int result=msg_copyer_send(sock,ip_header->saddr,
					tcp_header->source,CLIENT_ADD);
			if(-1 == result)
			{
				logInfo(LOG_ERR,"msg coper send error");
				return;
			}else
			{
				if(reusePort)
				{
					struct timeval start=getTime();
					clientTotal++;
					iter->second.process_recv(ip_header,tcp_header);
					struct timeval end=getTime();
					clientTotalTimes+=end.tv_sec-start.tv_sec;
					clientTotalTimes+=(end.tv_usec-start.tv_usec)/1000000.0;
				}else
				{
					struct timeval start=getTime();
					clientTotal++;
					sessions[value].process_recv(ip_header,tcp_header);
					struct timeval end=getTime();
					clientTotalTimes+=end.tv_sec-start.tv_sec;
					clientTotalTimes+=(end.tv_usec-start.tv_usec)/1000000.0;
					iter = sessions.find(value);
				}
				iter->second.synSeq=tcp_header->seq;
			}
		}
		else
		{
			SessIterator iter = sessions.find(value);
			if(iter != sessions.end())
			{
				if(iter->second.isSessionAlreadyExist)
				{
					/* if there are serveral sessions for four pair,
					 * then we only dispose the first one*/
					return;
				}
				iter->second.confirmed=0;
				struct timeval start=getTime();
				clientTotal++;
				iter->second.process_recv(ip_header,tcp_header);
				struct timeval end=getTime();
				clientTotalTimes+=end.tv_sec-start.tv_sec;
				clientTotalTimes+=(end.tv_usec-start.tv_usec)/1000000.0;
				iter->second.lastUpdateTime=now;
				if( (iter->second.is_over()))
				{
					if(iter->second.hasMoreNewSession)
					{
						iter->second.initForNextSession();
						logInfo(LOG_NOTICE,"init for next session from client");
						iter->second.restoreBufferedSession();
						return;
					}else
					{
						if(!iter->second.isStatClosed)
						{
							iter->second.isStatClosed=1;
						}
						activeCount--;
						leaveCount++;
						sessions.erase(iter);
					}
				}
			}else
			{
				//we check if we can pad tcp handshake for this request
				if(checkPacketPadding(ip_header,tcp_header))
				{
#if (TCPCOPY_MYSQL_BASIC)
					if(checkPacketPaddingForMysql(ip_header,tcp_header))
					{
						struct timeval start=getTime();
						clientTotal++;
						sessions[value].process_recv(ip_header,tcp_header);
						struct timeval end=getTime();
						clientTotalTimes+=end.tv_sec-start.tv_sec;
						clientTotalTimes+=(end.tv_usec-start.tv_usec)/1000000.0;
					}
#else
					struct timeval start=getTime();
					clientTotal++;
					sessions[value].process_recv(ip_header,tcp_header);
					struct timeval end=getTime();
					clientTotalTimes+=end.tv_sec-start.tv_sec;
					clientTotalTimes+=(end.tv_usec-start.tv_usec)/1000000.0;

#endif
				}
			}
		}
	}else
	{
		//we don't know where the packet comes from
		logInfo(LOG_WARN,"unknown packet");
		outputPacketForDebug(LOG_WARN,UNKNOWN_FLAG,ip_header,tcp_header);
	}
}

