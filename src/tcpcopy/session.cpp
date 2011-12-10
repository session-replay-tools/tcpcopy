#include <map>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdarg.h>
#include "session.h"
#include "send.h"
#include "../communication/msg.h"
#include "../log/log.h"
#include "address.h"

using std::map;

uint32_t localhost_ip;
uint32_t sample_ip;
uint32_t client_ip;
virtual_ip_addr local_ips;
uint32_t remote_ip;
uint16_t local_port;
uint16_t remote_port;

typedef map<uint64_t,session_st> SessContainer;
typedef map<uint64_t,uint32_t> IPContainer;
typedef map<uint16_t,dataContainer*> MysqlContainer;
typedef map<uint64_t,session_st>::iterator SessIterator;
typedef map<uint64_t,uint32_t>::iterator IPIterator;
typedef map<uint16_t,dataContainer*>::iterator MysqlIterator;

static SessContainer sessions;
static IPContainer trueIPContainer;
static MysqlContainer mysqlContainer;
static uint64_t activeCount=0;
static uint64_t enterCount=0;
static uint64_t leaveCount=0;
static uint64_t deleteObsoCount=0;
static uint64_t totalReconnectForClosed=0;
static uint64_t totalReconnectForNoSyn=0;
static uint64_t timeCount=0;
static uint64_t totalResponses=0;
static uint64_t totalRequests=0;
static uint64_t totalConnections=0;
static uint64_t totalNumOfNoRespSession=0;
static struct iphdr *fir_auth_user_pack=NULL;
static uint32_t global_total_seq_omit=0;

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
		logInfo(level,"from bak:%s:%u-->%s:%u,len %u,seq=%u,ack_seq=%u,win:%u",
				sbuf,ntohs(tcp_header->source),dbuf,
				ntohs(tcp_header->dest),packSize,seq,ack_seq,window);
	}else if(CLIENT_FLAG==flag)
	{
		logInfo(level,"recv client:%s:%u-->%s:%u,len %u,seq=%u,ack_seq=%u",
				sbuf,ntohs(tcp_header->source),dbuf,ntohs(tcp_header->dest),
				packSize,seq,ack_seq);
	}else if(SERVER_BACKEND_FLAG==flag)
	{
		logInfo(level,"to backend: %s:%u-->%s:%u,len %u,seq=%u,ack_seq=%u",
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
	 * we clear old sessions that is never visited for more than one minute
	 * this may be a problem for keepalive connections
	 * so we adopt a naive method to distinguish between short-lived 
	 * and long-lived sessions(one connection represents one session)
	 */
	time_t current=time(0);
	time_t normalBase=current-60;
	time_t keepaliveBase=current-1800;
	time_t tmpBase=0;
	double ratio=100.0*enterCount/(totalRequests+1);
	size_t MAXPACKETS=5000;
	if(isMySqlCopy)
	{
		MAXPACKETS=10000;
	}
	if(ratio<10)
	{
		normalBase=keepaliveBase;
		logInfo(LOG_NOTICE,"keepalive connection global");
	}
	logInfo(LOG_NOTICE,"session number when coming:%u",sessions.size());
	for(SessIterator p=sessions.begin();p!=sessions.end();)
	{
		double diff=current-p->second.lastRecvRespContentTime;
		if(diff<60)
		{
			p++;
			continue;
		}

		if(p->second.isKeepalive)
		{
			tmpBase=keepaliveBase;
		}else
		{
			tmpBase=normalBase;
		}
		if(p->second.unsend.size()>20)
		{
			logInfo(LOG_NOTICE,"internal unsend number:%u,port=%u",
					p->second.unsend.size(),p->second.client_port);
		}
		if(p->second.unsend.size()>MAXPACKETS)
		{
			if(!p->second.candidateErased)
			{
				p->second.candidateErased=true;
				logInfo(LOG_WARN,"unsend:candidate erased:%u,port=%u",
						p->second.unsend.size(),p->second.client_port);
				p++;
				continue;
			}
			deleteObsoCount++;
			if(!p->second.isStatClosed)
			{
				p->second.isStatClosed=true;
			}
			activeCount--;
			logInfo(LOG_WARN,"It has too many unsend packets:%u,port=%u",
					p->second.unsend.size(),p->second.client_port);
			leaveCount++;
			sessions.erase(p++);
			continue;
		}
		if(p->second.lostPackets.size()>MAXPACKETS)
		{
			if(!p->second.candidateErased)
			{
				logInfo(LOG_WARN,"lostPackets:set candidate erased");
				p->second.candidateErased=true;
				p++;
				continue;
			}
			deleteObsoCount++;
			if(!p->second.isStatClosed)
			{
				p->second.isStatClosed=true;
			}
			activeCount--;
			logInfo(LOG_WARN,"It has too many lost packets:%u,port=%u",
					p->second.lostPackets.size(),p->second.client_port);
			leaveCount++;
			sessions.erase(p++);
			continue;
		}
		if(p->second.handshakePackets.size()>MAXPACKETS)
		{
			if(!p->second.candidateErased)
			{
				logInfo(LOG_WARN,"handshake:set candidate erased");
				p->second.candidateErased=true;
				p++;
				continue;
			}
			deleteObsoCount++;
			if(!p->second.isStatClosed)
			{
				p->second.isStatClosed=true;
			}
			activeCount--;
			logInfo(LOG_WARN,"It has too many handshake packets:%u,port=%u",
					p->second.handshakePackets.size(),p->second.client_port);
			leaveCount++;
			sessions.erase(p++);
			continue;
		}
		if(isMySqlCopy)
		{
			if(p->second.mysqlSpecialPackets.size()>MAXPACKETS)
			{
				if(!p->second.candidateErased)
				{
					logInfo(LOG_WARN,"mysql:set candidate erased");
					p->second.candidateErased=true;
					p++;
					continue;
				}
				deleteObsoCount++;
				if(!p->second.isStatClosed)
				{
					p->second.isStatClosed=true;
				}
				activeCount--;
				logInfo(LOG_WARN,"It has too many mysql packets:%u,port=%u",
						p->second.mysqlSpecialPackets.size(),
						p->second.client_port);
				leaveCount++;
				sessions.erase(p++);
				continue;
			}
		}
		if(p->second.lastUpdateTime<tmpBase)
		{
			if(!p->second.candidateErased)
			{
				p->second.candidateErased=true;
				p++;
				continue;
			}
			deleteObsoCount++;
			if(!p->second.isStatClosed)
			{
				p->second.isStatClosed=true;
			}
			activeCount--;
			logInfo(LOG_NOTICE,"session timeout");
			leaveCount++;
			if(p->second.unsend.size()>10)
			{
				logInfo(LOG_WARN,"timeout unsend number:%u,port=%u",
					p->second.unsend.size(),p->second.client_port);
			}
			sessions.erase(p++);
		}else
		{
			p++;
		}
	}
	logInfo(LOG_NOTICE,"session number when leaving:%u",sessions.size());
	return 0;
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
 * check tcp seq is valid 
 */
static bool checkTcpSeg(struct tcphdr *tcp_header,uint32_t oldSeq)
{
	uint32_t curSeq=ntohl(tcp_header->seq);
	if(curSeq<=oldSeq)
	{
		logInfo(LOG_INFO,"current seq %u ,last seq:%u from client",
				curSeq,oldSeq);
		return false;
	}
	return true;
}

uint32_t session_st::wrap_send_ip_packet(uint64_t fake_ip_addr,
		unsigned char *data,uint32_t ack_seq)
{
	if(!data)
	{
		selectiveLogInfo(LOG_ERR,"error ip data is null");
		return 0;
	}
	struct iphdr *ip_header = (struct iphdr *)data;
	uint16_t size_ip = ip_header->ihl<<2;
	struct tcphdr *tcp_header = (struct tcphdr *)(data+size_ip);
	tcp_header->dest = remote_port;
	ip_header->daddr = remote_ip;
	if(fake_ip_addr!=0)
	{
		tcp_header->seq=htonl(nextSeq);
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
		nextSeq=nextSeq+contenLen;
		sendConPackets=sendConPackets+1;
	}

	tcp_header->check = tcpcsum((unsigned char *)ip_header,
			(unsigned short *)tcp_header,tot_len-size_ip);
	ip_header->check = 0;
	//for linux 
	//The two fields that are always filled in are: the IP checksum 
	//(hopefully for us - it saves us the trouble) and the total length, 
	//iph->tot_len, of the datagram 
	ip_header->check = csum((unsigned short *)ip_header,size_ip); 
	outputPacket(LOG_DEBUG,SERVER_BACKEND_FLAG,ip_header,tcp_header);
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
			selectiveLogInfo(LOG_INFO,"seq in the packet:%u,expected seq:%u",
					curSeq,oldSeq);
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
	selectiveLogInfo(LOG_DEBUG,"lost packet size:%d",lostPackets.size());
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
					selectiveLogInfo(LOG_NOTICE,"error info in lostPackets:%u",
							client_port);
				}else
				{
					isWaitResponse=true;
					isPartResponse=false;
					isResponseCompletely=false;
				}
				selectiveLogInfo(LOG_DEBUG,"send reserved packets for lost:%u",
						client_port);
				wrap_send_ip_packet(fake_ip_addr,data,virtual_next_sequence);
				if(contSize>0)
				{
					lastReqContSeq=ntohl(tcp_header->seq);
				}
				count++;
				free(data);
				lostPackets.erase(iter++);
			}else
			{
				selectiveLogInfo(LOG_DEBUG,"cant send packets for lost:%u",
						client_port);
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
		isWaitPreviousPacket=false;
	}

	return 0;
}

/**
 * check if it needs sending dead requests
 */
bool session_st::checkSendingDeadReqs()
{
	time_t now=time(0);
	int diff=now-lastResponseDispTime;
	/* it will wait for 3 seconds */
	if(diff <= 3)
	{
		return false;
	}
	if(isPartResponse)
	{
		selectiveLogInfo(LOG_NOTICE,"send dead requests to backend:%u",
				client_port);
		isWaitResponse=false;
		isPartResponse=false;
		isResponseCompletely=false;
		return true;
	}
	return false;
}

/**
 * send reserved packets to backend
 */
int session_st::sendReservedPackets()
{
	bool needPause=false;
	bool mayPause=false;
	unsigned char* prevPacket=NULL;
	uint32_t prePackSize=0;
	int count=0;
	bool isOmitTransfer=false;
	uint32_t curAck=0;
	selectiveLogInfo(LOG_DEBUG,"send reserved packets:%u,port:%u",
			unsend.size(),client_port);
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
			if(isMySqlCopy)
			{
				if(!isGreeingReceived)
				{
					break;
				}
			}
			curAck=ntohl(tcp_header->ack_seq);
			if(mayPause)
			{
				if(curAck!=lastAck)
				{
					selectiveLogInfo(LOG_DEBUG,"cease to send:%u",
							client_port);
					break;
				}
			}
			selectiveLogInfo(LOG_DEBUG,"set mayPause true");
			mayPause=true;
			isWaitResponse=true;
			isPartResponse=false;
			isResponseCompletely=false;
			isRequestBegin=true;
			isRequestComletely=false;
			lastReqContSeq=ntohl(tcp_header->seq);
			lastAck=ntohl(tcp_header->ack_seq);
		}else if(tcp_header->rst){
			reset_flag=true;
			isOmitTransfer=false;
			selectiveLogInfo(LOG_DEBUG,"send reset packet to backend:%u",
					client_port);
			needPause=true;
		}else if(tcp_header->fin)
		{
			isClientClosed=true;
			selectiveLogInfo(LOG_NOTICE,"set cli closed flag:%u",client_port);
			needPause=true;
			virtual_status |= CLIENT_FIN;
			confirmed=true;
		}else if(0==contSize&&isWaitResponse)
		{
			selectiveLogInfo(LOG_DEBUG,"omit tranfer:size 0 and wait resp:%u",
					client_port);
			isOmitTransfer=true;
		}else if (0 == contSize)
		{
			if(SYN_CONFIRM != virtual_status)
			{
				selectiveLogInfo(LOG_DEBUG,"omit tranfer:notsynack,%u",
						client_port);
				isOmitTransfer=true;
			}
			if(isRequestBegin)
			{
				isOmitTransfer=true;
				isRequestBegin=false;
				isRequestComletely=true;
			}
		}

		if(!isOmitTransfer)
		{
			count++;
			wrap_send_ip_packet(fake_ip_addr,data,virtual_next_sequence);
		}
		free(data);
		unsend.pop_front();
		if(isOmitTransfer)
		{
			if(isWaitResponse)
			{
				selectiveLogInfo(LOG_DEBUG,"cease to send reserved packs:%u",
						client_port);
				break;
			}
		}
		isOmitTransfer=false;
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
	isHalfWayIntercepted=true;
	isBackSynReceived=false;

	unsigned char fake_syn_buf[FAKE_SYN_BUF_SIZE];
	memset(fake_syn_buf,0,FAKE_SYN_BUF_SIZE);
	struct iphdr *ip_header2 = (struct iphdr *)fake_syn_buf;
	struct tcphdr *tcp_header2 = (struct tcphdr *)(fake_syn_buf+20);

	selectiveLogInfo(LOG_NOTICE,"sendFakedSynToBackend:%u",client_port);
	ip_header2->version = 4;
	ip_header2->ihl = 5;
	ip_header2->tot_len = htons(FAKE_SYN_BUF_SIZE);
	ip_header2->frag_off = 64; 
	ip_header2->ttl = 64; 
	ip_header2->protocol = 6;
	ip_header2->id= htons(client_ip_id+2);;
	ip_header2->saddr = ip_header->saddr;
	ip_header2->daddr = ip_header->daddr;
	tcp_header2->doff= 8;
	tcp_header2->source = tcp_header->source;
	tcp_header2->dest= tcp_header->dest;
	tcp_header2->syn=1;
	tcp_header2->seq = minus_1(tcp_header->seq);
	tcp_header2->window= 65535;
	virtual_next_sequence=tcp_header->seq;
	unsigned char *data=copy_ip_packet(ip_header2);
	handshakePackets.push_back(data);
	if(isMySqlCopy)
	{
		isPureRequestBegin=true;
		if(fir_auth_user_pack)
		{
			struct iphdr* tmp_ip_header=NULL;
			struct tcphdr* tmp_tcp_header=NULL;
			tmp_ip_header=(struct iphdr*)copy_ip_packet(fir_auth_user_pack);
			tmp_ip_header->saddr=ip_header2->saddr;
			size_t size_ip= tmp_ip_header->ihl<<2;
			size_t total_len= ntohs(tmp_ip_header->tot_len);
			tmp_tcp_header=(struct tcphdr*)((char *)tmp_ip_header+size_ip);
			size_t size_tcp= tmp_tcp_header->doff<<2;
			size_t contentLen=total_len-size_ip-size_tcp;
			tmp_tcp_header->source=tcp_header2->source;
			unsend.push_back((unsigned char*)tmp_ip_header);
			total_seq_omit=global_total_seq_omit;
			uint32_t total_cont_len=contentLen;	
			MysqlIterator mysqlIter=mysqlContainer.find(client_port);
			dataContainer* datas=NULL;
			struct iphdr* tmp_ip_header2=NULL;
			struct tcphdr* tmp_tcp_header2=NULL;
			//TODO to be removed later
			if(mysqlIter!= mysqlContainer.end())
			{
				datas=mysqlIter->second;
				//check if we insert COM_STMT_PREPARE statements 
				for(dataIterator iter=datas->begin();
						iter!=datas->end();iter++)
				{
					unsigned char *data =*iter;
					tmp_ip_header2=(struct iphdr *)data;
					size_ip= tmp_ip_header2->ihl<<2;
					total_len= ntohs(tmp_ip_header2->tot_len);
					tmp_tcp_header2=(struct tcphdr*)((char *)tmp_ip_header2
							+size_ip); 
					size_tcp= tmp_tcp_header2->doff<<2;
					size_t tmpContentLen=total_len-size_ip-size_tcp;
					total_cont_len+=tmpContentLen;
				}
			}

			selectiveLogInfo(LOG_NOTICE,"total len needs to be subtracted:%u",
					total_cont_len);
			tcp_header2->seq=htonl(ntohl(tcp_header2->seq)-total_cont_len);
			tmp_tcp_header->seq=plus_1(tcp_header2->seq);
			uint32_t baseSeq=ntohl(tmp_tcp_header->seq)+contentLen;
			if(mysqlIter!= mysqlContainer.end())
			{
				datas=mysqlIter->second;
				//check if we insert COM_STMT_PREPARE statements 
				for(dataIterator iter=datas->begin();
						iter!=datas->end();iter++)
				{
					unsigned char *data =*iter;
					tmp_ip_header2=(struct iphdr *)data;
					tmp_ip_header2=(struct iphdr*)copy_ip_packet(tmp_ip_header2);
					size_ip= tmp_ip_header2->ihl<<2;
					total_len= ntohs(tmp_ip_header2->tot_len);
					tmp_tcp_header2=(struct tcphdr*)((char *)tmp_ip_header2
							+size_ip); 
					size_tcp= tmp_tcp_header2->doff<<2;
					size_t tmpContentLen=total_len-size_ip-size_tcp;
					tmp_tcp_header2->seq=htonl(baseSeq);
					unsend.push_back((unsigned char*)tmp_ip_header2);
					total_cont_len+=tmpContentLen;
					baseSeq+=tmpContentLen;
				}
			}
		}
	}

	outputPacket(LOG_NOTICE,FAKE_CLIENT_FLAG,ip_header2,tcp_header2);
	selectiveLogInfo(LOG_DEBUG,"send faked syn to back,client win:%u",
			tcp_header2->window);
	wrap_send_ip_packet(fake_ip_addr,fake_syn_buf,virtual_next_sequence);
}

/**
 * send faked syn ack packet to backend for handshake
 */
void session_st::sendFakedSynAckToBackend(struct iphdr* ip_header,
		struct tcphdr* tcp_header)
{
	static unsigned char fake_ack_buf[40];
	memset(fake_ack_buf,40,0);
	struct iphdr *ip_header2 = (struct iphdr *)fake_ack_buf;
	struct tcphdr *tcp_header2 = (struct tcphdr *)(fake_ack_buf+20);
	selectiveLogInfo(LOG_NOTICE,"sendFakedSynAckToBackend:%u",client_port);
	ip_header2->version = 4;
	ip_header2->ihl = 5;
	ip_header2->tot_len = htons(40);
	ip_header2->frag_off = 64; 
	ip_header2->ttl = 64; 
	ip_header2->protocol = 6;
	ip_header2->id= htons(client_ip_id+2);;
	ip_header2->saddr = client_ip_addr;
	ip_header2->daddr = local_dest_ip_addr; 
	tcp_header2->doff= 5;
	tcp_header2->source = tcp_header->dest;
	tcp_header2->dest= local_port;
	tcp_header2->ack=1;
	tcp_header2->ack_seq = virtual_next_sequence;
	tcp_header2->seq = tcp_header->ack_seq;
	tcp_header2->window= 65535;
	unsigned char *data=copy_ip_packet(ip_header2);
	handshakePackets.push_back(data);
	outputPacket(LOG_NOTICE,FAKE_CLIENT_FLAG,ip_header2,tcp_header2);
	wrap_send_ip_packet(fake_ip_addr,fake_ack_buf,virtual_next_sequence);
}

/**
 * send faked ack packet to backend 
 */
void session_st::sendFakedAckToBackend(struct iphdr* ip_header,
		struct tcphdr* tcp_header)
{
	static unsigned char fake_ack_buf[40];
	memset(fake_ack_buf,40,0);
	struct iphdr *ip_header2 = (struct iphdr *)fake_ack_buf;
	struct tcphdr *tcp_header2 = (struct tcphdr *)(fake_ack_buf+20);
	ip_header2->version = 4;
	ip_header2->ihl = 5;
	ip_header2->tot_len = htons(40);
	ip_header2->frag_off = 64; 
	ip_header2->ttl = 64; 
	ip_header2->protocol = 6;
	ip_header2->id= htons(client_ip_id+2);;
	ip_header2->saddr = ip_header->daddr;
	tcp_header2->doff= 5;
	tcp_header2->source = tcp_header->dest;
	tcp_header2->ack=1;
	tcp_header2->ack_seq = virtual_next_sequence;
	tcp_header2->seq = tcp_header->ack_seq;
	tcp_header2->window= 65535;
	selectiveLogInfo(LOG_INFO,"send faked ack to backend,client win:%u",
			tcp_header2->window);
	wrap_send_ip_packet(fake_ip_addr,fake_ack_buf,virtual_next_sequence);
}

/**
 * send faked fin to backend according to the backend packet
 */
void session_st::sendFakedFinToBackend(struct iphdr* ip_header,
		struct tcphdr* tcp_header)
{
	selectiveLogInfo(LOG_NOTICE,"send faked fin To Back:%u",client_port);
	static unsigned char fake_fin_buf[40];
	memset(fake_fin_buf,40,0);
	struct iphdr *ip_header2 = (struct iphdr *)fake_fin_buf;
	struct tcphdr *tcp_header2 = (struct tcphdr *)(fake_fin_buf+20);
	ip_header2->version = 4;
	ip_header2->ihl = 5;
	ip_header2->tot_len = htons(40);
	ip_header2->frag_off = 64; 
	ip_header2->ttl = 64; 
	ip_header2->protocol = 6;
	ip_header2->id= htons(client_ip_id+2);;
	ip_header2->saddr = ip_header->daddr;
	tcp_header2->doff= 5;
	tcp_header2->source = tcp_header->dest;
	tcp_header2->fin =1;
	tcp_header2->ack=1;
	uint16_t size_ip = ip_header->ihl<<2; 
	uint16_t size_tcp= tcp_header->doff<<2;
	uint16_t tot_len  = ntohs(ip_header->tot_len);
	uint16_t contenLen=tot_len-size_ip-size_tcp;
	if(contenLen>0){   
		uint32_t next_ack= htonl(ntohl(tcp_header->seq)+contenLen); 
		tcp_header2->ack_seq = next_ack;
	}else
	{
		tcp_header2->ack_seq = virtual_next_sequence;
	}
	tcp_header2->seq = tcp_header->ack_seq;
	tcp_header2->window= 65535;
	wrap_send_ip_packet(fake_ip_addr,fake_fin_buf,virtual_next_sequence);
}

/**
 * send faked fin to backend according to the client packet
 */
void session_st::sendFakedFinToBackByCliePack(struct iphdr* ip_header,
		struct tcphdr* tcp_header)
{
	selectiveLogInfo(LOG_NOTICE,"send faked fin To Back from cli pack:%u",
			client_port);
	static unsigned char fake_fin_buf[40];
	memset(fake_fin_buf,40,0);
	struct iphdr *ip_header2 = (struct iphdr *)fake_fin_buf;
	struct tcphdr *tcp_header2 = (struct tcphdr *)(fake_fin_buf+20);
	ip_header2->version = 4;
	ip_header2->ihl = 5;
	ip_header2->tot_len = htons(40);
	ip_header2->frag_off = 64; 
	ip_header2->ttl = 64; 
	ip_header2->protocol = 6;
	ip_header2->id= htons(client_ip_id+2);;
	ip_header2->saddr = ip_header->saddr;
	tcp_header2->doff= 5;
	tcp_header2->source = tcp_header->source;
	tcp_header2->fin =1;
	tcp_header2->rst =1;
	tcp_header2->ack=1;
	
	tcp_header2->ack_seq = virtual_next_sequence;
	if(isClientClosed)
	{
		tcp_header2->seq =htonl(nextSeq-1); 
	}else
	{
		tcp_header2->seq =htonl(nextSeq); 
	}
	tcp_header2->window= 65535;
	wrap_send_ip_packet(fake_ip_addr,fake_fin_buf,virtual_next_sequence);
}

/**
 * establish a connection for intercepting already connected packets
 */
void session_st::establishConnectionForNoSynPackets(struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
	if(isMySqlCopy)
	{
		logLevel=LOG_DEBUG;
		selectiveLogInfo(LOG_WARN,"establish conn for already connected:%u",
				client_port);
	}else
	{
		selectiveLogInfo(LOG_NOTICE,"establish conn for already connected:%u",
				client_port);
	}
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
	isSynIntercepted=true;
	activeCount++;
	totalReconnectForNoSyn++;

}

/**
 * establish a connection for already closed connection
 */
void session_st::establishConnectionForClosedConn()
{
	selectiveLogInfo(LOG_INFO,"reestablish connection for keepalive:%u",
			client_port);

	if(handshakePackets.size()!=handshakeExpectedPackets)
	{
		selectiveLogInfo(LOG_WARN,"hand Packets size not expected:%u,exp:%u",
				handshakePackets.size(),handshakeExpectedPackets);
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
			outputPacket(LOG_NOTICE,CLIENT_FLAG,ip_header,tcp_header);
			return;
		}
		if(0 == fake_ip_addr)
		{
			client_ip_addr=ip_header->saddr;
		}else
		{
			selectiveLogInfo(LOG_DEBUG,"erase fake_ip_addr");
			trueIPContainer.erase(get_ip_port_value(fake_ip_addr,
						tcp_header->source));
		}
		fake_ip_addr=getRandomIP();
		selectiveLogInfo(LOG_NOTICE,"change ip address");
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
		wrap_send_ip_packet(fake_ip_addr,data,virtual_next_sequence);
		isSynIntercepted=true;
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
		//if it is the second authenticate_user,then skip it
		if(COM_STMT_PREPARE == command||
				(hasPrepareStat&&isExcuteForTheFirstTime))
		{
			if(COM_STMT_PREPARE == command)
			{
				hasPrepareStat=true;
			}else
			{
				if(COM_QUERY == command&&hasPrepareStat)
				{
					if(numberOfExcutes>0)
					{
						isExcuteForTheFirstTime=false;
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
			selectiveLogInfo(LOG_NOTICE,"push back necc statement:%u",
					client_port);

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
			logInfo(LOG_DEBUG,"this is query command");
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
	
	outputPacket(LOG_DEBUG,BACKEND_FLAG,ip_header,tcp_header);
	if( tcp_header->rst)
	{
		reset_flag = true;
		selectiveLogInfo(LOG_INFO,"reset from backend:%u",client_port);
		return;
	}
	virtual_ack = tcp_header->ack_seq;
	uint32_t ack=ntohl(tcp_header->ack_seq);
	uint32_t tot_len = ntohs(ip_header->tot_len);
	uint32_t size_ip = ip_header->ihl<<2;
	uint32_t size_tcp = tcp_header->doff<<2;
	uint32_t contSize=tot_len-size_tcp-size_ip;
	
	time_t current=time(0);
	if(contSize>0)
	{
		lastRecvRespContentTime=current;
	}
	if(ack > nextSeq)
	{
		selectiveLogInfo(LOG_NOTICE,"ack back more than nextSeq:%u,%u,port=%u",
				ack,nextSeq,client_port);
		nextSeq=ack;
	}else if(ack <nextSeq)
	{
		selectiveLogInfo(LOG_NOTICE,"ack back less than nextSeq:%u,%u,port=%u",
				ack,nextSeq,client_port);
		if(isClientClosed&&!tcp_header->fin)
		{
			sendFakedFinToBackend(ip_header,tcp_header);
			return;
		}
		if(tot_len>0)
		{
			needContinueProcessingForBakAck=true;
		}
		lastRespPacketSize=tot_len;
		return;
	}

	if( tcp_header->syn)
	{
		if(isBackSynReceived)
		{
			selectiveLogInfo(LOG_DEBUG,"recv syn from back again");
		}else
		{
			totalConnections++;
			isBackSynReceived=true;
			selectiveLogInfo(LOG_DEBUG,"recv syn from back");
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
		selectiveLogInfo(LOG_INFO,"recv fin from back:%u",client_port);
		isTestConnClosed=true;
		isWaitResponse=false;
		isTrueWaitResponse=false;
		isResponseCompletely=true;
		virtual_status  |= SERVER_FIN;
		virtual_next_sequence = plus_1(tcp_header->seq);
		sendFakedAckToBackend(ip_header,tcp_header);
		if(!isClientClosed)
		{
			//send constructed server fin to the backend
			sendFakedFinToBackend(ip_header,tcp_header);
			isFakedSendingFinToBackend=true;
		}else
		{
			over_flag=true;
		}
		return;
	}else if(tcp_header->ack)
	{
		if(isClientClosed&&isTestConnClosed)
		{
			over_flag=true;
			return;
		}
		if(isWaitResponse)
		{
			if(!isTrueWaitResponse)
			{
				totalRequests++;
			}
			isTrueWaitResponse=true;
		}
		
	}

	uint32_t next_seq = htonl(ntohl(tcp_header->seq)+contSize);
	bool isMtuModifed=false;
	bool isGreetReceivedPacket=false; 
	
	selectiveLogInfo(LOG_DEBUG,"cont size:%d",contSize);
	//it is nontrivial to check if the packet is the last packet of response
	//the following is not 100 percent right here
	if(contSize>0||needContinueProcessingForBakAck)
	{
		respContentPackets++;
		virtual_next_sequence =next_seq;
		if(!isClientClosed)
		{
			sendFakedAckToBackend(ip_header,tcp_header);
		}else
		{
			sendFakedFinToBackend(ip_header,tcp_header);
			return;
		}

		if(!candidateErased)
		{
			if(isMySqlCopy)
			{
				if(!isGreeingReceived)
				{
					selectiveLogInfo(LOG_INFO,"recv greeting from back");
					isGreeingReceived=true;
					isGreetReceivedPacket=true;
				}
			}
			isPartResponse=true;

			if(tot_len>mtu)
			{
				isMtuModifed=true;
				mtu=tot_len;
				selectiveLogInfo(LOG_NOTICE,"cur mtu:%u,port:%u",
						mtu,client_port);
			}
			if(tot_len==DEFAULT_RESPONSE_MTU)
			{
				lastRespPacketSize=tot_len;
				return;
			}
			if(!isMtuModifed&&tot_len==mtu)
			{
				if(lastRespPacketSize==tot_len)
				{
					lastRespPacketSize=tot_len;
					return;
				}
			}
			{
				selectiveLogInfo(LOG_DEBUG,"receive from backend");
				if(isWaitResponse||isGreetReceivedPacket)
				{
					selectiveLogInfo(LOG_DEBUG,"receive back server's resp");
					totalResponses++;
					isResponseCompletely=true;
					isWaitResponse=false;
					isTrueWaitResponse=false;
					virtual_next_sequence =next_seq;
					virtual_status = SEND_RESPONSE_CONFIRM;
					responseReceived++;
					lastResponseDispTime=current;
					sendReservedPackets();
					needContinueProcessingForBakAck=false;
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
			selectiveLogInfo(LOG_NOTICE,"send fin to back again");
		}
	}
	virtual_next_sequence= next_seq;
	if(candidateErased)
	{
		if(!isClientClosed)
		{
			selectiveLogInfo(LOG_NOTICE,"candidate erased true:%u",
					client_port);
			//send constructed server fin to the backend
			sendFakedFinToBackend(ip_header,tcp_header);
			isFakedSendingFinToBackend=true;
			isClientClosed=true;
			selectiveLogInfo(LOG_NOTICE,"set client closed flag:%u",
					client_port);
		}
	}
	lastRespPacketSize=tot_len;

}

/**
 * processing client packets
 */
void session_st::process_recv(struct iphdr *ip_header,
		struct tcphdr *tcp_header)
{
	outputPacket(LOG_DEBUG,CLIENT_FLAG,ip_header,tcp_header);
	//check if it needs sending fin to backend
	if(candidateErased)
	{
		if(!isClientClosed)
		{
			sendFakedFinToBackByCliePack(ip_header,tcp_header);
			isClientClosed=true;
			selectiveLogInfo(LOG_NOTICE,"set client closed flag:%u",
					client_port);
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
	if(fake_ip_addr!=0)
	{
		selectiveLogInfo(LOG_INFO,"set fake ip addr for client");
		ip_header->saddr=fake_ip_addr;
		tcp_header->seq=htonl(nextSeq);
	}
	//processing the reset packet
	if(tcp_header->rst)
	{
		isClientReset=true;
		selectiveLogInfo(LOG_NOTICE,"reset from client");
		if(isWaitResponse)
		{
			selectiveLogInfo(LOG_NOTICE,"push reset pack from cli");
			unsend.push_back(copy_ip_packet(ip_header));
		}else
		{
			wrap_send_ip_packet(fake_ip_addr,(unsigned char *) ip_header,
					virtual_next_sequence);
			reset_flag = true;
		}
		return;
	}
	/* processing the syn packet */
	if(tcp_header->syn)
	{
		isSynIntercepted=true;
		client_port=ntohs(tcp_header->source);
		if(isMySqlCopy)
		{
			/* remove old mysql info*/
			MysqlIterator iter=mysqlContainer.find(client_port);
			dataContainer* datas=NULL;
			if(iter!= mysqlContainer.end())
			{
				datas=iter->second;
				for(dataIterator iter2=datas->begin();
						iter2!=datas->end();)
				{
					 free(*(iter2++));
				}
				mysqlContainer.erase(iter);
				delete(datas);
				selectiveLogInfo(LOG_NOTICE,"remove old mysql info");
			}
		}
		unsigned char *data=copy_ip_packet(ip_header);
		handshakePackets.push_back(data);
		wrap_send_ip_packet(fake_ip_addr,(unsigned char *)ip_header,
				virtual_next_sequence);
		return;
	}
	if(0 == client_port)
	{
		client_port=ntohs(tcp_header->source);
	}
	/* processing the fin packet */
	if(tcp_header->fin)
	{
		selectiveLogInfo(LOG_DEBUG,"recv fin packet from cli");
		if(isFakedSendingFinToBackend)
		{
			return;
		}
		//client sends fin ,and the server acks it
		if(virtual_ack == tcp_header->seq)
		{
			if(isWaitResponse)
			{
				selectiveLogInfo(LOG_DEBUG,"push back packet");
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
						virtual_next_sequence);
				virtual_status |= CLIENT_FIN;
				confirmed=true;
				isClientClosed=true;
				selectiveLogInfo(LOG_NOTICE,"set client closed flag:%u",
						client_port);
			}
		}
		else
		{
			selectiveLogInfo(LOG_DEBUG,"push back packet");
			unsend.push_back(copy_ip_packet(ip_header));
			if(checkSendingDeadReqs())
			{
				sendReservedPackets();
			}
		}
		return;
	}
	//processing the other type of packet
	uint16_t tot_len = ntohs(ip_header->tot_len);
	uint32_t size_ip = ip_header->ihl<<2;
	uint32_t size_tcp = tcp_header->doff<<2;
	uint32_t contSize=tot_len-size_tcp-size_ip;

	uint32_t tmpLastAck=lastAck;
	bool isNewRequest=false;
	bool isNeedOmit=false;
	if(!isSynIntercepted)
	{
		isHalfWayIntercepted=true;
	}
	if(isMySqlCopy)
	{
		if(isSynIntercepted)
		{
			if(!isGreeingReceived&&isHalfWayIntercepted)
			{
				unsend.push_back(copy_ip_packet(ip_header));
				return;
			}
			if(0==contSize&&!isGreeingReceived)
			{
				unsend.push_back(copy_ip_packet(ip_header));
				return;
			}
		}
	}
	if(contSize>0)
	{
		reqContentPackets++;
		if(isMySqlCopy&&!isHalfWayIntercepted)
		{
			if(!isPureRequestBegin)
			{
				//check if mysql protocol validation ends?
				unsigned char* payload;
				payload=(unsigned char*)((char*)tcp_header+size_tcp);
				//skip  Packet Length
				payload=payload+3;
				unsigned char packetNumber=payload[0];
				//if it is the second authenticate_user,then skip it
				if(3==packetNumber)
				{
					isNeedOmit=true;
					isPureRequestBegin=true;
					selectiveLogInfo(LOG_INFO,"this is the sec auth packet");
				}
				if(0==packetNumber)
				{
					isPureRequestBegin=true;
					selectiveLogInfo(LOG_INFO,"it has no sec auth packet");
				}
			}
			if(isNeedOmit)
			{
				selectiveLogInfo(LOG_NOTICE,"omit sec validation for mysql");
				total_seq_omit=contSize;
				global_total_seq_omit=total_seq_omit;
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
					selectiveLogInfo(LOG_NOTICE,"set global fir auth packet");
				}
				if(isGreeingReceived)
				{
					isLoginReceived=true;
					loginCanSendFlag=true;
				}else
				{
					if(!isLoginReceived)
					{
						isLoginReceived=true;
						selectiveLogInfo(LOG_DEBUG,"push back mysql login req");
						unsend.push_back(copy_ip_packet(ip_header));
						return;
					}
				}
			}
			checkMysqlPacketNeededForReconnection(ip_header,tcp_header);
			if(!isGreeingReceived)
			{
				selectiveLogInfo(LOG_DEBUG,"push back client packs for mysql");
				unsend.push_back(copy_ip_packet(ip_header));
				return;
			}
		}

		time_t current=time(0);
		double diff=current-lastRecvRespContentTime;
		//if the sesssion recv no response for more than 5 min
		//then enter the suicide process
		if(diff > 300)
		{
			logLevel=LOG_DEBUG;
			selectiveLogInfo(LOG_WARN,"no res back,req:%u,res:%u,contsize:%u",
					reqContentPackets,respContentPackets,contSize);
			totalNumOfNoRespSession++;
			if(0 == baseReqContentPackets)
			{
				baseReqContentPackets=reqContentPackets;
			}
			double diffReqCont=reqContentPackets-baseReqContentPackets;
			if(diffReqCont>100)
			{
				over_flag=true;
				return;
			}
		}
	}
	//data packet or the third packet
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
			selectiveLogInfo(LOG_DEBUG,"buffer the handshake packet");
			unsigned char *data=copy_ip_packet(ip_header);
			handshakePackets.push_back(data);
		}
		//when client send multiple packet more quickly than the local network
		unsend.push_back(copy_ip_packet(ip_header));
		selectiveLogInfo(LOG_DEBUG,"SYN_SEND push back the packet from cli");
	}
	else
	{
		if(tcp_header->ack)
		{
			isRequestComletely=true;
			isRequestBegin=false;
		}

		if(contSize>0)
		{
			lastAck=ntohl(tcp_header->ack_seq);
			if(lastAck!=tmpLastAck)
			{
				isNewRequest=true;
				isRequestComletely=false;
				isRequestBegin=true;
			}
			selectiveLogInfo(LOG_DEBUG,"check it is a http request");
			if(isTestConnClosed)
			{
				//if the connection to the backend is closed,then we 
				//reestablish the connection and 
				//we reserve all comming packets for later disposure
				if(isMySqlCopy)
				{
					if(checkPacketPaddingForMysql(ip_header,tcp_header))
					{
						selectiveLogInfo(LOG_NOTICE,"init session");
						initSessionForKeepalive();
						establishConnectionForNoSynPackets(ip_header,
								tcp_header);
						unsend.push_back(copy_ip_packet(ip_header));
					}
				}else
				{
					selectiveLogInfo(LOG_NOTICE,"init session");
					initSessionForKeepalive();
					establishConnectionForClosedConn();
					unsend.push_back(copy_ip_packet(ip_header));
				}
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
				selectiveLogInfo(LOG_DEBUG,"it is a retransm from client");
				return;
			}else
			{
				if(isWaitResponse)
				{
					bool savePacket=false;
					if(isNewRequest&&checkTcpSeg(tcp_header,lastReqContSeq))
					{
						savePacket=true;
					}else
					{
						size_t baseConPackets=reqContentPackets-1;
						if(sendConPackets<baseConPackets)
						{
							selectiveLogInfo(LOG_NOTICE,
									"it has reserved cont packs");
							savePacket=true;
						}
					}
					if(savePacket)
					{
						selectiveLogInfo(LOG_DEBUG,"push back the packet");
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
						lostPackets.push_back(copy_ip_packet(ip_header));
						selectiveLogInfo(LOG_DEBUG,"lost and need prev pack");
						isWaitPreviousPacket=true;
						return;
					}
					if(isWaitPreviousPacket)
					{
						//we do not support session when  two packets are 
						//lost and retransmitted
						wrap_send_ip_packet(fake_ip_addr,
								(unsigned char *)ip_header,
								virtual_next_sequence);
						sendReservedLostPackets();
						isWaitResponse=true;
						isResponseCompletely=false;
						isPartResponse=false;
						return;
					}
				}
				virtual_status=SEND_REQUEST;
				if(isWaitResponse&&checkTcpSeg(tcp_header,lastReqContSeq)&&
						!isNewRequest)
				{
					isSegContinue=true;
					wrap_send_ip_packet(fake_ip_addr,
							(unsigned char *)ip_header,virtual_next_sequence);
					selectiveLogInfo(LOG_DEBUG,"it is a continuous http req");
				}
				lastReqContSeq=ntohl(tcp_header->seq);
				if(isSegContinue)
				{
					isSegContinue=false;
					return;
				}else
				{
					requestProcessed++;
					if(requestProcessed>30)
					{
						isKeepalive=true;
					}
					selectiveLogInfo(LOG_DEBUG,"a new request from client");
					
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
			selectiveLogInfo(LOG_DEBUG,"wait backent server's response");
			if(checkSendingDeadReqs())
			{
				sendReservedPackets();
			}
		}else
		{
			if(isClientClosed)
			{
				unsend.push_back(copy_ip_packet(ip_header));
				selectiveLogInfo(LOG_DEBUG,"save ack for server fin");
				if(checkSendingDeadReqs())
				{
					sendReservedPackets();
				}
			}else
			{
				if(SEND_REQUEST==virtual_status)
				{
					isWaitResponse=true;
					isPartResponse=false;
					isResponseCompletely=false;
				}
				if(!isResponseCompletely)
				{
					wrap_send_ip_packet(fake_ip_addr,
							(unsigned char *)ip_header,virtual_next_sequence);
				}
			}
		}
	}
}

/**
 * filter packets 
 */
bool isPacketNeeded(const char *packet)
{
	bool isNeeded=false;
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
			isNeeded=true;
		}
	}
	return isNeeded;
}

/**
 * the main procedure for processing the filtered packets
 */
void process(char *packet)
{
	struct tcphdr *tcp_header;
	struct iphdr *ip_header;
	uint32_t size_ip;
	bool reusePort=false;
	timeCount++;

	if(timeCount%100000==0)
	{
		//this is for checking memory leak
		logInfo(LOG_WARN,
				"activeCount:%llu,total syns:%llu,rel reqs:%llu,obs del:%llu",
				activeCount,enterCount,leaveCount,deleteObsoCount);
		logInfo(LOG_WARN,"total conns:%llu,total reqs:%llu,total resps:%llu",
				totalConnections,totalRequests,totalResponses);
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
			IPIterator iter2=trueIPContainer.find(key);
			if(iter2!= trueIPContainer.end())
			{
				clientIP=iter2->second;
			}
		}
		SessIterator iter = sessions.find(get_ip_port_value(clientIP,
					tcp_header->dest));
		if(iter != sessions.end())
		{
			iter->second.confirmed=false;
			iter->second.lastUpdateTime=time(0);
			iter->second.update_virtual_status(ip_header,tcp_header);
			if( iter->second.is_over())
			{
				if(!iter->second.isStatClosed)
				{
					iter->second.isStatClosed=true;
				}
				activeCount--;
				leaveCount++;
				sessions.erase(iter);
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
		uint64_t value=get_ip_port_value(ip_header->saddr,tcp_header->source);
		if(tcp_header->syn)
		{
			activeCount++;
			enterCount++;
			SessIterator iter = sessions.find(value);
			if(iter != sessions.end())
			{
				//check if it is a duplicate syn
				time_t now=time(0);
				int diff=now-iter->second.createTime;
				//if less than 30 seconds,then we consider it is a dup syn 
				if(diff < 30)
				{
					if(iter->second.is_over())
					{
						logInfo(LOG_INFO,"dup syn,ses over,time diff:%d",diff);
					}else
					{
						enterCount--;
						logInfo(LOG_NOTICE,"duplicate syn,time diff:%d",diff);
						outputPacketForDebug(LOG_NOTICE,CLIENT_FLAG,ip_header,
								tcp_header);
						return;
					}
				}
				deleteObsoCount++;	
				activeCount--;
				//reuse port number
				iter->second.initSession();
				reusePort=true;
				logInfo(LOG_WARN,"reuse port number,key :%llu",value);
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
					iter->second.process_recv(ip_header,tcp_header);
				}else
				{
					sessions[value].process_recv(ip_header,tcp_header);
				}
			}
		}
		else
		{
			SessIterator iter = sessions.find(value);
			if(iter != sessions.end())
			{
				iter->second.confirmed=false;
				iter->second.process_recv(ip_header,tcp_header);
				iter->second.lastUpdateTime=time(0);
				if( (iter->second.is_over()))
				{
					if(!iter->second.isStatClosed)
					{
						iter->second.isStatClosed=true;
					}
					activeCount--;
					leaveCount++;
					sessions.erase(iter);
				}
			}else
			{
				//we check if we can pad tcp handshake for this request
				if(checkPacketPadding(ip_header,tcp_header))
				{
					if(isMySqlCopy)
					{
						if(checkPacketPaddingForMysql(ip_header,tcp_header))
						{
							sessions[value].process_recv(ip_header,tcp_header);
						}
					}else
					{
						sessions[value].process_recv(ip_header,tcp_header);
					}
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

