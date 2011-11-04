#ifndef  _TCP_REDIRECT_SESSION_H_INC
#define  _TCP_REDIRECT_SESSION_H_INC

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <list>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

typedef struct virtual_ip_addr{
	uint32_t ips[16];
	int num;
}virtual_ip_addr;

extern uint32_t sample_ip;
extern virtual_ip_addr local_ips;
extern uint16_t local_port;
extern uint32_t remote_ip;
extern uint16_t remote_port;
extern int global_out_level;

#pragma pack(push,1)
struct etharp_frame { 
	unsigned char dst[6]; 
	unsigned char src[6];
	unsigned short type; 
};
#pragma pack(pop)
void process(char *);
bool isPacketNeeded(const char *packet);
void outputPacketForDebug(int level,int flag,struct iphdr *ip_header,
		struct tcphdr *tcp_header);
typedef std::list<unsigned char *> dataContainer;
typedef std::list<unsigned char *>::iterator dataIterator;

#define SYN_SEND     1
#define SYN_CONFIRM  2
#define SEND_REQUEST 4
#define SEND_RESPONSE_CONFIRM 8
#define SERVER_FIN  16
#define	CLIENT_FIN  32
#define BACKEND_FLAG 0
#define CLIENT_FLAG 1
#define FAKE_CLIENT_FLAG 10
#define SERVER_FLAG 2
#define UNKNOWN_FLAG 3
#define SERVER_BACKEND_FLAG 4
#define SELF_FLAG 5
#define DEFAULT_RESPONSE_MTU 1500
#define MIN_RESPONSE_MTU 576
#define RESERVE_CLIENT_FLAG 6

#define FAKE_SYN_BUF_SIZE 52


struct session_st
{
	uint32_t virtual_next_sequence;
	uint32_t virtual_ack;
	uint32_t fake_ip_addr;
	uint32_t client_ip_addr;
	uint32_t local_dest_ip_addr;
	uint16_t virtual_status;
	uint16_t client_ip_id;

	bool    reset_flag;
	bool    over_flag;
	bool 	isWaitBakendClosed;
	bool 	isClientClosed;
	bool 	isWaitResponse;
	bool 	isPartResponse;
	bool 	isResponseCompletely;
	bool 	isTrueWaitResponse;
	bool 	isWaitPreviousPacket;
	bool 	isSegContinue;
	bool 	isRequestComletely;
	bool    isRequestBegin;
	bool 	isKeepalive;
	bool 	confirmed;
	bool 	isTestConnClosed;
	bool 	isFakedSendingFinToBackend;
	bool 	isSynIntercepted;
	bool 	isHalfWayIntercepted;
	bool 	isStatClosed;

	uint32_t lastAckFromResponse;
	uint32_t lastSeqFromResponse;
	uint32_t lastReqContSeq;
	uint32_t nextSeq;
	uint32_t lastAck;
	uint32_t mtu;
	dataContainer unsend;
	dataContainer lostPackets;
	dataContainer handshakePackets;
	size_t requestProcessed;
	size_t responseReceived;
	size_t reqContentPackets;
	size_t baseReqContentPackets;
	size_t respContentPackets;
	time_t lastUpdateTime;
	time_t lastResponseDispTime;
	time_t createTime;
	time_t lastRecvRespContentTime;

	int logLevel;

	int generateRandomNumber(int min,int max,unsigned int* seed)                                                                        
	{
		int randNum=(int)(max*(rand_r(seed)/(RAND_MAX+1.0)))+min;
		return randNum;
	}

	uint32_t getRandomIP()
	{
		int ip0,ip1,ip2,ip3;
		unsigned int seed=0;
		struct timeval tp;
		gettimeofday(&tp,NULL);
		seed=tp.tv_usec;
		char buf[64];

		ip0=generateRandomNumber(1,254,&seed);
		ip1=generateRandomNumber(1,254,&seed);
		ip2=generateRandomNumber(1,254,&seed);
		ip3=generateRandomNumber(1,254,&seed);
		sprintf(buf,"%d.%d.%d.%d",ip0,ip1,ip2,ip3);
		return inet_addr(buf);
	}

	void initSession()
	{
		lastReqContSeq=0;
		nextSeq=0;
		lastAck=0;
		mtu=MIN_RESPONSE_MTU;
		lastAckFromResponse=0;
		lastSeqFromResponse=0;
		virtual_next_sequence=0;
		client_ip_id=0;
		initSessionForKeepalive();
		for(dataIterator iter=handshakePackets.begin();
				iter!=handshakePackets.end();)
		{
			free(*(iter++));
		}
		handshakePackets.clear();
	}

	void initSessionForKeepalive()
	{
		logLevel=global_out_level;
		fake_ip_addr=0;
		isFakedSendingFinToBackend=false;
		isTestConnClosed=false;
		isSynIntercepted=false;
		isHalfWayIntercepted=false;
		isStatClosed=false;
		virtual_status = SYN_SEND;
		reset_flag = false;
		over_flag = false;
		isWaitPreviousPacket=false;
		isWaitBakendClosed=false;
		isClientClosed=false;
		isKeepalive=false;
		isWaitResponse=false;
		isPartResponse=false;
		isResponseCompletely=false;
		isRequestComletely=true;
		isRequestBegin=false;
		isTrueWaitResponse=false;
		isSegContinue=false;
		confirmed=true;

		lastReqContSeq=0;
		nextSeq=0;
		lastAck=0;
		lastAckFromResponse=0;
		lastSeqFromResponse=0;
		requestProcessed=0;
		responseReceived=0;
		reqContentPackets=0;
		baseReqContentPackets=0;
		respContentPackets=0;
		lastUpdateTime=time(0);
		lastResponseDispTime=lastUpdateTime;
		createTime=lastUpdateTime;
		lastRecvRespContentTime=lastUpdateTime;

		for(dataIterator iter=unsend.begin();iter!=unsend.end();)
		{
			free(*(iter++));
		}
		unsend.clear();
		for(dataIterator iter=lostPackets.begin();iter!=lostPackets.end();)
		{
			free(*(iter++));
		}
		lostPackets.clear();
	}

	session_st()
	{
		initSession();	
	}

	~session_st()
	{
		for(dataIterator iter=unsend.begin();iter!=unsend.end();)
		{
			free(*(iter++));
		}
		unsend.clear();
		for(dataIterator iter=lostPackets.begin();iter!=lostPackets.end();)
		{
			free(*(iter++));
		}
		lostPackets.clear();
		for(dataIterator iter=handshakePackets.begin();
				iter!=handshakePackets.end();)
		{
			unsigned char* data=*(iter++);
			free(data);
		}
		handshakePackets.clear();
	}
	void outputPacket(int level,int flag,struct iphdr *ip_header,
			struct tcphdr *tcp_header);
	int sendReservedLostPackets();
	int sendReservedPackets();
	bool checkPacketLost(struct iphdr *ip_header,
			struct tcphdr *tcp_header,uint32_t oldSeq);
	bool checkSendDeadRequests();
	void update_virtual_status(struct iphdr *ip_header,
			struct tcphdr* tcp_header);
	void establishConnectionForNoSynPackets(struct iphdr *ip_header,
			struct tcphdr *tcp_header);
	void establishConnectionForClosedConn();
	void sendFakedSynToBackend(struct iphdr* ip_header,
			struct tcphdr* tcp_header);
	void sendFakedSynAckToBackend(struct iphdr* ip_header,
			struct tcphdr* tcp_header);
	void sendFakedAckToBackend(struct iphdr* ip_header,
			struct tcphdr* tcp_header);
	void sendFakedFinToBackend(struct iphdr* ip_header,
			struct tcphdr* tcp_header);
	unsigned char * copy_ip_packet(struct iphdr *ip_header);
	void save_header_info(struct iphdr *ip_header,struct tcphdr *tcp_header);
	void process_recv(struct iphdr *ip_header,struct tcphdr *tcp_header);
	bool is_over()
	{
		if(confirmed&& (virtual_status&CLIENT_FIN) && 
				(virtual_status&SERVER_FIN))
		{
			return true;
		}
		if(reset_flag)
		{
			return true;
		}
		if(over_flag)
		{
			return true;
		}
		return false;
	}
};


inline uint64_t get_ip_port_value(uint32_t s_ip,uint16_t s_port)
{
	uint64_t value=(uint64_t(s_ip))<<16;
	value+=s_port;
	return value;
}


#endif   /* ----- #ifndef _TCP_REDIRECT_SESSION_H_INC  ----- */

