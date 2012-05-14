#ifndef  _TCP_REDIRECT_SESSION_H_INC
#define  _TCP_REDIRECT_SESSION_H_INC

#include "../log/log.h"
#include "../communication/msg.h"
#include <stdarg.h>
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

extern virtual_ip_addr local_ips;
extern uint16_t local_port;
extern uint32_t remote_ip;
extern uint16_t remote_port;
extern uint16_t port_shift_factor;
extern uint16_t rand_shift_port;
extern int global_out_level;

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
#define RESERVE_CLIENT_FLAG 6

#define FAKE_SYN_BUF_SIZE 52
#define COM_STMT_PREPARE 22
#define COM_QUERY 3

#define RECV_BUF_SIZE 2048

#if (TCPCOPY_MYSQL_ADVANCED) 
#define SCRAMBLE_LENGTH 20
#define SEED_323_LENGTH 8
#define MAX_PASSWORD_LEN 256
#endif


struct session_st
{
	uint32_t virtual_next_sequence;
	uint32_t virtual_ack;
	uint32_t fake_ip_addr;
	uint32_t client_ip_addr;
	uint32_t local_dest_ip_addr;
	uint32_t total_seq_omit;

	uint32_t lastAckFromResponse;
	uint32_t lastSeqFromResponse;
	uint32_t lastReqContSeq;
	uint32_t nextSeq;
	uint32_t synSeq;
	uint32_t lastAck;
	uint32_t lastRespPacketSize;
	uint32_t handshakeExpectedPackets;
	dataContainer unsend;
	dataContainer nextSessionBuffer;
	dataContainer unAckPackets;
	dataContainer lostPackets;
	dataContainer handshakePackets;
	dataContainer mysqlSpecialPackets;
	size_t requestProcessed;
	size_t responseReceived;
	size_t reqContentPackets;
	size_t sendConPackets;
	size_t respContentPackets;
	size_t numberOfExcutes;
	size_t logRecordNum;
	size_t lastSameAckTotal;
	size_t contPacketsFromGreet;
	time_t lastUpdateTime;
	time_t createTime;
	time_t lastRecvRespContentTime;
	time_t lastSendClientContentTime;
	uint16_t virtual_status;
	uint16_t client_ip_id;
	uint16_t client_port;
	uint16_t fake_client_port;
#if (TCPCOPY_MYSQL_ADVANCED)
	char scrambleBuf[SCRAMBLE_LENGTH+1];
	char seed323[SEED_323_LENGTH+1];
	char password[MAX_PASSWORD_LEN];
#endif
	unsigned logLevel:4;
	unsigned alreadyRetransmit:1;
	unsigned isNewRetransmit:1;
	unsigned simulClosing:1;
	unsigned reset_flag:1;
	unsigned over_flag:1;
	unsigned isClientClosed:1;
	unsigned isTestConnClosed:1;
	unsigned isWaitResponse:1;
	unsigned isPartResponse:1;
	unsigned isResponseCompletely:1;
	unsigned isTrueWaitResponse:1;
	unsigned isWaitPreviousPacket:1;
	unsigned isSegContinue:1;
	unsigned isRequestComletely:1;
	unsigned isRequestBegin:1;
	unsigned isKeepalive:1;
	unsigned confirmed:1;
	unsigned isFakedSendingFinToBackend:1;
	unsigned isSynIntercepted:1;
	unsigned isBackSynReceived:1;
	unsigned isHalfWayIntercepted:1;
	unsigned isStatClosed:1;
	unsigned isClientReset:1;
	unsigned isPureRequestBegin:1;
	unsigned isGreeingReceived:1;
	unsigned isNeedSecondAuth:1;
	unsigned loginCanSendFlag:1;
	unsigned isFirstAuthSent:1;
	unsigned candidateErased:1;
	unsigned isSeqAckNotConsistent:1;
	unsigned isLoginReceived:1;
	unsigned hasPrepareStat:1;
	unsigned isExcuteForTheFirstTime:1;
	unsigned hasMoreNewSession:1;
	unsigned retransmitSynTimes:4;

	void initSession()
	{
		numberOfExcutes=0;
		lastReqContSeq=0;
		nextSeq=0;
		synSeq=0;
		lastAck=0;
		handshakeExpectedPackets=2;
		virtual_next_sequence=0;
		virtual_ack=0;
		client_ip_id=0;
		initSessionForKeepalive();
		for(dataIterator iter=handshakePackets.begin();
				iter!=handshakePackets.end();)
		{
			free(*(iter++));
		}
		handshakePackets.clear();
		for(dataIterator iter=mysqlSpecialPackets.begin();
				iter!=mysqlSpecialPackets.end();)
		{
			free(*(iter++));
		}
		mysqlSpecialPackets.clear();

	}

	void initSessionForKeepalive()
	{
		lastSameAckTotal=0;
		contPacketsFromGreet=0;
		logRecordNum=0;
		lastRespPacketSize=0;
		total_seq_omit=0;
		logLevel=global_out_level;
		fake_ip_addr=0;
		isFakedSendingFinToBackend=0;
		isTestConnClosed=0;
		isSynIntercepted=0;
		isBackSynReceived=0;
		isHalfWayIntercepted=0;
		isStatClosed=0;
		isClientReset=0;
		isPureRequestBegin=0;
		isGreeingReceived=0;
		isNeedSecondAuth=0;
		loginCanSendFlag=0;
		isFirstAuthSent=0;
		candidateErased=0;
		isSeqAckNotConsistent=0;
		isLoginReceived=0;
		hasPrepareStat=0;
		isExcuteForTheFirstTime=1;
		hasMoreNewSession=0;
		retransmitSynTimes=0;
		virtual_status = SYN_SEND;
		reset_flag = 0;
		alreadyRetransmit=0;
		isNewRetransmit=0;
		simulClosing=0;
		over_flag = 0;
		isWaitPreviousPacket=0;
		isClientClosed=0;
		isKeepalive=0;
		isWaitResponse=0;
		isPartResponse=0;
		isResponseCompletely=0;
		isRequestComletely=1;
		isRequestBegin=0;
		isTrueWaitResponse=0;
		isSegContinue=0;
		confirmed=1;

		lastReqContSeq=0;
		nextSeq=0;
		synSeq=0;
		lastAck=0;
		lastAckFromResponse=0;
		lastSeqFromResponse=0;
		requestProcessed=0;
		responseReceived=0;
		reqContentPackets=0;
		sendConPackets=0;
		respContentPackets=0;
		lastUpdateTime=time(0);
		createTime=lastUpdateTime;
		lastRecvRespContentTime=lastUpdateTime;
		lastSendClientContentTime=lastUpdateTime;

		client_port=0;
		fake_client_port=0;
		
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
		for(dataIterator iter=unAckPackets.begin();iter!=unAckPackets.end();)
		{
			free(*(iter++));
		}
		unAckPackets.clear();

	}

	void initForNextSession()
	{
		initSession();
		for(dataIterator iter=nextSessionBuffer.begin();
				iter!=nextSessionBuffer.end();)
		{
			unsend.push_back(*iter);	
			iter++;
		}
		nextSessionBuffer.clear();
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
		for(dataIterator iter=nextSessionBuffer.begin();
				iter!=nextSessionBuffer.end();)
		{
			free(*(iter++));
		}
		nextSessionBuffer.clear();
		for(dataIterator iter=lostPackets.begin();iter!=lostPackets.end();)
		{
			free(*(iter++));
		}
		lostPackets.clear();
		for(dataIterator iter=unAckPackets.begin();iter!=unAckPackets.end();)
		{
			free(*(iter++));
		}
		unAckPackets.clear();

		for(dataIterator iter=handshakePackets.begin();
				iter!=handshakePackets.end();)
		{
			unsigned char* data=*(iter++);
			free(data);
		}
		handshakePackets.clear();
		for(dataIterator iter=mysqlSpecialPackets.begin();
				iter!=mysqlSpecialPackets.end();)
		{
			unsigned char* data=*(iter++);
			free(data);
		}
		mysqlSpecialPackets.clear();
	}
	void outputPacket(int level,int flag,struct iphdr *ip_header,
			struct tcphdr *tcp_header);
	void selectiveLogInfo(int level,const char *fmt, ...);
	int sendReservedLostPackets();
	int sendReservedPackets();
	int retransmitPacket();
	int updateRetransmissionPackets();
	bool checkReservedContainerHasContent();
	bool checkPacketLost(struct iphdr *ip_header,
			struct tcphdr *tcp_header,uint32_t oldSeq);
	bool checkSendingDeadReqs();
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
			struct tcphdr* tcp_header,bool changeSeq);
	void sendFakedFinToBackend(struct iphdr* ip_header,
			struct tcphdr* tcp_header);
	void sendFakedFinToBackByCliePack(struct iphdr* ip_header,
			struct tcphdr* tcp_header);
	void save_header_info(struct iphdr *ip_header,struct tcphdr *tcp_header);
	uint32_t wrap_send_ip_packet(uint64_t fake_ip_addr,
		unsigned char *data,uint32_t ack_seq,int isSave);

	bool checkMysqlPacketNeededForReconnection(struct iphdr *ip_header,
			struct tcphdr *tcp_header);
	void process_recv(struct iphdr *ip_header,struct tcphdr *tcp_header);
	void restoreBufferedSession();
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

