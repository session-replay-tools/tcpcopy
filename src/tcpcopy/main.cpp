/*
 *  tcpcopy - an online replication replication tool
 *
 *  Copyright 2011 Netease, Inc.  All rights reserved.
 *  Use and distribution licensed under the BSD license.  See
 *  the LICENSE file for full text.
 *
 *  Authors:
 *      bin wang <163.beijing@gmail.com or bwang@corp.netease.com>
 *      bo  wang <wangbo@corp.netease.com>
 */

#include <fcntl.h>
#include <asm/types.h>
#include <sys/socket.h> 
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <pthread.h>
#include <unistd.h>
#include <ctype.h>
#include <getopt.h>

#include "session.h"
#include "send.h"
#include "address.h"
#include "../event/select_server.h"
#include "../log/log.h"
#if (TCPCOPY_MYSQL_NO_SKIP)
#include "../mysql/pairs.h"
#endif
#include "../communication/msg.h"

#define MAX_IP_LEN 4096
#define RECV_POOL_SIZE 67108864
#define RECV_POOL_SIZE_SHIFT 26
#define MAX_ADDR 67106816
#define MAX_MEMORY_SIZE 524288
#define SUCCESS 0
#define FAILURE -1
#define MULTI_THREADS 1
#define MEMORY_USAGE "VmRSS:"
#define VERSION "0.4.0"

static pthread_mutex_t mutex;
static pthread_cond_t empty;
static pthread_cond_t full;
static char recvpool[RECV_POOL_SIZE];
static char recvitem[MAX_IP_LEN];
static uint64_t readCounter=0;
static uint64_t writeCounter=0;

static int raw_sock;
static uint64_t eventTotal=0;
static uint64_t packetsPutNum=0;
static bool isReadCompletely=true;

static int replica_num=1;

/**
 * put one packet to buffered pool
 */
static void putPacketToPool(const char *packet,int len)
{
	packetsPutNum++;
	int actualLen=len;
	pthread_mutex_lock (&mutex);
	uint64_t nextWPos=writeCounter+len+sizeof(int);	
	int writeNextPointer=nextWPos%RECV_POOL_SIZE;
	if(writeNextPointer>MAX_ADDR)
	{
		nextWPos=(nextWPos/RECV_POOL_SIZE+1)<<RECV_POOL_SIZE_SHIFT;
		len+=RECV_POOL_SIZE-writeNextPointer;
	}
	uint64_t diff=nextWPos-readCounter;
	while(true)
	{
		if(diff>RECV_POOL_SIZE)
		{
			logInfo(LOG_ERR,"pool is full,read:%llu,write:%llu,nextWPos:%llu",
					readCounter,writeCounter,nextWPos);
			pthread_cond_wait(&empty, &mutex);
		}else
		{
			break;
		}
		diff=nextWPos-readCounter;
	}
	int writePointer=writeCounter%RECV_POOL_SIZE;
	int* sizeP=(int*)(recvpool+writePointer);
	char* p=recvpool+writePointer+sizeof(int);
	writeCounter=nextWPos;
	//put packet to pool
	memcpy(p,packet,actualLen);
	*sizeP=len;
	pthread_cond_signal(&full);
	pthread_mutex_unlock (&mutex);
}

static uint64_t recvFromPoolPackets=0;

/**
 * get one packet from buffered pool
 */
static char* getPacketFromPool()
{
	recvFromPoolPackets++;
	pthread_mutex_lock (&mutex);
	isReadCompletely=false;
	if(readCounter>=writeCounter)
	{
		isReadCompletely=true;
		pthread_cond_wait(&full, &mutex);
	}
	int readPos=readCounter%RECV_POOL_SIZE;
	char* p=recvpool+readPos+sizeof(int);
	int len=*(int*)(recvpool+readPos);
	memcpy(recvitem,p,len);
	readCounter=readCounter+len+sizeof(int);
	if(len<40)
	{
		logInfo(LOG_WARN,"packet len is less than 40");
	}

	pthread_cond_signal(&empty);
	pthread_mutex_unlock (&mutex);
	if(recvFromPoolPackets%10000==0)
	{
		logInfo(LOG_INFO,"recv from pool packets:%llu,put packets in pool:%llu",
				recvFromPoolPackets,packetsPutNum);
	}
	return recvitem;
}

/**
 * processing packets here
 */
static void *dispose(void *threadid) 
{
	if(NULL!=threadid)
	{
		printf("I am booted,thread id:%d\n",*((int*)threadid));
		logInfo(LOG_INFO,"I am booted,thread id:%d",*((int*)threadid));
	}else
	{
		printf("I am booted\n");
		logInfo(LOG_INFO,"I am booted with no thread id");
	}
	while(1)
	{
		char* packet=getPacketFromPool();
		process(packet);
	}
	return NULL;
}

static void set_nonblock(int socket)
{
	int flags;
	flags = fcntl(socket,F_GETFL,0);
	fcntl(socket, F_SETFL, flags | O_NONBLOCK);
}


static int init_raw_socket()
{
#if (COPY_LINK_PACKETS)
	/* 
	 * AF_PACKET
	 * Packet sockets are used to receive or send raw packets 
	 * at the device driver level.They allow the user to 
	 * implement protocol modules in user space on top of 
	 * the physical layer. 
	 * ETH_P_IP
	 * Internet Protocol packet that is related to the Ethernet 
	 */
	int sock = socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_IP));
#else 
	/* copy ip datagram from IP layer*/
	int sock = socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
#endif
	if(-1 == sock)
	{
		perror("socket");
	}
	set_nonblock(sock);
	int rcvbuf_opt=67108864;
	socklen_t optlen=sizeof(int);
	int ret = setsockopt(sock,SOL_SOCKET,SO_RCVBUF,&rcvbuf_opt,optlen);
	if(-1 == ret)
	{
		perror("setsockopt");
	}
	return sock;
}

static uint64_t rawPackets=0;
static uint64_t rawValidPackets=0;

/**
 * retrieve raw packets here
 */
static int retrieve_raw_sockets(int sock)
{

	char recvbuf[RECV_BUF_SIZE];
	memset(recvbuf,0,RECV_BUF_SIZE);
	int err=0;
	int count=0;
	while(true)
	{
		int recv_len = recvfrom(sock,recvbuf,RECV_BUF_SIZE,0,NULL,NULL);
		if(recv_len < 0)
		{
			err=errno;
			if(EAGAIN==err)
			{
				break;
			}
			perror("recvfrom");
			logInfo(LOG_ERR,"recvfrom info error");
		}
		if(recv_len==0)
		{
			logInfo(LOG_ERR,"recv len is 0");
			break;
		}
		rawPackets++;
		if(recv_len>RECV_BUF_SIZE)
		{
			printf("recv_len:%d ,it is too long for recvbuf\n",recv_len);
			logInfo(LOG_ERR,"recv_len:%d ,it is too long for recvbuf",recv_len);
		}
		char* packet=recvbuf;
		if(isPacketNeeded((const char* )packet))
		{
			rawValidPackets++;
#if (MULTI_THREADS)  
			putPacketToPool((const char*)packet,recv_len);
			/*multi-copy is only supported in multithreading mode*/
			if(replica_num>1)
			{
				int i=1;
				struct tcphdr *tcp_header=NULL;
				struct iphdr *ip_header=NULL;
				uint32_t size_ip;
				int randNum=0;
				for(;i<replica_num;i++)
				{
					ip_header = (struct iphdr*)packet;
					size_ip = ip_header->ihl<<2;
					tcp_header = (struct tcphdr*)((char *)ip_header+size_ip);
					uint16_t tmp_port_addition=(1024<<((i<<1)-1))
						+rand_shift_port;
					uint16_t transfered_port=ntohs(tcp_header->source);
					if(transfered_port<=(65535-tmp_port_addition))
					{    
						transfered_port=transfered_port+tmp_port_addition;
					}else
					{    
						transfered_port=1024+tmp_port_addition;
					}    
#if (DEBUG_TCPCOPY)
					logInfo(LOG_DEBUG,"shift port:%u",tmp_port_addition);
#endif
					tcp_header->source=htons(transfered_port);
					putPacketToPool((const char*)packet,recv_len);
				}
			}
#else
			process(packet);
#endif
		}
		count++;
		if(rawPackets%100000==0)
		{
			logInfo(LOG_NOTICE,
					"recv raw packets:%llu,valid :%llu,total in pool:%llu\n",
					rawPackets,rawValidPackets,packetsPutNum);
		}
	}

	return 0;
}

static void checkMemoryUsage(const char* path)
{
	FILE* fp=fopen(path,"r");
	if(!fp)
	{
		logInfo(LOG_ERR,"%s can't be opened",path);
		exit(1);
	}
	const int BUF_SIZE=2048;
	char buf[BUF_SIZE];
	char *p=NULL;
	int index=0;
	int memory=0;
	while(fgets(buf,BUF_SIZE,fp)!=NULL)
	{
		if(strlen(buf)>0&&strstr(buf,MEMORY_USAGE)!=NULL)
		{
			logInfo(LOG_WARN,"memory usage:%s",buf);
			index=strlen(MEMORY_USAGE);
			p=buf+index;

			while(index<2048&&!isdigit(p[0]))
			{
				index++;
				p++;
			}
			if(index<2048)
			{
				memory=atoi(p);
				//if more than 0.5G,suicide
				if(memory>MAX_MEMORY_SIZE)
				{
					logInfo(LOG_ERR,"tcpcopy occupies too much memory:%d KB",
							memory);
					fclose(fp);
					exit(1);
				}
			}else
			{
				logInfo(LOG_ERR,"no memroy info");
				fclose(fp);
				exit(1);
			}
		}
	}
	fclose(fp);
}


static void dispose_event(int fd){
	eventTotal++;
	if(fd == raw_sock){
		retrieve_raw_sockets(fd);
	}else{
		struct receiver_msg_st * msg = msg_copyer_recv(fd);
		if(NULL == msg ){
			fprintf(stderr,"socket error:\n");
			exit(1);
		}   
		//it changes source port for this packet
		(msg->tcp_header).source=remote_port;
		//it is tricked as if from tested machine
#if (MULTI_THREADS)  
		putPacketToPool((const char*)msg,sizeof(receiver_msg_st));
#else
		process((char*)msg);
#endif
	}   
	if((eventTotal%1000000)==0)
	{
		//retrieve memory usage by this process
		//if more than 0.5G,then suicide
		int pid=getpid();
		char path[512];
		sprintf(path,"/proc/%d/status",pid);
		checkMemoryUsage(path);
	}
}

static void exit_tcp_copy(){
	close(raw_sock);
	send_close();
	exit(0);
}

static void tcp_copy_over(const int sig){
	logInfo(LOG_WARN,"sig %d received",sig);
	int total=0;
	while(!isReadCompletely)
	{
		logInfo(LOG_WARN,"sleep one second");
		sleep(1);
		total++;
		if(total>30)
		{
			break;
		}
	}
	close(raw_sock);
	send_close();
	endLogInfo();
	exit(0);
}

static void set_signal_handler(){
	atexit(exit_tcp_copy);
	signal(SIGINT,tcp_copy_over);
	signal(SIGPIPE,tcp_copy_over);
	signal(SIGHUP,tcp_copy_over);
	signal(SIGTERM,tcp_copy_over);
}

static int init_tcp_copy()
{
	select_sever_set_callback(dispose_event);
	raw_sock=init_raw_socket();
	if(raw_sock!=-1)
	{
		select_sever_add(raw_sock);
		/*init sending info*/
		send_init();
#if (MULTI_THREADS)  
		pthread_t thread;
		pthread_mutex_init(&mutex,NULL);
		pthread_cond_init(&full,NULL);
		pthread_cond_init(&empty,NULL);
		pthread_create(&thread,NULL,dispose,NULL);
#endif
		//add a connection to the tested server for exchanging infomation
		add_msg_connetion(local_port,remote_ip,remote_port);
		logInfo(LOG_NOTICE,"add a tunnel for exchanging information:%u",
				ntohs(remote_port));

		return SUCCESS;
	}else
	{
		return FAILURE;
	}

}

/**
 * retrieve all valid local ip addresses
 * 127.0.0.1 or localhost is not valid here
 */
static int retrieveVirtualIPAddress(const char* ips)
{
	size_t len;
	int count=0;
	const char* split;
	const char* p=ips;
	char tmp[32];
	memset(tmp,0,32);
	uint32_t localhost=inet_addr("127.0.0.1");	
	uint32_t inetAddr=0;
	while(true)
	{
		split=strchr(p,':');
		if(split!=NULL)
		{
			len=(size_t)(split-p);
		}else
		{
			len=strlen(p);
		}
		strncpy(tmp,p,len);
		inetAddr=inet_addr(tmp);	
		if(inetAddr==localhost)
		{
			return false;
		}
		local_ips.ips[count++]=inetAddr;
		if(NULL==split)
		{
			break;
		}else
		{
			p=split+1;
		}
		memset(tmp,0,32);

	}
	local_ips.num=count;
	return true;
}

typedef struct _tcpcopy_options TcpcopyOptions;                                                                                
struct _tcpcopy_options
{
	char *conf_file;
};

TcpcopyOptions options = {
	"tcpcopy.conf"
};

int readArgs (int argc,
		char **argv,
		TcpcopyOptions *options)
{
	int c;
	char pairs[512];
	int result=0;
	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"pairs",  1, 0, 'p'},
			{"num",  1, 0, 'n'},
			{"port_shift_factor",  1, 0, 'f'},
			{"help",       0, 0, 'h'},
			{"version",    0, 0, 'v'},
			{0, 0, 0, 0}
		};
		c = getopt_long (argc, argv, "n:p:hv",
				long_options, &option_index);
		if (c == -1) {
			break;
		}
		switch (c) {			
			case 'p':
#if (TCPCOPY_MYSQL_ADVANCED)  
				strcpy(pairs,optarg);
				retrieveMysqlUserPwdInfo(pairs);
				result=1;
#endif
				break;
			case 'n':
				replica_num=atoi(optarg);
				if(replica_num<1)
				{
					replica_num=1;
				}
#if (!TCPCOPY_MYSQL_ADVANCED)  
				result=1;
#endif
				break;

			case 'f':
				port_shift_factor=atoi(optarg);
#if (!TCPCOPY_MYSQL_ADVANCED)  
				result=1;
#endif
				break;
			case 'c':
				options->conf_file = (char*)malloc(strlen(optarg) + 1);
				if (!options->conf_file) {
					fprintf(stderr, "Not enough memory to "
							"launch rinetd.\n");
					exit(1);
				}
				strcpy(options->conf_file, optarg);
				break;
			case 'h':
				printf("Usage: tcpcopy [OPTION]\n"
						"  -p, --pair    user password pair for mysqlcopy \n"
						"  -n, --num     multicopy number of tcpcopy\n"
						"  -f, --port_shift_factor  client port shift factor\n"
						"  -h, --help    display this help\n"
						"  -v, --version display version number\n"
						"\n");
				exit (0);
			case 'v':
				printf ("rinetd %s\n", VERSION);
				exit (0);
			case '?':
			default:
				exit (1);
		}
	}
	return result;
}

/**
 * main entry point
 */
int main(int argc ,char **argv)
{
	bool result=true;
	if(argc < 5)
	{
		printf("Usage: %s 61.135.250.1 80 61.135.250.2 80\n",
				argv[0]);
		exit(1);
	}
	initLogInfo();
	logInfo(LOG_NOTICE,"%s %s %s %s %s",argv[0],argv[1],
			argv[2],argv[3],argv[4]);
	logInfo(LOG_NOTICE,"tcpcopy version:%s",VERSION);
#if (TCPCOPY_MYSQL_SKIP)
	logInfo(LOG_NOTICE,"TCPCOPY_MYSQL_SKIP mode");
#endif
#if (TCPCOPY_MYSQL_NO_SKIP)
	logInfo(LOG_NOTICE,"TCPCOPY_MYSQL_NO_SKIP mode");
#endif
	
	result=retrieveVirtualIPAddress(argv[1]);
	if(!result)
	{
		printf("it does not support local ip addr or domain name");
		logInfo(LOG_ERR,"it does not support local ip addr or domain name");
	}
	local_port = htons(atoi(argv[2]));
	remote_ip = inet_addr(argv[3]);
	remote_port = htons(atoi(argv[4]));

	if(argc>5)
	{
		if(!readArgs(argc,argv,&options))
		{
#if (TCPCOPY_MYSQL_ADVANCED)  
			logInfo(LOG_ERR,"user password pair is missing:%d",argc);
#endif
		}
	}else
	{
#if (TCPCOPY_MYSQL_ADVANCED)  
		logInfo(LOG_ERR,"user password pair is missing");
		printf("Usage: %s 1.1.1.1 80 1.1.1.2 80 -p user1@psw1:user2@psw2:...\n",
				argv[0]);
		exit(1);
#endif
	}

	if(port_shift_factor||replica_num>1)
	{
		struct timeval tp;
		gettimeofday(&tp,NULL);
		unsigned int seed=tp.tv_usec;
		rand_shift_port=(int)((rand_r(&seed)/(RAND_MAX+1.0))*512);

		if(port_shift_factor)
		{
			logInfo(LOG_NOTICE,"port shift factor:%u",port_shift_factor);
		}else
		{
			logInfo(LOG_NOTICE,"replica num:%d",replica_num);
		}
		logInfo(LOG_NOTICE,"random shift port:%u",rand_shift_port);
	}

	set_signal_handler();
	if(SUCCESS==init_tcp_copy())
	{
		select_server_run();
		return 0;
	}else
	{
		return 1;
	}
}

