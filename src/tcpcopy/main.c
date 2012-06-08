/*
 *  tcpcopy 
 *  an online replication replication tool for tcp based applications
 *
 *  Copyright 2011 Netease, Inc.  All rights reserved.
 *  Use and distribution licensed under the BSD license.
 *  See the LICENSE file for full text.
 *
 *  Authors:
 *      bin wang <wangbin579@gmail.com>
 *      bo  wang <wangbo@corp.netease.com>
 */

#include <xcopy.h>


static pthread_mutex_t mutex;
static pthread_cond_t  empty, full;
static char pool[RECV_POOL_SIZE];
static char item[DEFAULT_MTU+DEFAULT_MTU];
static int raw_sock, read_over_flag = 1, replica_num = 1;
static uint64_t read_cnt  = 0, write_cnt = 0;
static uint64_t event_cnt = 0, packs_put_cnt=0;
static uint64_t raw_packets = 0, raw_valid_packets = 0;
static uint64_t recv_pack_cnt_from_pool = 0;

/*
 * Put the packet to the buffered pool
 */
static void put_packet_to_pool(const char *packet, int len){
	int       act_len = len, next_w_pointer = 0, writePointer = 0;
	int       *size_p = NULL;
	uint64_t  next_w_cnt = 0, diff = 0;
	char      *p = NULL;

	packs_put_cnt++;

	pthread_mutex_lock(&mutex);

	next_w_cnt     = write_cnt + len + sizeof(int);	
	next_w_pointer = next_w_cnt%RECV_POOL_SIZE;
	if(next_w_pointer > MAX_ADDR)
	{
		next_w_cnt = (next_w_cnt/RECV_POOL_SIZE + 1)<<RECV_POOL_SIZE_SHIFT;
		len += RECV_POOL_SIZE - next_w_pointer;
	}
	diff = next_w_cnt - read_cnt;
	while(1)
	{
		if(diff > RECV_POOL_SIZE)
		{
			log_info(LOG_ERR, "pool is full");
			log_info(LOG_ERR, "read:%llu, write:%llu, next_w_cnt:%llu",
					read_cnt, write_cnt, next_w_cnt);
			pthread_cond_wait(&empty, &mutex);
		}else
		{
			break;
		}
		diff = next_w_cnt - read_cnt;
	}
	writePointer = write_cnt % RECV_POOL_SIZE;
	size_p       = (int*)(pool + writePointer);
	p            = pool + writePointer + sizeof(int);
	write_cnt    = next_w_cnt;
	/* Put packet to pool */
	memcpy(p, packet, act_len);
	*size_p      = len;
	pthread_cond_signal(&full);
	pthread_mutex_unlock(&mutex);
}


/*
 * Get one packet from buffered pool
 */
static char *get_packt_from_pool(){
	int  read_pos, len;
	char *p;

	recv_pack_cnt_from_pool++;
	read_over_flag = 0;

	pthread_mutex_lock (&mutex);
	if(read_cnt >= write_cnt)
	{
		read_over_flag = 1;
		pthread_cond_wait(&full, &mutex);
	}
	read_pos = read_cnt%RECV_POOL_SIZE;
	p        = pool + read_pos + sizeof(int);
	len      = *(int*)(pool + read_pos);
	memcpy(item, p, len);
	read_cnt = read_cnt + len + sizeof(int);
	pthread_cond_signal(&empty);
	pthread_mutex_unlock (&mutex);

	/* The min packet length is 40 bytes */
	if(len < 40){
		log_info(LOG_WARN, "packet len is less than 40");
	}
	if(recv_pack_cnt_from_pool%10000 == 0){
		log_info(LOG_INFO, "recv from pool :%llu,put in pool:%llu",
				recv_pack_cnt_from_pool, packs_put_cnt);
	}

	return item;
}

/*
 * Process packets here
 */
static void *dispose(void *thread_id) {
	char *packet;

	if(NULL != thread_id){
		printf("I am booted,thread id:%d\n", *((int*)thread_id));
		log_info(LOG_NOTICE, "I am booted,thread id:%d",
				*((int*)thread_id));
	}else{
		printf("I am booted\n");
		log_info(LOG_NOTICE, "I am booted with no thread id");
	}
	while(1){
		packet = get_packt_from_pool();
		process(packet);
	}

	return NULL;
}

static void set_nonblock(int socket){
	int flags;
	flags = fcntl(socket, F_GETFL, 0);
	fcntl(socket, F_SETFL, flags | O_NONBLOCK);
}

/* Initiate input raw socket */
static int init_raw_socket()
{
	int       sock, recv_buf_opt, result;
	socklen_t opt_len;
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
	sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
#else 
	/* copy ip datagram from IP layer*/
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
#endif
	if(-1 == sock){
		perror("socket");
		log_info(LOG_ERR, "%s", strerror(errno));	
	}
	set_nonblock(sock);
	rcv_buf_opt   = 67108864;
	opt_len = sizeof(int);
	int ret = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcv_buf_opt,
			opt_len);
	if(-1 == ret){
		perror("setsockopt");
		log_info(LOG_ERR, "%s", strerror(errno));	
	}

	return sock;
}

/* Replicate packets */
static int replicate_packs(const char *packet,int length){			
	int           i;
	struct tcphdr *tcp_header;
	struct iphdr  *ip_header;
	uint32_t      size_ip;
	uint16_t      tmp_port_addition, transfered_port;
	
	for(i = 1; i<replica_num; i++){
		ip_header  = (struct iphdr*)packet;
		size_ip    = ip_header->ihl << 2;
		tcp_header = (struct tcphdr*)((char *)ip_header + size_ip);
		tmp_port_addition= (1024 << ((i << 1)-1)) + rand_shift_port;
		transfered_port  = ntohs(tcp_header->source);
		if(transfered_port <= (65535-tmp_port_addition)){    
			transfered_port = transfered_port + tmp_port_addition;
		}else{    
			transfered_port = 1024 + tmp_port_addition;
		}    
#if (DEBUG_TCPCOPY)
		log_info(LOG_DEBUG, "shift port:%u", tmp_port_addition);
#endif
		tcp_header->source = htons(transfered_port);
		put_packet_to_pool((const char*)packet, length);
	}

	return 0;

}

/*
 * Retrieve raw packets
 */
static int retrieve_raw_sockets(int sock){

	char recv_buf[RECV_BUF_SIZE], tmp_packet[DEFAULT_MTU];
	char *packet;
	int  i, err, count = 0, recv_len, packet_num, m_payload_len;
	struct tcphdr *tcp_header;
	struct iphdr  *ip_header;
	uint32_t size_ip, size_tcp, tot_len, cont_size, syn;

	while(1){
		recv_len = recvfrom(sock, recv_buf, RECV_BUF_SIZE, 0,
				NULL, NULL);
		if(recv_len < 0){
			err = errno;
			if(EAGAIN == err){
				break;
			}
			perror("recvfrom");
			log_info(LOG_ERR, "recvfrom:%s", strerror(errno));
		}
		if(0 == recv_len){
			log_info(LOG_ERR, "recv len is 0");
			break;
		}
		raw_packets++;
		if(recv_len > RECV_BUF_SIZE){
			log_info(LOG_ERR, "recv_len:%d ,it is too long",
					recv_len);
		}
		packet = recv_buf;
		if(isPacketNeeded((const char *)packet)){
			raw_valid_packets++;
#if (MULTI_THREADS)  
			packet_num = 1;
			/* If packet length larger than 1500,we split it */
			if(recv_len > DEFAULT_MTU){
				/* Calculate packet number */
				ip_header  = (struct iphdr*)packet;
				size_ip    = ip_header->ihl << 2;
				tot_len    = ntohs(ip_header -> tot_len);
				tcp_header = (struct tcphdr*)((char *)ip_header + size_ip);
				size_tcp   = tcp_header->doff << 2;
				cont_size  = tot_len - size_tcp - size_ip;
				m_payload_len = DEFAULT_MTU - size_tcp - size_ip;
				packet_num = (cont_size + m_payload_len - 1)/m_payload_len;
				syn        = ntohl(tcp_header->seq);
				if(tot_len > RECV_BUF_SIZE){
					log_info(LOG_ERR, "receive an abnormal packet:%d",
							tot_len);
					count++;
					continue;
				}
				for(i = 0 ; i<packet_num; i++){
					tcp_header->seq = htonl(syn + i * m_payload_len);
					if(i != (packet_num-1)){
						ip_header->tot_len = DEFAULT_MTU;
					}else{
						ip_header->tot_len = size_tcp + size_ip +
							(cont_size - i * m_payload_len);
					}
					put_packet_to_pool((const char*)packet, 
							ip_header->tot_len);
					if(replica_num > 1){
						memcpy(tmp_packet, packet, ip_header->tot_len);
						replicate_packs(tmp_packet, ip_header->tot_len);
					}
				}
			}else{
				put_packet_to_pool((const char*)packet, recv_len);
				/* Multi-copy is only supported in multithreading mode */
				if(replica_num > 1){
					replicate_packs(packet, recv_len);
				}
			}
#else
			process(packet);
#endif
		}
		count++;
		if(raw_packets%100000 == 0){
			log_info(LOG_NOTICE,
					"raw packets:%llu, valid :%llu, total in pool:%llu",
					raw_packets, raw_valid_packets, packs_put_cnt);
		}
	}

	return 0;
}

static void check_memory_usage(const char* path){
	FILE      *fp ;
	const int BUF_SIZE = 2048;
	char      buf[BUF_SIZE];
	char      *p=NULL;
	int       index = 0, memory = 0;

	fp = fopen(path, "r");
	if(!fp){
		log_info(LOG_ERR, "%s can't be opened", path);
		exit(1);
	}

	while(fgets(buf,BUF_SIZE,fp) != NULL){
		if(strlen(buf) > 0 && strstr(buf, MEMORY_USAGE) != NULL){

			log_info(LOG_WARN, "memory usage:%s", buf);
			index = strlen(MEMORY_USAGE);
			p     = buf + index;

			while(index < BUF_SIZE && !isdigit(p[0])){
				index++;
				p++;
			}

			if(index < BUF_SIZE){
				memory = atoi(p);
				//if more than 0.5G,then we exit
				if(memory > MAX_MEMORY_SIZE){
					log_info(LOG_ERR, "it occupies too much memory:%d KB",
							memory);
					fclose(fp);
					exit(1);
				}
			}else
			{
				log_info(LOG_ERR, "no memroy info");
				fclose(fp);
				exit(1);
			}
		}
	}

	fclose(fp);
}

/* Dispose one event*/
static void dispose_event(int fd){
	struct msg_server_s *msg;
	int                 pid;
	char                path[512];

	event_cnt++;
	if(fd == raw_sock){
		retrieve_raw_sockets(fd);
	}else{
		msg = msg_client_recv(fd);
		if(NULL == msg ){
			fprintf(stderr, "msg is null:\n");
			log_info(LOG_ERR, "msg is null from msg_client_recv");
			exit(1);
		}   
#if (MULTI_THREADS)  
		put_packet_to_pool((const char*)msg, sizeof(msg_server_s));
#else
		process((char*)msg);
#endif
	}   
	if((event_cnt%1000000) == 0){
		pid = getpid();
		sprintf(path, "/proc/%d/status", pid);
		check_memory_usage(path);
	}
}

static void exit_tcp_copy(){
	close(raw_sock);
	raw_sock = -1;
	send_close();
	exit(0);
}

static void tcp_copy_over(const int sig){
	int total = 0;

	log_info(LOG_WARN, "sig %d received", sig);
	while(!read_over_flag){
		log_info(LOG_WARN, "sleep one second");
		sleep(1);
		total++;
		if(total > 30)
		{
			break;
		}
	}
	if(-1 != raw_sock)
	{
		close(raw_sock);
	}
	send_close();
	end_log_info();
	exit(0);
}

static void set_signal_handler(){
	atexit(exit_tcp_copy);
	signal(SIGINT,  tcp_copy_over);
	signal(SIGPIPE, tcp_copy_over);
	signal(SIGHUP,  tcp_copy_over);
	signal(SIGTERM, tcp_copy_over);
}

static int init_tcp_copy(){
#if (MULTI_THREADS)  
	pthread_t thread;
#endif
	select_sever_set_callback(dispose_event);
	raw_sock = init_raw_socket();
	if(raw_sock != -1){
		select_sever_add(raw_sock);
		/* Init output raw socket info */
		send_init();
#if (MULTI_THREADS)  
		pthread_mutex_init(&mutex, NULL);
		pthread_cond_init(&full, NULL);
		pthread_cond_init(&empty, NULL);
		pthread_create(&thread, NULL, dispose, NULL);
#endif
		/* Add a connection to the tested server for exchanging info */
		add_msg_connetion(local_port, remote_ip, remote_port);
		log_info(LOG_NOTICE,"add a tunnel for exchanging info:%u",
				ntohs(remote_port));

		return SUCCESS;
	}else
	{
		return FAILURE;
	}

}

/*
 * Retrieve all valid local ip addresses
 * 127.0.0.1 or localhost is not valid here
 */
static int retrieveVirtualIPAddress(const char* ips){
	size_t     len;
	int        count = 0;
	const char *split, *p = ips;
	char       tmp[32];
	uint32_t   localhost = inet_addr("127.0.0.1");	
	uint32_t   inetAddr  = 0;

	memset(tmp,0,32);

	while(1){
		split=strchr(p, ':');
		if(split != NULL){
			len = (size_t)(split-p);
		}else{
			len = strlen(p);
		}
		strncpy(tmp, p, len);
		inetAddr = inet_addr(tmp);	
		if(inetAddr == localhost){
			return 0;
		}
		local_ips.ips[count++] = inetAddr;
		if(NULL == split){
			break;
		}else{
			p = split + 1;
		}
		memset(tmp, 0, 32);
	}
	local_ips.num = count;
	return 1;
}


int readArgs (int argc, char **argv){
	char pairs[512];
	int  c, result=0, option_index;
	while (1) {
		option_index = 0;
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
				strcpy(pairs, optarg);
				retrieveMysqlUserPwdInfo(pairs);
				result = 1;
#endif
				break;
			case 'n':
				replica_num = atoi(optarg);
				if(replica_num < 1)
				{
					replica_num = 1;
				}
#if (!TCPCOPY_MYSQL_ADVANCED)  
				result = 1;
#endif
				break;

			case 'f':
				port_shift_factor = atoi(optarg);
#if (!TCPCOPY_MYSQL_ADVANCED)  
				result = 1;
#endif
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

/*
 * Main entry point
 */
int main(int argc ,char **argv)
{
	int            result = 1;
	struct timeval tp;
	unsigned int   seed;

	if(argc < 5)
	{
		printf("Usage: %s 61.135.250.1 80 61.135.250.2 80\n",
				argv[0]);
		exit(1);
	}
	init_log_info();
	log_info(LOG_NOTICE, "%s %s %s %s %s", argv[0], argv[1],
			argv[2], argv[3], argv[4]);
	log_info(LOG_NOTICE, "tcpcopy version:%s", VERSION);
#if (TCPCOPY_MYSQL_SKIP)
	log_info(LOG_NOTICE, "TCPCOPY_MYSQL_SKIP mode");
#endif
#if (TCPCOPY_MYSQL_NO_SKIP)
	log_info(LOG_NOTICE, "TCPCOPY_MYSQL_NO_SKIP mode");
#endif
	
	result=retrieveVirtualIPAddress(argv[1]);
	if(!result)
	{
		fprintf(stderr, "local ip or domain is not supported:\n");
		log_info(LOG_ERR, "local ip or domain is not supported");
	}
	local_port  = htons(atoi(argv[2]));
	remote_ip   = inet_addr(argv[3]);
	remote_port = htons(atoi(argv[4]));

	if(argc > 5)
	{
		if(!readArgs(argc, argv))
		{
#if (TCPCOPY_MYSQL_ADVANCED)  
			log_info(LOG_ERR,"user password pair is missing:%d",argc);
#endif
		}
	}else
	{
#if (TCPCOPY_MYSQL_ADVANCED)  
		log_info(LOG_ERR, "user password pair is missing");
		printf("Usage: %s 1.1.1.1 80 1.1.1.2 80 -p user1@psw1:user2@psw2:...\n",
				argv[0]);
		exit(1);
#endif
	}

	if(port_shift_factor || replica_num > 1)
	{
		gettimeofday(&tp, NULL);
		seed = tp.tv_usec;
		rand_shift_port = (int)((rand_r(&seed)/(RAND_MAX + 1.0))*512);

		if(port_shift_factor)
		{
			log_info(LOG_NOTICE, "port shift factor:%u",
					port_shift_factor);
		}else
		{
			log_info(LOG_NOTICE, "replica num:%d", replica_num);
		}
		log_info(LOG_NOTICE, "random shift port:%u", rand_shift_port);
	}

	set_signal_handler();
	if(SUCCESS == init_tcp_copy())
	{
		select_server_run();
		return 0;
	}else
	{
		return 1;
	}
}

