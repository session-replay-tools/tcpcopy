/*
 *  tcpcopy 
 *  An online replication replication tool for tcp based applications
 *
 *  Copyright 2011 Netease, Inc.  All rights reserved.
 *  Use and distribution licensed under the BSD license.
 *  See the LICENSE file for full text.
 *
 *  Authors:
 *      bin wang <wangbin579@gmail.com>
 *      bo  wang <wangbo@corp.netease.com>
 */

#include "../core/xcopy.h"
#include "manager.h"

/* Global variables */
xcopy_clt_settings clt_settings;

static void set_signal_handler(){
	atexit(tcp_copy_exit);
	signal(SIGINT,  tcp_copy_over);
	signal(SIGPIPE, tcp_copy_over);
	signal(SIGHUP,  tcp_copy_over);
	signal(SIGTERM, tcp_copy_over);
}


static void usage(void) {  
	printf("tcpcopy " VERSION "\n");
	printf("-x <transfer,> what we copy and where to send \n"
		   "               transfer format:\n"
		   "               online_ip:online_port-target_ip:target_port,...\n"
		   "-p <pair>      user password pair for mysql\n"
		   "               pair format:\n"
		   "               user1@psw1:user2@psw2:...\n"
		   "-n <num>       the number of replication for multi-copying\n"
		   "-f <num>       port shift factor for mutiple tcpcopy instances\n"
		   "-m <num>       max memory to use for tcpcopy in megabytes\n"
		   "-M <num>       MTU sent to backend(max value 4096)\n"
		   "-l <file>      log file path\n"
		   "-P <file>      save PID in <file>, only used with -d option\n"
		   "-h             print this help and exit\n"
		   "-v             version\n"
		   "-d             run as a daemon\n");
	return;
}



static int read_args(int argc, char **argv){
	int  c;
	
	while (-1 != (c = getopt(argc, argv,
		 "x:" /* where do we copy request from and to */
		 "p:" /* user password pair for mysql*/
		 "n:" /* the replicated number of each request for multi-copying */
		 "f:" /* port shift factor for mutiple tcpcopy instances */
		 "m:" /* max memory to use for tcpcopy client in megabytes */
		 "M:" /* MTU sent to backend */
		 "l:" /* error log file path */
		 "P:" /* save PID in file */
		 "h" /* help, licence info */   
		 "v"  /* verbose */
		 "d"  /* daemon mode */
	    ))) {
		switch (c) {
			case 'x':
				clt_settings.raw_transfer= strdup(optarg);
				break;
			case 'p':
				clt_settings.user_pwd = strdup(optarg);
				break;
			case 'n':
				clt_settings.replica_num = atoi(optarg);
				break;
			case 'f':
				clt_settings.factor = atoi(optarg);
				break;
			case 'm':
				clt_settings.max_rss = 1024*atoi(optarg);
				break;
			case 'l':
				clt_settings.log_path = strdup(optarg);
				break;
			case 'M':
				clt_settings.mtu = atoi(optarg);
				break;
			case 'h':
				usage();
				exit(EXIT_SUCCESS);
			case 'v':
				printf ("tcpcopy version:%s\n", VERSION);
				exit(EXIT_SUCCESS);
			case 'd':
				clt_settings.do_daemonize = 1;
				break;
			case 'P':
				clt_settings.pid_file = optarg;
				break;
			default:
				fprintf(stderr, "Illegal argument \"%c\"\n", c);
				exit(EXIT_FAILURE);
		}

	}

	/* Check mtu value is more than max mtu supported */
	if(clt_settings.mtu >MAX_MTU){
		clt_settings.mtu = MAX_MTU;
	}

	return 0;
}

static void output_for_debug(int argc, char **argv)
{
	/* Print tcpcopy version */
	log_info(LOG_NOTICE, "tcpcopy version:%s", VERSION);
	/* Print target */
	log_info(LOG_NOTICE, "target:%s", clt_settings.raw_transfer);

	/* Print tcpcopy working mode */
#if (TCPCOPY_MYSQL_SKIP)
	log_info(LOG_NOTICE, "TCPCOPY_MYSQL_SKIP mode");
#endif
#if (TCPCOPY_MYSQL_NO_SKIP)
	log_info(LOG_NOTICE, "TCPCOPY_MYSQL_NO_SKIP mode");
#endif
}

static int parse_ip_port_pair(const char *pair, uint32_t *ip,
		uint16_t *port)
{
	size_t     len;
	uint32_t   localhost  = inet_addr("127.0.0.1");	
	char       buffer[128];
	const char *split, *p = pair;
	uint32_t   inetAddr;

	split = strchr(p, ':');
	if(split != NULL){
		len = (size_t)(split - p);
		memset(buffer, 0 , 128);
		strncpy(buffer, p, len);
		inetAddr = inet_addr(buffer);	
		if(inetAddr == localhost){
			log_info(LOG_WARN, "ip address can not be loalhost");
			fprintf(stderr, "ip address can not be loalhost\n");
			exit(EXIT_FAILURE);
		}else{
			*ip = inetAddr;
		}
	}else{
		log_info(LOG_NOTICE,"ip does not exist:%s", p);
	}

	*port = atoi(p);

}

/*
 * One target format:
 * 192.168.0.1:80-192.168.0.2:8080 
 * or
 * 80-192.168.0.2:8080
 */
static void parse_one_target(int index, const char *target)
{
	size_t     len;
	char       buffer[128];
	const char *split, *p = target;
	uint32_t   ip;
	uint16_t   port;
	ip_port_pair_mapping_t *map;
	map = clt_settings.transfer.mappings[index];

	/* Parse online ip and port */
	split = strchr(p, '-');
	if(split != NULL){
		len = (size_t)(split - p);
	}else{
		log_info(LOG_WARN,"target info is not valid:%s", p);
		return;
	}
	strncpy(buffer, p, len);
	port = 0;
	ip   = 0;
	parse_ip_port_pair(buffer, &ip, &port);
	map->online_ip   = ip;
	map->online_port = port;
	p = split + 1;

	/* Parse target ip and port */
	port = 0;
	ip   = 0;
	parse_ip_port_pair(p, &ip ,&port);
	map->target_ip   = ip;
	map->target_port = port;
}

/* 
 * Retrieve target addresses
 * Format(by -x argument): 
 * 192.168.0.1:80-192.168.0.2:8080,192.168.0.1:3306-192.168.0.3:3306
 */
static int retrieve_target_addresses(){
	size_t     len, size;
	int        count = 1, i;
	const char *split, *p = clt_settings.raw_transfer;
	char       buffer[128];
	ip_port_pair_mapping_t **mappings;

	if(NULL == p){
		log_info(LOG_ERR, "it must have -x argument");
		fprintf(stderr, "no -x argument\n");
		exit(EXIT_FAILURE);
	}
	memset(buffer, 0, 128);
	
	/* Retrieve target number */
	while(1){
		split = strchr(p, ',');
		if(NULL == split){
			break;
		}else{
			p = split + 1;
			count++;
		}
	}

	/* Allocate resources for target */
	clt_settings.transfer.num = count;
	size = sizeof(ip_port_pair_mapping_t *);
	mappings = calloc(count, size);
	size = sizeof(ip_port_pair_mapping_t);
	for(i = 0; i < count; i++){
		mappings[i] = (ip_port_pair_mapping_t *)calloc(1, size);
	}
	clt_settings.transfer.mappings = mappings;

	/* Retrieve every target detail info */
	p = clt_settings.raw_transfer;
	i = 0;
	while(1){
		split = strchr(p, ',');
		if(split != NULL){
			len = (size_t)(split - p);
		}else{
			len = strlen(p);
		}
		/* Now we have one target*/
		strncpy(buffer, p, len);
		/* Parse this target info */
		parse_one_target(i, buffer);
		if(NULL == split){
			break;
		}else{
			p = split + 1;
		}
		memset(buffer, 0, 128);
		i++;
	}
	return 1;
}

static int set_details()
{
	int            rand_port, ret;
	struct timeval tp;
	unsigned int   seed;

	/* Generate random port for avoiding port conflicts */
	gettimeofday(&tp, NULL);
	seed = tp.tv_usec;
	rand_port = (int)((rand_r(&seed)/(RAND_MAX+1.0))*512);
	clt_settings.rand_port_shifted = rand_port;
	/* Set signal handler */	
	set_signal_handler();
	/* Set ip port pair mapping according to settings*/
	retrieve_target_addresses();
#if (TCPCOPY_MYSQL_ADVANCED)  
	if(NULL != clt_settings.user_pwd){
		retrieve_mysql_user_pwd_info(clt_settings.user_pwd);
	}else{
		log_info(LOG_ERR, "it must have -p argument");
		fprintf(stderr, "no -p argument\n");
		exit(EXIT_FAILURE);

	}
#endif

	/* Daemonize */
	if (clt_settings.do_daemonize) {
		if (sigignore(SIGHUP) == -1) {
			perror("Failed to ignore SIGHUP");
			log_info(LOG_ERR, "Failed to ignore SIGHUP");
		}    
		if (daemonize() == -1) {
			fprintf(stderr, "failed to daemon() in order to daemonize\n");
			exit(EXIT_FAILURE);
		}    
	}    
}

/* defaults */
static int settings_init()
{
	/* Init values */
	clt_settings.mtu = DEFAULT_MTU;
	clt_settings.max_rss = MAX_MEMORY_SIZE;
}

/*
 * Main entry point
 */
int main(int argc ,char **argv)
{
	int ret;
	/* set defaults*/
	settings_init();
	/* Read args */
	read_args(argc, argv);
	/* Init log for outputing debug info */
	log_init(clt_settings.log_path);
	/* Output debug info */
	output_for_debug(argc, argv);
	/* Set details for running */
	set_details();
	/* Initiate tcpcopy client*/
	ret = tcp_copy_init();
	if(SUCCESS != ret){
		exit(EXIT_FAILURE);
	}
	/* Run now */
	select_server_run();
	return 0;
}

