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
	printf("-t <tranfer>  what we copy and where to send \n"
		   "              transfer format:\n"
		   "              online_ip:online_port->target_ip:target_port|...\n"
		   "-p <pair>     user password pair for mysql\n"
		   "              pair format:\n"
		   "              user1@psw1:user2@psw2:...\n"
		   "-n <num>      the number of replication for multi-copying\n"
		   "-f <num>      port shift factor for mutiple tcpcopy instances\n"
		   "-m <num>      max memory to use for tcpcopy in megabytes\n"
		   "-M <num>      MTU sent to backend\n"
		   "-l <file>     log file path\n"
		   "-P <file>     save PID in <file>, only used with -d option\n"
		   "-h            print this help and exit\n"
		   "-v            version\n"
		   "-d            run as a daemon\n");
	return;
}

static int read_args(int argc, char **argv){
	int  c;
	while (-1 != (c = getopt(argc, argv,
		 "t:" /* where do we copy request from and to */
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
			case 't':
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

/*
 * 192.168.0.1:80->192.168.0.2:8080 
 */
static void parse_one_target(int index, const char *target)
{
	size_t     len;
	char       buffer[128];
	const char *split, *p = target;
	uint32_t   localhost  = inet_addr("127.0.0.1");	
	uint32_t   inetAddr;
	ip_port_pair_mapping_t *map;
	map = clt_settings.transfer.mappings[index];

	/* Parse online ip address */
	split = strchr(p, ':');
	if(split != NULL){
		len = (size_t)(split - p);
	}else{
		log_info(LOG_WARN,"online ip is not valid:%s", p);
		return;
	}
	strncpy(buffer, p, len);
	inetAddr = inet_addr(buffer);	
	if(inetAddr == localhost){
		log_info(LOG_WARN,"src ip address is not valid:%s", p);
		return;
	}else{
		map->online_ip= inetAddr;
	}
	p = split + 1;

	/* Parse online port */
	split = strchr(p, '-');
	if(split != NULL){
		len = (size_t)(split - p);
	}else{
		log_info(LOG_WARN,"online port is not valid:%s", p);
		return;
	}
	memset(buffer, 0 , 128);
	strncpy(buffer, p, len);
	map->online_port = atoi(buffer);
	p = split + 2;

	/* Parse target ip address */
	split = strchr(p, ':');
	if(split != NULL){
		len = (size_t)(split - p);
	}else{
		log_info(LOG_WARN,"target ip is not valid:%s", p);
		return;
	}
	memset(buffer, 0 , 128);
	inetAddr = inet_addr(buffer);	
	if(inetAddr == localhost){
		log_info(LOG_WARN,"dst ip address is not valid");
		return;
	}else{
		map->target_ip= inetAddr;
	}
	p = split + 1;

	/* Parse target port */
	map->target_port = atoi(p);

}

/* 
 * Retrieve target addresses
 * Format(by -t parameter): 
 * 192.168.0.1:80->192.168.0.2:8080|192.168.0.1:3306->192.168.0.3:3306
 */
static int retrieve_target_addresses(){
	size_t     len, size;
	int        count = 1, i;
	const char *split, *p = clt_settings.raw_transfer;
	char       buffer[128];
	ip_port_pair_mapping_t **mappings;

	memset(buffer, 0, 128);
	
	/* Retrieve target number */
	while(1){
		split = strchr(p, '|');
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
		split = strchr(p, '|');
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
	retrieve_mysql_user_pwd_info(clt_settings.user_pwd);
#endif
}

/*
 * Main entry point
 */
int main(int argc ,char **argv)
{
	int ret;

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

