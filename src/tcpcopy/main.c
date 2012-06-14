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

#include "../core/xcopy.h"

/* Global variables */
uint16_t                g_port_shift_factor, g_rand_port_shift;
ip_port_pair_mappings_t g_transfer_target;

/* Static variables */
static int              replica_num;

int read_args (int argc, char **argv){
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
				retrieve_mysql_user_pwd_info(pairs);
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
				g_port_shift_factor = atoi(optarg);
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

static void print_command(int argc, char **argv)
{
	int i;
	for(i = 0; i < argc; i++){
		log_info(LOG_NOTICE,"the %dth argv is:%s",i + 1,argv[i]);
	}
}
/*
 * Retrieve all valid local ip addresses
 * 127.0.0.1 or localhost is not valid here
 */
static int retrieve_vir_ip_addr(const char* ips){
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
		//local_ips.ips[count++] = inetAddr;
		if(NULL == split){
			break;
		}else{
			p = split + 1;
		}
		memset(tmp, 0, 32);
	}
	//local_ips.num = count;
	return 1;
}


/*
 * Main entry point
 */
int main(int argc ,char **argv)
{
	int ret;

	if(argc < 5)
	{
		printf("Usage: %s 61.135.250.1 80 61.135.250.2 80\n",
				argv[0]);
		exit(1);
	}
	/* Init log for outputing debug info */
	init_log_info();
	/* Print command for debug */
	print_command(argc, argv);
	/* Print tcpcopy version */
	log_info(LOG_NOTICE, "tcpcopy version:%s", VERSION);

	/* Print tcpcopy working mode */
#if (TCPCOPY_MYSQL_SKIP)
	log_info(LOG_NOTICE, "TCPCOPY_MYSQL_SKIP mode");
#endif
#if (TCPCOPY_MYSQL_NO_SKIP)
	log_info(LOG_NOTICE, "TCPCOPY_MYSQL_NO_SKIP mode");
#endif
	
	ret = retrieve_vir_ip_addr(argv[1]);
	if(!ret)
	{
		log_info(LOG_ERR, "retrieve ip and port error");
	}
	//local_port  = htons(atoi(argv[2]));
	//remote_ip   = inet_addr(argv[3]);
	//remote_port = htons(atoi(argv[4]));

	if(argc > 5)
	{
		if(!read_args(argc, argv))
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

	return 0;
}

