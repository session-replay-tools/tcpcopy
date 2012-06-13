/*
 * tcpcopy - an online replication replication tool
 *
 *  Copyright 2011 Netease, Inc.  All rights reserved.
 *  Use and distribution licensed under the BSD license.  See
 *  the LICENSE file for full text.
 *
 *  Authors:
 *      bin wang <wangbin579@gmail.com>
 *      bo  wang <wangbo@corp.netease.com>
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include "../core/xcopy.h"

passed_ip_addr_t passed_ips;

static void release_resources()
{
	log_info(LOG_NOTICE, "release_resources begin");
	interception_over();
	log_info(LOG_NOTICE, "release_resources end except log file");
	end_log_info();
}

static void signal_handler(int sig)
{
	log_info(LOG_ERR,"set signal handler:%d", sig);
	printf("set signal handler:%d\n", sig);
	if(SIGSEGV == sig)
	{    
		log_info(LOG_ERR, "SIGSEGV error");
		release_resources();
		/*avoid dead loop*/
		signal(SIGSEGV, SIG_DFL);
		kill(getpid(), sig);
	}else
	{    
		exit(EXIT_SUCCESS);
	} 
}

static void set_signal_handler(){
	int i=1;
	atexit(release_resources);
	for(; i<SIGTTOU; i++)	
	{
		signal(i, signal_handler);
	}
}

static int retrieve_ip_addr(const char* ips)
{
	size_t      len;
	int         count=0;
	const char  *split, *p=ips;
	char        tmp[32];
	uint32_t    address;

	memset(tmp, 0, 32);

	while(1)
	{
		split=strchr(p, ':');
		if(split != NULL)
		{   
			len = (size_t)(split-p);
		}else
		{   
			len = strlen(p);
		}   
		strncpy(tmp, p, len);
		address = inet_addr(tmp);    
		passed_ips.ips[count++] = address;
		if(NULL == split)
		{
			break;
		}else
		{
			p = split + 1;
		}
		memset(tmp, 0, 32);

	}

	passed_ips.num = count;

	return 1;
}


int main(int argc ,char **argv){
	if(argc > 1)
	{
		retrieve_ip_addr(argv[1]);
	}

	init_log_info();
	set_signal_handler();
	interception_init();
	interception_run();

	return 0;
}

