/*                                                                                           *  tcpcopy - an online replication replication tool
 *
 *  Copyright 2011 Netease, Inc.  All rights reserved.
 *  Use and distribution licensed under the BSD license.  See
 *  the LICENSE file for full text.
 *
 *  Authors:
 *      bin wang <163.beijing@gmail.com or bwang@corp.netease.com>
 *      bo  wang <wangbo@corp.netease.com>
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdlib.h>
#include <signal.h>

#include "interception.h"

static void releaseResources()
{
	logInfo(LOG_NOTICE,"releaseResources begin");
	interception_over();
	logInfo(LOG_NOTICE,"releaseResources end except log file");
	endLogInfo();
}

static void signal_handler(int sig)
{
	logInfo(LOG_ERR,"set signal handler:%d",sig);
	printf("set signal handler:%d\n",sig);
	if(SIGSEGV==sig)
	{    
		logInfo(LOG_ERR,"SIGSEGV error");
		releaseResources();
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
	atexit(releaseResources);
	for(;i<SIGTTOU;i++)	
	{
		signal(i,signal_handler);
	}
}

static int retrieveIPAddresses(const char* ips)
{
	size_t len;
	int count=0;
	const char* split;
	const char* p=ips;
	char tmp[32];
	memset(tmp,0,32);
	uint32_t inetAddr=0;
	while(1)
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
		passed_ips.ips[count++]=inetAddr;
		if(NULL==split)
		{
			break;
		}else
		{
			p=split+1;
		}
		memset(tmp,0,32);

	}
	passed_ips.num=count;
	return 1;
}


int main(int argc ,char **argv){
	if(argc>1)
	{
		retrieveIPAddresses(argv[1]);
	}
	initLogInfo();
	set_signal_handler();
	interception_init();
	interception_run();
	return 0;
}


