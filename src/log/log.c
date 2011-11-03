#include "log.h"

static FILE* file=NULL;
int global_out_level;

static char* err_levels[] = { 
	"unknown",
	"emerg",
	"alert",
	"crit",
	"error",
	"warn",
	"notice",
	"info",
	"debug"
};

void initLogInfo()
{
	global_out_level=LOG_WARN;
	file=fopen("error.log","a+");
}

/**
 * this function is not thread safe
 */
void logInfo(int level,const char *fmt, ...)
{
	va_list args;
	struct tm localTime;
	time_t t;
	char timeStr[32];
	struct tm* pLocalTime=NULL;
	char* pTimeStr=NULL;
	size_t len=0;
	if(global_out_level >= level)
	{
		if (file) {
			t=time(0);
			fprintf(file,"[%s] ",err_levels[level]);
			pLocalTime=localtime_r(&t,&localTime);
			if(NULL == pLocalTime)
			{
				return;
			}
			pTimeStr=asctime_r(pLocalTime,timeStr);
			if(NULL == pTimeStr)
			{
				return;
			}
			len=strlen(pTimeStr);
			pTimeStr[len-1]=':';
			fprintf(file,"%s",pTimeStr);
			va_start(args, fmt);
			(void)vfprintf(file, fmt, args);
			fprintf( file, "\n" );
			va_end(args);
		}
	}
}

void endLogInfo()
{
	if(file)
	{
		(void)fclose(file);
		file=NULL;
	}
}

