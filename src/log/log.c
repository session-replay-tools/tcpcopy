#include "log.h"

static FILE* file=NULL;
int output_level;

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
	output_level=LOG_DEBUG;
	file=fopen("error.log","a+");
}

/**
 * this function is not thread safe
 */
void logInfo(int level,const char *fmt, ...)
{
	va_list args;
	if(output_level >= level)
	{
		if (file) {
			time_t t;
			t=time(0);
			struct tm localTime;
			fprintf(file,"[%s] ",err_levels[level]);
			char timeStr[32];
			struct tm * pLocalTime=localtime_r(&t,&localTime);
			if(NULL == pLocalTime)
			{
				return;
			}
			char* pTimeStr=asctime_r(pLocalTime,timeStr);
			if(NULL == pTimeStr)
			{
				return;
			}
			size_t len=strlen(pTimeStr);
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
		fclose(file);
		file=NULL;
	}
}

