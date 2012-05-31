#ifndef  _LOG_H_INC
#define  _LOG_H_INC

#include <stdio.h>
#include <string.h>
#include <unistd.h> 
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C" 
{
#endif

#define LOG_STDERR            0
#define LOG_EMERG             1
#define LOG_ALERT             2
#define LOG_CRIT              3
#define LOG_ERR               4
#define LOG_WARN              5
#define LOG_NOTICE            6
#define LOG_INFO              7
#define LOG_DEBUG             8 

//#define TCPCOPY_MYSQL_SKIP        1
//#define TCPCOPY_MYSQL_NO_SKIP     1
#define DEBUG_TCPCOPY 		  0

#if(TCPCOPY_MYSQL_SKIP)
#define TCPCOPY_MYSQL_BASIC 1
#endif

#if(TCPCOPY_MYSQL_NO_SKIP)

#ifndef TCPCOPY_MYSQL_BASIC
#define TCPCOPY_MYSQL_BASIC 1
#endif

#define TCPCOPY_MYSQL_ADVANCED 1

#endif


	void initLogInfo();
	void logInfoForSel(int level,const char *fmt, va_list args);
	void logInfo(int level,const char *fmt, ...);
	void endLogInfo();

#ifdef __cplusplus
}
#endif


#endif  

