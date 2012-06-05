#ifndef  _LOG_H_INC
#define  _LOG_H_INC

#ifdef __cplusplus
extern "C" 
{
#endif

	void init_log();
	void log_info(int level,const char *fmt, ...);
	void end_log();

#ifdef __cplusplus
}
#endif

#endif  

