#ifndef  _PAIRS_H_INC
#define  _PAIRS_H_INC

#include "../log/log.h"
#ifdef __cplusplus
extern "C" 
{
#endif

#define MD5_LEN 16
typedef struct mysql_user{
	unsigned char md5[MD5_LEN];
	char password[256];
}mysql_user;

char* retrieveUserPwd(char* user);
void retrieveMysqlUserPwdInfo(char* pairs);

#ifdef __cplusplus
}
#endif

#endif
