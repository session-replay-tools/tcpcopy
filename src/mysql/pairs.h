#ifndef  _PAIRS_H_INC
#define  _PAIRS_H_INC

#define MD5_LEN 16

typedef struct mysql_user{
	unsigned char md5[MD5_LEN];
	char password[256];
}mysql_user;

char *retrieve_user_pwd(char *user);
void retrieve_mysql_user_pwd_info(char *pairs);

#endif

