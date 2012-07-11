#ifndef  _PAIRS_H_INC
#define  _PAIRS_H_INC


typedef struct mysql_user{
	char *user;
	char password[256];
	struct mysql_user* next;
}mysql_user;

char *retrieve_user_pwd(char *user);
void retrieve_mysql_user_pwd_info(char *pairs);

#endif

