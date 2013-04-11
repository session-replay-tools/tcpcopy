#ifndef  PAIRS_INCLUDED
#define  PAIRS_INCLUDED


typedef struct mysql_user{
	char user[256];
	char password[256];
	struct mysql_user* next;
}mysql_user;

char *retrieve_user_pwd(char *user);
int retrieve_mysql_user_pwd_info(char *pairs);
void release_mysql_user_pwd_info();

#endif

