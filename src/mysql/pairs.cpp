#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <map>
#include <openssl/md5.h>
#include "../log/log.h"
#include "pairs.h"

using std::map;
typedef map<uint64_t,mysql_user*> UserPwdContainer;
typedef map<uint64_t,mysql_user*>::iterator UserPwdIterator;

static UserPwdContainer userPwds;

static void getMd5(unsigned char* md,const char* src)
{   
	unsigned int len=strlen(src);
	MD5((const unsigned char*)src,len,md);
} 

static uint64_t getKeyFromUser(const char* user,unsigned char* md5)
{
	int i;
	uint64_t key=0;
	getMd5(md5,user);
	for(i=0;i<MD5_LEN;i++)
	{
		key=(key<<8)+(unsigned int)md5[i];
	}
	return key;
}

char* retrieveUserPwd(char* user)
{
	unsigned char md5[MD5_LEN];
	mysql_user* userInfo;
	uint64_t key=getKeyFromUser(user,md5);
	UserPwdIterator iter=userPwds.find(key);
	if(iter!= userPwds.end())
	{
		userInfo=iter->second;
		return userInfo->password;
	}
	return NULL;
}

void retrieveMysqlUserPwdInfo(char* pairs)
{
	char *p=pairs;
	char *q,*next;
	char *pairEnd;
	char user[256];
	size_t len=strlen(p);
	char *end=p+len;
	mysql_user* userInfo;
	uint64_t key;

	if(len<=1)
	{
		logInfo(LOG_WARN,"use password error:%s",pairs);
		exit(1);
	}
	do{
		next=strchr(p,':');
		q=strchr(p,'@');
		if(next!=NULL)
		{
			if(next!=p)
			{
				pairEnd=next-1;
			}else
			{
				logInfo(LOG_WARN,"use password info error:%s",pairs);
				exit(1);
			}
		}else
		{
			pairEnd=p+strlen(p)-1;
		}
		memset(user,0,256);
		strncpy(user,p,q-p);
		userInfo=(mysql_user*)malloc(sizeof(mysql_user));
		strncpy(userInfo->password,q+1,pairEnd-q);
		key=getKeyFromUser(user,userInfo->md5);
		userPwds[key]=userInfo;
		if(next!=NULL)
		{
			p=next+1;
		}else
		{
			break;
		}
	}while(p<end);
}


