#include "pairs.h"
#include "../core/hash.h"

static hash_table *user_pwd_table;

static void get_md5(unsigned char *md, const char *src){   
	unsigned int len = strlen(src);
	MD5((const unsigned char *)src, len, md);
} 

static uint64_t get_key_from_user(const char *user, unsigned char *md5){
	int i;
	uint64_t key = 0;

	get_md5(md5,user);

	for(i = 0; i< MD5_LEN; i++){
		key = (key<<8) + (unsigned int)md5[i];
	}

	return key;
}

char *retrieve_user_pwd(char *user){
	unsigned char  md5[MD5_LEN];
	mysql_user     *p_user_info;
	uint64_t       key = get_key_from_user(user,md5);

	p_user_info = hash_find(user_pwd_table, key);

	if(NULL != p_user_info){
		return p_user_info->password;
	}

	return NULL;
}

void retrieve_mysql_user_pwd_info( char *pairs){
	char       *p, *end, *q, *next, *pair_end;
	char       user[256];
	mysql_user *p_user_info;
	uint64_t   key;
	size_t     len;  
	
	user_pwd_table = hash_create(256);
	strcpy(user_pwd_table->name, "user password table");

	p = pairs;

	if(NULL == p){
		log_info(LOG_WARN, "use password null");
		exit(1);
	}
	len = strlen(p);
	end = p + len;

	if(len <= 1){
		log_info(LOG_WARN, "use password error:%s", pairs);
		exit(1);
	}
	do{
		next = strchr(p, ':');
		q = strchr(p, '@');
		if( next != NULL){
			if(next != p){
				pair_end = next - 1;
			}else{
				log_info(LOG_WARN, "use password info error:%s", pairs);
				exit(1);
			}
		}else{
			pair_end = p + strlen(p) - 1;
		}
		memset(user, 0, 256);
		strncpy(user, p, q-p);
		p_user_info = (mysql_user*)malloc(sizeof(mysql_user));
		strncpy(p_user_info->password, q + 1, pair_end - q);
		key = get_key_from_user(user, p_user_info->md5);
		hash_add(user_pwd_table, key, (void *)p_user_info);
		if(next != NULL){
			p = next + 1;
		}else{
			break;
		}
	}while( p < end);
}


