#include "pairs.h"
#include "../core/hash.h"

static hash_table *user_pwd_table;

static uint64_t get_key_from_user(char *user)
{
    size_t   len, i;
    uint64_t key = 0;

    if(NULL == user){
        return key;
    }
    len = strlen(user);
    for (i = 0; i < len; i++ ){   
        key = 31*key + user[i];
    }   

    return key;
}

char *retrieve_user_pwd(char *user)
{
    mysql_user *p_user_info;
    uint64_t   key;

    key = get_key_from_user(user);
    p_user_info = hash_find(user_pwd_table, key);

    while(p_user_info){
        if(strcmp(p_user_info->user, user) == 0){
            return p_user_info->password;
        }
        p_user_info = p_user_info->next;
    }

    return NULL;
}

void retrieve_mysql_user_pwd_info(char *pairs)
{
    char       *p, *end, *q, *next, *pair_end, user[256];
    mysql_user *p_user_info, *p_tmp_user_info;
    uint64_t   key;
    size_t     len;  
    
    user_pwd_table = hash_create(256);
    strcpy(user_pwd_table->name, "user password table");

    p   = pairs;
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
        p_user_info = (mysql_user*)calloc(1, sizeof(mysql_user));
        strncpy(p_user_info->password, q + 1, pair_end - q);
        key = get_key_from_user(user);
        p_tmp_user_info = hash_find(user_pwd_table, key);
        if(NULL == p_tmp_user_info){
            hash_add(user_pwd_table, key, (void *)p_user_info);
        }else{
            p_tmp_user_info->next = p_user_info;
        }
        if(next != NULL){
            p = next + 1;
        }else{
            break;
        }
    }while( p < end);
}


