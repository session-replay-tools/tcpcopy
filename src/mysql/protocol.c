#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include "password.h"
#include "pairs.h"
#include "../log/log.h"
#define SHA1_HASH_SIZE 20

static inline unsigned char char_val(unsigned char X)
{
	return (unsigned char) (X >= '0' && X <= '9' ? X-'0' :
			X >= 'A' && X <= 'Z' ? X-'A'+10 : X-'a'+10);
}
static void hex2octet(unsigned char *to, const char *str, unsigned int len)
{
	const char *str_end= str + len;
	while (str < str_end)
	{
		register char tmp= char_val(*str++);
		*to++= (tmp << 4) | char_val(*str++);
	}
}

static void newHash(uint64_t *result,const char *password)
{
	uint64_t nr = 1345345333L;
	uint64_t add = 7;
	uint64_t nr2 = 0x12345671L;
	uint64_t tmp;
	int i=0;
	int length=strlen(password);

	for (; i < length; ++i) {
		if(' '==password[i]||'\t'==password[i])
		{
			/* skip spaces */
			continue;
		}

		tmp = (0xff & password[i]);
		nr ^= ((((nr & 63) + add) * tmp) + (nr << 8));
		nr2 += ((nr2 << 8) ^ nr);
		add += tmp;
	}

	result[0] = nr & 0x7fffffffL;
	result[1] = nr2 & 0x7fffffffL;

}

/*
 * Right from Monty's code
 */
void new_crypt(char* result,const char* password,char *message)
{
	char b;
	double d;
	uint64_t pw[2];
	uint64_t msg[2];
	newHash(pw,message);
	newHash(msg,password);
	uint64_t max = 0x3fffffffL;
	uint64_t seed1 = (pw[0] ^ msg[0]) % max;
	uint64_t seed2 = (pw[1] ^ msg[1]) % max;
	int length=strlen(message);
	int i=0;

	for (; i < length; i++) {
		seed1 = ((seed1 * 3) + seed2) % max;
		seed2 = (seed1 + seed2 + 33) % max;
		d = (double) seed1 / (double) max;
		b = (char)floor((d * 31) + 64);
		result[i] = b;
	}
	seed1 = ((seed1 * 3) + seed2) % max;
	seed2 = (seed1 + seed2 + 33) % max;
	d = (double) seed1 / (double) max;
	b = (char) floor(d * 31);

	for (i = 0; i < length; i++) {
		result[i] ^= (char) b;
	}
}

/* Convert scrambled password from asciiz hex string to binary form. */
static void get_salt_from_password(unsigned char *hash_stage2, const char *password)
{
	  hex2octet(hash_stage2, password+1 /* skip '*' */, SHA1_HASH_SIZE * 2);
}

int isLastDataPacket(unsigned char *payload)
{
	unsigned char *p,*q;
	char* str;
	size_t len;
	p=payload;
	len=p[0]+(p[1]<<8)+(p[2]<<16);
	if(len < 9)
	{
		/*skip  Packet Length*/
		p=p+3;
		/*skip Packet Number*/
		p=p+1;
		if(254 == p[0])
		{
			return 1;
		}
	}
	return 0;
}

int parse_handshake_init_content(unsigned char *payload,
		                size_t length,char *scramble_buff)
{
	/*
	 * 1                            protocol_version
	 * n (Null-Terminated String)   server_version
	 * 4                            thread_id
	 * 8                            scramble_buff
	 * 1                            (filler) always 0x00
	 * 2                            server_capabilities
	 * 1                            server_language
	 * 2                            server_status
	 * 2                            server capabilities (two upper bytes)
	 * 1                            length of the scramble
	 * 10                            (filler)  always 0
	 * n                            rest of the plugin provided data (at least 12 bytes) 
	 * 1                            \0 byte, terminating the second part of a scramble
	 */
	unsigned char *p,*q;
	char* str;
	size_t len;
	size_t count;
	size_t strLen;
	p=payload;
	/*skip  Packet Length*/
	p=p+3;
	/*skip Packet Number*/
	p=p+1;
	/*skip protocol_version*/
	p++;
	str=p;
	len=strlen(str);
	/*skip server_version*/
	p=p+len+1;
	//skip thread_id
	p+=4;
	str=p;
	count=p-payload+8;
	if(count >length)
	{
		logInfo(LOG_ERR,"payload len is too short for init:%u,%u",
				length,count);
		return 0;
	}
	strncpy(scramble_buff,p,8);	
	/*skip scramble_buff*/
	p=p+8+1;
	/*skip server_capabilities*/
	p=p+2;
	/*skip server_language*/
	p=p+1;
	/*skip server_status*/
	p=p+2;
	/*skip server capabilities (two upper bytes)*/
	p=p+2;
	/*skip length of the scramble*/
	p=p+1;
	/*skip (filler)  always 0*/
	p=p+10;
	str=p;
	strLen=strlen(str)+8;
	count=p-payload+strlen(str);
	if(strLen>SCRAMBLE_LENGTH||count >length)
	{
		if(count >length)
		{
			logInfo(LOG_ERR,"payload len is too short for init2:%u,%u",
					length,count);
		}else
		{
			logInfo(LOG_ERR,"scramble is too long:%u",strLen);
		}
		return 0;
	}
	/*copy the rest of scramble_buff*/
	strncpy(scramble_buff+8,str,strlen(str));
	return 1;

}

int change_client_auth_content(unsigned char *payload,
		                size_t length,char* password,char *message)
{
	/*
	 * 4                            client_flags
	 * 4                            max_packet_size
	 * 1                            charset_number
	 * 23                           (filler) always 0x00...
	 * n (Null-Terminated String)   user
	 * n (Length Coded Binary)      scramble_buff (1 + x bytes) 
	 * n (Null-Terminated String)   databasename (optional)
	 */
	char *str;
	size_t len;
	char user[256];
	unsigned char *p,*q;
	unsigned char scramble_buff[SCRAMBLE_LENGTH+1];
	size_t i;
	memset(scramble_buff,0,SCRAMBLE_LENGTH+1);
	p=payload;
	/*skip mysql packet header */
	/*skip Packet Length*/
	p=p+3;
	/*skip Packet Number*/
	p=p+1;
	/*skip client_flags*/
	p=p+4;
	/*skip max_packet_size*/
	p=p+4;
	/*skip charset_number*/
	p=p+1;
	/*skip (filler) always 0x00...*/
	p=p+23;
	len=p-payload;
	if(len > length)
	{
		logInfo(LOG_ERR,"payload len is too short:%u,%u",length,len);
		return 0;
	}
	str=p;
	/*retrieve user*/
	memset(user,0,256);
	strcpy(user,str);
	char* pwd=retrieveUserPwd(user);
	logInfo(LOG_WARN,"user:%s,pwd:%s",user,pwd);
	/*skip user*/
	p=p+strlen(str)+1;
	/*skip scramble_buff length*/
	p=p+1;
	len=p-payload+SCRAMBLE_LENGTH;
	if(len > length)
	{
		logInfo(LOG_ERR,"payload len is too short too:%u,%u",length,len);
		return 0;
	}
	scramble((char*)scramble_buff,message,pwd);
	/*change scramble_buff according the target server scramble*/
	for(i=0;i<SCRAMBLE_LENGTH;i++)
	{
		p[i]=scramble_buff[i];
	}
	/*save password*/
	strcpy(password,pwd);
	return 1;

}

int change_client_second_auth_content(unsigned char *payload,size_t length,
		char* newContent)
{
	/*
	 * 4                            client_flags
	 * 4                            max_packet_size
	 * 1                            charset_number
	 * 23                           (filler) always 0x00...
	 * n (Null-Terminated String)   user
	 * n (Length Coded Binary)      scramble_buff (1 + x bytes) 
	 * n (Null-Terminated String)   databasename (optional)
	 */
	unsigned char *p;
	size_t i;
	size_t len;
	p=payload;
	/*skip mysql packet header */
	/*skip Packet Length*/
	p=p+3;
	/*skip Packet Number*/
	p=p+1;
	len=p-payload+8;
	if(len > length)
	{
		logInfo(LOG_ERR,"payload len is too short for sec :%u,%u",
				length,len);
		return 0;
	}
	/*change scramble_buff according the target server scramble*/
	for(i=0;i<8;i++)
	{
		p[i]=newContent[i];
	}
	return 1;

}

