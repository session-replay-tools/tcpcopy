#ifndef  PROTOCOL_INC
#define  PROTOCOL_INC
#ifdef __cplusplus
extern "C" 
{
#endif


/*
 * we support only mysql 4.1 and later
 * ssl is not supported here
 */

int parse_handshake_init_content(unsigned char *payload,
		size_t length,char *scramble);
int change_client_auth_content(unsigned char *payload,
		size_t length,char *message,const char* password);
void new_crypt(char* result,const char* password,char *message);
int isLastDataPacket(unsigned char *payload);
int change_client_second_auth_content(unsigned char *payload,
		size_t length,char* newContent);

#ifdef __cplusplus
}
#endif

#endif   /* ----- #ifndef PROTOCOL_INC  ----- */



