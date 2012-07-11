#include "../core/xcopy.h"
#include "pairs.h"
#include "protocol.h"
#include "password.h"

static inline unsigned char char_val(unsigned char X)
{
    return (unsigned char) (X >= '0' && X <= '9' ? X-'0':
            X >= 'A' && X <= 'Z' ? X-'A'+10 : X-'a'+10);
}

static void new_hash(uint64_t *result, const char *password)
{
    uint64_t   nr  = 1345345333L, add = 7;
    uint64_t   nr2 = 0x12345671L, tmp;
    int        i = 0, length;

    length = strlen(password);

    for (; i < length; ++i) {
        if(' ' == password[i] || '\t' == password[i]){
            /* Skip spaces */
            continue;
        }

        tmp  = (0xff & password[i]);
        nr  ^= ((((nr & 63) + add) * tmp) + (nr << 8));
        nr2 += ((nr2 << 8) ^ nr);
        add += tmp;
    }

    result[0] = nr & 0x7fffffffL;
    result[1] = nr2 & 0x7fffffffL;

}

/*
 * Right from Monty's code
 */
void new_crypt(char *result, const char *password, char *message)
{
    char     b;
    double   d;
    uint64_t pw[2], msg[2], max, seed1, seed2;
    int      length, i;

    new_hash(pw, message);
    new_hash(msg, password);
    max = 0x3fffffffL;
    seed1 = (pw[0] ^ msg[0]) % max;
    seed2 = (pw[1] ^ msg[1]) % max;
    length = strlen(message);

    for (i =0; i < length; i++) {
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

int is_last_data_packet(unsigned char *payload)
{
    unsigned char *p;
    size_t        len;

    p   = payload;
    len = p[0] + (p[1] << 8) + (p[2] << 16);

    if(len < 9){
        /*Skip Packet Length*/
        p = p + 3;
        /*Skip Packet Number*/
        p = p + 1;
        if(254 == p[0]){
            return 1;
        }
    }
    return 0;
}

#if (TCPCOPY_MYSQL_ADVANCED) 
int parse_handshake_init_cont(unsigned char *payload,
                        size_t length, char *scramble_buff)
{
    /*
     * The following is the protocol format of mysql handshake
     *
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
     * n                            rest of the plugin provided data 
     *                              (at least 12 bytes) 
     * 1                            \0 byte, terminating 
     *                              the second part of a scramble
     */
    unsigned char *p;
    char          *str;
    size_t        len, count, str_len;

    p = payload;
    /* Skip Packet Length */
    p = p + 3;
    /* Skip Packet Number */
    p = p + 1;
    /* Skip protocol_version */
    p++;
    str = (char *)p;
    len = strlen(str);
    /* Skip server_version */
    p   = p + len + 1;
    /* Skip thread_id */
    p  += 4;
    str = (char *)p;
    count = p - payload + 8;
    if(count > length){
        log_info(LOG_ERR, "payload len is too short for init:%u,%u",
                length, count);
        return 0;
    }
    strncpy(scramble_buff, (char *)p, 8);   
    /* Skip scramble_buff */
    p = p + 8 + 1;
    /* Skip server_capabilities */
    p = p + 2;
    /* Skip server_language */
    p = p + 1;
    /* Skip server_status */
    p = p + 2;
    /* Skip server capabilities (two upper bytes) */
    p = p + 2;
    /* Skip length of the scramble */
    p = p + 1;
    /* Skip (filler)  always 0 */
    p = p + 10;
    str = (char *)p;
    str_len = strlen(str) + 8;
    count = p - payload + strlen(str);
    if(str_len > SCRAMBLE_LENGTH|| count > length){
        if(count >length){
            log_info(LOG_ERR, "payload len is too short for init2:%u,%u",
                    length, count);
        }else{
            log_info(LOG_ERR, "scramble is too long:%u", str_len);
        }
        return 0;
    }
    /* Copy the rest of scramble_buff */
    strncpy(scramble_buff + 8, str, strlen(str));

    return 1;
}

int change_client_auth_content(unsigned char *payload,
                        int length, char *password, char *message)
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
    char   *str;
    size_t len, i;
    char   user[256], *pwd;
    unsigned char *p, scramble_buff[SCRAMBLE_LENGTH + 1];

    memset(scramble_buff, 0, SCRAMBLE_LENGTH + 1);
    p = payload;
    /* Skip mysql packet header */
    /* Skip Packet Length */
    p = p + 3;
    /* Skip Packet Number */
    p = p + 1;
    /* Skip client_flags */
    p = p + 4;
    /* Skip max_packet_size */
    p = p + 4;
    /* Skip charset_number */
    p = p + 1;
    /* Skip (filler) always 0x00... */
    p = p + 23;
    len = p - payload;
    if(len > length){
        log_info(LOG_ERR, "payload len is too short:%u,%u", length, len);
        return 0;
    }
    str = (char *)p;
    /* Retrieve user */
    memset(user, 0, 256);
    strcpy(user, str);
    pwd = retrieve_user_pwd(user);
    if(pwd != NULL){
        log_info(LOG_WARN, "user:%s,pwd:%s", user, pwd);
    }else{
        log_info(LOG_WARN, "user:%s,pwd is null", user);
        return 0;
    }
    /* Skip user */
    p = p + strlen(str) + 1;
    /* Skip scramble_buff length */
    p = p + 1;
    len = p - payload + SCRAMBLE_LENGTH;
    if(len > length){
        log_info(LOG_ERR, "payload len is too short too:%u,%u",
                length, len);
        return 0;
    }
    scramble((char*)scramble_buff, message, pwd);
    /* Change scramble_buff according the target server scramble */
    for(i = 0; i < SCRAMBLE_LENGTH; i++){
        p[i] = scramble_buff[i];
    }
    /* Save password */
    strcpy(password, pwd);
    return 1;

}

int change_client_second_auth_content(unsigned char *payload,size_t length,
        char *new_content)
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
    size_t        i, len;

    p = payload;
    /* Skip mysql packet header */
    /* Skip Packet Length */
    p = p + 3;
    /* Skip Packet Number */
    p = p + 1;
    len = p - payload + 8;
    if(len > length){
        log_info(LOG_ERR, "payload len is too short for sec :%u,%u",
                length, len);
        return 0;
    }
    /* Change scramble_buff according to the target server scramble */
    for(i = 0; i < 8; i++){
        p[i] = new_content[i];
    }
    return 1;

}
#endif

