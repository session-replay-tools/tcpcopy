
#include <xcopy.h>
#include "pairs.h"
#include "protocol.h"
#include "password.h"

static void
new_hash(uint64_t *result, const char *password)
{
    int        i = 0, length;
    uint64_t   nr  = 1345345333L, add = 7, nr2 = 0x12345671L, tmp;

    length = strlen(password);

    for (; i < length; ++i) {
        if (' ' == password[i] || '\t' == password[i]) {
            /* skip spaces */
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
 * right from Monty's code
 */
void
new_crypt(char *result, const char *password, char *message)
{
    int      length, i;
    char     b;
    double   d;
    uint64_t pw[2], msg[2], max, seed1, seed2;

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

    d = (double) seed1 / (double) max;
    b = (char) floor(d * 31);

    for (i = 0; i < length; i++) {
        result[i] ^= (char) b;
    }
}

int
is_last_data_packet(unsigned char *payload)
{
    size_t         len;
    unsigned char *p;

    p   = payload;
    len = p[0] + (p[1] << 8) + (p[2] << 16);

    if (len < 9) {
        /* skip packet length */
        p = p + 3;
        /* skip packet number */
        p = p + 1;
        if (254 == p[0]) {
            return 1;
        }
    }
    return 0;
}

#if (TCPCOPY_MYSQL_ADVANCED) 
int
parse_handshake_init_cont(unsigned char *payload, size_t length, 
        char *scramble_buff)
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
    char          *str;
    size_t         len, count, str_len;
    unsigned char *p;

    p = payload;
    /* skip packet length */
    p = p + 3;
    /* skip packet number */
    p = p + 1;
    /* skip protocol_version */
    p++;
    str = (char *) p;
    len = strlen(str);
    /* skip server_version */
    p   = p + len + 1;
    /* skip thread_id */
    p  += 4;
    count = p - payload + 8;
    if (count > length) {
        tc_log_info(LOG_ERR, 0, "payload len is too short for init:%u,%u",
                length, count);
        return 0;
    }
    strncpy(scramble_buff, (char *) p, 8);   
    /* skip scramble_buff */
    p = p + 8 + 1;
    /* skip server_capabilities */
    p = p + 2;
    /* skip server_language */
    p = p + 1;
    /* skip server_status */
    p = p + 2;
    /* skip server capabilities (two upper bytes) */
    p = p + 2;
    /* skip length of the scramble */
    p = p + 1;
    /* skip (filler)  always 0 */
    p = p + 10;
    str = (char *) p;
    str_len = strlen(str) + 8;
    count = p - payload + strlen(str);
    if (str_len > SCRAMBLE_LENGTH|| count > length) {
        if (count >length) {
            tc_log_info(LOG_ERR, 0, "payload len is too short for init2:%u,%u",
                    length, count);
        } else {
            tc_log_info(LOG_ERR, 0, "scramble is too long:%u", str_len);
        }
        return 0;
    }
    /* copy the rest of scramble_buff */
    strncpy(scramble_buff + 8, str, strlen(str));

    return 1;
}

int
change_client_auth_content(unsigned char *payload, int length,
        char *password, char *message)
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
    char          *str, user[256], *pwd;
    size_t         len, i;
    unsigned char *p, *q, scramble_buff[SCRAMBLE_LENGTH + 1];

    memset(scramble_buff, 0, SCRAMBLE_LENGTH + 1);

    p = payload;
    /* skip mysql packet header */
    /* skip packet length */
    p = p + 3;
    /* skip packet number */
    p = p + 1;
    /* skip client_flags */
    p = p + 4;
    /* skip max_packet_size */
    p = p + 4;
    /* skip charset_number */
    p = p + 1;
    /* skip (filler) always 0x00... */
    q = p;
    p = p + 23;
    len = p - payload;
    if (len > length) {
        tc_log_info(LOG_ERR, 0, "payload len is too short:%d,%u", length, len);
        return 0;
    }

    tc_log_info(LOG_INFO, 0, "before judge,cont len:%d", length);
    for (i = 0; i < 23; i++) {
        if (q[i] != 0 ) {
            tc_log_info(LOG_WARN, 0, "it is not a login packet");
            return 0;
        }
    }

    tc_log_info(LOG_INFO, 0, "after judge");

    str = (char *) p;
    tc_log_info(LOG_INFO, 0, "break here?");
    /* retrieve user */
    memset(user, 0, 256);

    tc_log_info(LOG_INFO, 0, "break here??");

    len = strlen(str);
    if (len >= 256) {
        tc_log_info(LOG_ERR, 0, "user len is too long:%s,%u", str, len);
        return 0;
    }
    strcpy(user, str);

    pwd = retrieve_user_pwd(user);
    if (pwd != NULL) {
        tc_log_info(LOG_WARN, 0, "user:%s,pwd:%s", user, pwd);
    } else {
        tc_log_info(LOG_WARN, 0, "user:%s,pwd is null", user);
        return 0;
    }

    /* skip user */
    p = p + len + 1;

    /* skip scramble_buff length */
    p = p + 1;
    len = p - payload + SCRAMBLE_LENGTH;
    if (len > length) {
        tc_log_info(LOG_ERR, 0, "payload len is too short too:%d,%u",
                length, len);
        return 0;
    }

    scramble((char *) scramble_buff, message, pwd);

    /* change scramble_buff according the target server scramble */
    for (i = 0; i < SCRAMBLE_LENGTH; i++) {
        p[i] = scramble_buff[i];
    }

    /* save password */
    strcpy(password, pwd);

    return 1;
}

int 
change_client_second_auth_content(unsigned char *payload, size_t length,
        char *new_content)
{
    size_t         i, len;
    unsigned char *p;

    p = payload;
    /* skip mysql packet header */
    /* skip packet length */
    p = p + 3;

    /* skip packet number */
    p = p + 1;

    len = p - payload + 8;
    if (len > length) {
        tc_log_info(LOG_ERR, 0, "payload len is too short for sec :%u,%u",
                length, len);
        return 0;
    }

    /* change scramble_buff according to the target server scramble */
    for (i = 0; i < 8; i++) {
        p[i] = new_content[i];
    }
    return 1;

}
#endif

