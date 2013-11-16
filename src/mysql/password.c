#include <xcopy.h>

#include "password.h"

#if (TCPCOPY_MYSQL_ADVANCED) 
static void
my_crypt(char *to, const unsigned char *s1, const unsigned char *s2, uint len)
{
    const unsigned char *s1_end = s1 + len; 

    while (s1 < s1_end) {
        *to++= *s1++ ^ *s2++;
    }    
}

/**
 * SHA1(password) XOR 
 * SHA1("20-bytes random data from server" <concat> SHA1(SHA1(password)))
 */
void
scramble(char *to, const char *message, const char *password)
{
    unsigned char hash_stage1[SHA1_HASH_SIZE];
    unsigned char hash_stage2[SHA1_HASH_SIZE];

    tc_sha1_digest_one(hash_stage1, SHA1_HASH_SIZE, 
            (const unsigned char *) password, strlen(password));
    tc_sha1_digest_one(hash_stage2, SHA1_HASH_SIZE, 
            hash_stage1, SHA1_HASH_SIZE);
    tc_sha1_digest_two((unsigned char *) to, SCRAMBLE_LENGTH, 
            (const unsigned char *) message, SCRAMBLE_LENGTH, 
            (const unsigned char *) hash_stage2, SHA1_HASH_SIZE);

    my_crypt(to, (const unsigned char *) to, hash_stage1, SCRAMBLE_LENGTH);
}
#endif

