#include "../core/xcopy.h"

#include "my_global.h"
#include "password.h"
#include "sha1.h"

#if (TCPCOPY_MYSQL_ADVANCED) 
static void
my_crypt(char *to, const uchar *s1, const uchar *s2, uint len)
{
    const uint8 *s1_end = s1 + len; 

    while (s1 < s1_end) {
        *to++= *s1++ ^ *s2++;
    }    
}

void 
scramble(char *to, const char *message, const char *password)
{
    SHA1_CONTEXT sha1_context;

    uint8 hash_stage1[SHA1_HASH_SIZE];
    uint8 hash_stage2[SHA1_HASH_SIZE];

    mysql_sha1_reset(&sha1_context);

    /* Stage 1: hash password */
    mysql_sha1_input(&sha1_context, (uint8 *)password,
            (uint)strlen(password));
    mysql_sha1_result(&sha1_context, hash_stage1);

    /* 
     * Stage 2: 
     * hash stage 1; 
     * Note that hash_stage2 is stored in the database 
     */
    mysql_sha1_reset(&sha1_context);
    mysql_sha1_input(&sha1_context, hash_stage1, SHA1_HASH_SIZE);
    mysql_sha1_result(&sha1_context, hash_stage2);

    /* Create crypt string as sha1(message, hash_stage2) */;
    mysql_sha1_reset(&sha1_context);
    mysql_sha1_input(&sha1_context, (const uint8 *) message, 
            SCRAMBLE_LENGTH);
    mysql_sha1_input(&sha1_context, hash_stage2, SHA1_HASH_SIZE);

    /* Xor allows 'from' and 'to' overlap: lets take advantage of it */
    mysql_sha1_result(&sha1_context, (uint8 *) to);
    my_crypt(to, (const uchar *) to, hash_stage1, SCRAMBLE_LENGTH);
}
#endif

