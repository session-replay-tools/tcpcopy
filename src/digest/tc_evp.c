#include <xcopy.h>
#include "tc_evp.h"

#if (TCPCOPY_DIGEST) 

#include <openssl/evp.h>


static const EVP_MD *md;
static EVP_MD_CTX sha1_ctx;
static int digests_init = 0;
static int sha1_init = 0;

int 
tc_init_digests()
{
    OpenSSL_add_all_digests();
    digests_init = 1;
    return 1;
}

int 
tc_destroy_digests()
{
    if (digests_init) {
        EVP_cleanup();
        digests_init = 0;
    }

    return 1;
}


int
tc_init_sha1()
{
    md = EVP_get_digestbyname(MYSQL_SHA1);

    if (!md) {
        tc_log_info(LOG_ERR, 0, "%s is not supported", MYSQL_SHA1);
        return 0;
    }

    sha1_init = 1;
    EVP_MD_CTX_init(&sha1_ctx);

    return 1;
}

int 
tc_destroy_sha1()
{
    if (sha1_init) {
        EVP_MD_CTX_cleanup(&sha1_ctx);
        sha1_init = 0;
    }

    return 1;
}

static void tc_tailor(unsigned char *dest, unsigned int dest_len,
        const unsigned char *hash, unsigned int hash_len)
{
    int i;

    if (dest_len > hash_len) {
        return;
    }

    for (i = 0; i < dest_len; i++) {
        dest[i] = hash[i];
    }
}

int 
tc_sha1_digest_one(unsigned char *dest, unsigned int dest_len, 
        const unsigned char *seed, unsigned int seed_len)
{
    unsigned int  sha1_value_len;
    unsigned char sha1_value[EVP_MAX_MD_SIZE];

    if (!sha1_init) {
        return 0;
    }

    EVP_DigestInit_ex(&sha1_ctx, md, NULL);
    EVP_DigestUpdate(&sha1_ctx, seed, seed_len);
    EVP_DigestFinal_ex(&sha1_ctx, sha1_value, &sha1_value_len);

    tc_tailor(dest, dest_len, sha1_value, sha1_value_len);

    return 1;
}

int 
tc_sha1_digest_two(unsigned char *dest, unsigned int dest_len, 
        const unsigned char *seed1, unsigned int seed1_len, 
        const unsigned char *seed2, unsigned int seed2_len)
{
    unsigned int  sha1_value_len;
    unsigned char sha1_value[EVP_MAX_MD_SIZE];

    if (!sha1_init) {
        return 0;
    }

    EVP_DigestInit_ex(&sha1_ctx, md, NULL);
    EVP_DigestUpdate(&sha1_ctx, seed1, seed1_len);
    EVP_DigestUpdate(&sha1_ctx, seed2, seed2_len);
    EVP_DigestFinal_ex(&sha1_ctx, sha1_value, &sha1_value_len);

    tc_tailor(dest, dest_len, sha1_value, sha1_value_len);

    return 1;
}

#endif

