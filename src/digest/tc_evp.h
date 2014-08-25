#ifndef  TC_EVP_INCLUDED
#define  TC_EVP_INCLUDED


#if (TC_DIGEST) 
#define ALGO_SHA1 "sha1"
int tc_init_digests();
int tc_destroy_digests();
int tc_init_sha1();
int tc_destroy_sha1();
int tc_sha1_digest_one(unsigned char *dest, unsigned int dest_len, 
        const unsigned char *seed, unsigned int seed_len);
int tc_sha1_digest_two(unsigned char *dest, unsigned int dest_len, 
        const unsigned char *seed1, unsigned int seed1_len, 
        const unsigned char *seed2, unsigned int seed2_len);
#endif

#endif   /* ----- #ifndef TC_EVP_INCLUDED ----- */

