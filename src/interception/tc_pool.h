#ifndef  TC_POOL_INCLUDED
#define  TC_POOL_INCLUDED

#if (INTERCEPT_THREAD)
void tc_pool_init();
void put_resp_header_to_pool(tc_ip_header_t *ip_header);
tc_ip_header_t *get_resp_ip_hdr_from_pool(char *resp, int *len);
#endif

#endif /* TC_POOL_INCLUDED */

