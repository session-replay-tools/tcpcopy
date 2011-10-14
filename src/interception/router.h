#ifndef  _TCPCOPY_RECEIVER_ROUTER_H_INC
#define  _TCPCOPY_RECEIVER_ROUTER_H_INC

#ifdef __cplusplus
extern "C"
{
#endif

	void router_init();
	void router_update(struct iphdr *ip_header);
	void router_add(uint32_t ,uint16_t,int);
	void router_del(uint32_t ,uint16_t);
	void router_destroy();


#ifdef __cplusplus
}
#endif
#endif   /* ----- #ifndef _TCPCOPY_RECEIVER_ROUTER_H_INC  ----- */

