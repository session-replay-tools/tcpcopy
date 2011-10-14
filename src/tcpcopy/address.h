#ifndef  _TCPCOPY_COPYER_ADDRESS_H_INC
#define  _TCPCOPY_COPYER_ADDRESS_H_INC


#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct address_node{
		uint32_t ip;
		uint32_t port;
		int      sock;
	}address;

	void 	 add_msg_connetion(uint16_t src_port,uint32_t dst_ip,uint16_t dst_port);
	void 	 address_init();
	int  	 address_add(const char *ptr);
	address *address_find_node(uint16_t src_port);
	int 	 address_copy_or_not(uint16_t);
	int 	 address_find_sock(uint16_t src_port);

#ifdef __cplusplus
}
#endif

#endif   /* ----- #ifndef _TCPCOPY_COPYER_ADDRESS_H_INC ----- */

