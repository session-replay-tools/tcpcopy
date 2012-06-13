#include "../core/xcopy.h"

static int sock;
static struct sockaddr_in dst_addr;

int send_init(){
	int n = 1;
	/*
	 * On Linux when setting the protocol as IPPROTO_RAW,
	 * then by default the kernel sets the IP_HDRINCL option and 
	 * thus does not prepend its own IP header. 
	 */
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock > 0) {
		log_info(LOG_NOTICE, "create raw output socket successfully");
	} 
	else {
		log_info(LOG_ERR, "it can't create raw output socket");
	} 
	/*
	 * Tell the IP layer not to prepend its own header
	 * it does not need setting for linux,but *BSD needs
	 */
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &n, sizeof(n)) < 0) {
		perror("IP_HDRINCL");  
		log_info(LOG_ERR, "%s", strerror(errno));
		exit(1);  
	}
	dst_addr.sin_family = AF_INET;

	return 0;
}

int send_close(){
	if(sock > 0){
		close(sock);
		sock = -1;
	}
	return 0;
}

/*
 * Send the ip packet to the remote test server
 * (it will not go through ip fragmentation))
 */
ssize_t send_ip_packet(uint32_t dst_ip, struct iphdr *ip_header,
		uint16_t tot_len)
{
	/*
	 * The IP layer isn't involved at all. This has one negative effect 
	 * in result(although in performance it's better): 
	 * no IP fragmentation will take place if needed. 
	 * This means that a raw packet larger than the MTU of the 
	 * interface will probably be discarded. Instead ip_local_error(), 
	 * which does general sk_buff cleaning,is called and an error EMSGSIZE 
	 * is returned. On the other hand, normal raw socket frag.
	 * if tot_len is more than 1500,it will fail
	 */
	ssize_t send_len = 0;
	if(sock > 0)
	{
		dst_addr.sin_addr.s_addr = dst_ip;
		send_len = sendto(sock, (char *)ip_header, tot_len, 0,
				(struct sockaddr *)&dst_addr, sizeof(dst_addr));
		if(-1 == send_len)
		{
			perror("send to");
			log_info(LOG_ERR,"send to:%s", strerror(errno));
		}
	}

	return send_len;
}

