#ifndef __TCPCOPY_H__
#define __TCPCOPY_H__ 


typedef struct {
    /* Online ip from the client perspective */
    uint32_t online_ip;
    uint32_t target_ip;
    uint16_t online_port;
    uint16_t target_port;
} ip_port_pair_mapping_t;


typedef struct {
    int                      num;
    ip_port_pair_mapping_t **mappings;
} ip_port_pair_mappings_t;


typedef struct xcopy_clt_settings {
    unsigned int  replica_num:10;       /* Replicated number of each request */
    unsigned int  factor:8;             /* Port shift factor */
    unsigned int  mtu:16;               /* MTU sent to backend */
    unsigned int  do_daemonize:1;       /* Daemon flag */
    unsigned int  max_rss:21;           /* Max memory size allowed for tcpcopy
                                           client(max size 2G) */

    unsigned int  session_timeout:16;   /* Max value for session timeout
                                           If it reaches this value, the session
                                           will be removed */

    char         *raw_transfer;         /* Online_ip online_port target_ip
                                           target_port string */

    char         *pid_file;             /* Pid file */
    char         *log_path;             /* Error log path */
#if (TCPCOPY_OFFLINE)
    char         *pcap_file;            /* Pcap file */
#endif
    uint16_t      rand_port_shifted;    /* Random port shifted */
    uint16_t      srv_port;             /* Server listening port */
    uint32_t      lo_tf_ip;             /* Ip address from localhost to
                                           (localhost transfered ip) */
#ifdef TCPCOPY_MYSQL_ADVANCED
    char         *user_pwd;             /* User password string for mysql */
#endif
    ip_port_pair_mappings_t transfer;   /* Transfered online_ip online_port
                                           target_ip target_port */
    int           multiplex_io;
} xcopy_clt_settings;


typedef struct {
    int raw_socket_out;
    int raw_socket_in;
} tc_tcpcopy_rsc_t;

typedef struct {
    unsigned int tc_interval:1;
}tc_tcpcopy_ctl_t;

extern xcopy_clt_settings clt_settings;
extern tc_tcpcopy_rsc_t tcpcopy_rsc;
extern tc_tcpcopy_ctl_t tcpcopy_ctl;

#include <tc_util.h>

#ifdef TCPCOPY_MYSQL_ADVANCED
#include <pairs.h>
#include <protocol.h>
#endif

#include <tc_address.h>
#include <tc_manager.h>
#include <tc_session.h>

#endif /* __TCPCOPY_H__ */
