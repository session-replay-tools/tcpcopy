#include <xcopy.h>
#include <intercept.h>
#if (INTERCEPT_THREAD)
#include <pthread.h>

static char            pool[POOL_SIZE];
static uint64_t        read_counter  = 0;
static uint64_t        write_counter = 0; 
static pthread_mutex_t mutex;
static pthread_cond_t  empty;
static pthread_cond_t  full;

void tc_pool_init()
{
    pthread_mutex_init(&mutex, NULL);                                                               
    pthread_cond_init(&full, NULL);
    pthread_cond_init(&empty, NULL);
}

void put_resp_header_to_pool(tc_ip_header_t *ip_header)
{
    int                    *p_len, cur_w_pos, diff, next_w_pos;
    char                   *p_content;
    uint16_t                size_ip, size_tcp, new_size_tcp, save_len, record_len;
#if (TCPCOPY_MYSQL_ADVANCED) 
    uint16_t                cont_len, tot_len;
    unsigned char          *payload; 
#endif
    uint64_t                next_w_cnt; 
    tc_tcp_header_t        *tcp_header;

    if (ip_header->protocol != IPPROTO_TCP) {
        tc_log_info(LOG_WARN, 0, "this is not a tcp packet");
        return;
    }

    save_len = RESP_MAX_USEFUL_SIZE;

    size_ip = ip_header->ihl << 2;
    tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);
    size_tcp = tcp_header->doff << 2;

#if (TCPCOPY_MYSQL_ADVANCED) 
    tot_len  = ntohs(ip_header->tot_len);
    cont_len = tot_len - size_ip - size_tcp;
#endif

    record_len = save_len;
    pthread_mutex_lock(&mutex);
    next_w_cnt = write_counter + save_len + sizeof(int); 
    next_w_pos = next_w_cnt & POOL_MASK;

    if (next_w_pos > POOL_MAX_ADDR) {
        next_w_cnt  = (next_w_cnt / POOL_SIZE + 1) << POOL_SHIFT;
        record_len += (POOL_SIZE - next_w_pos);
    }

    diff = next_w_cnt - read_counter;
    
    for (;;) {
        if (diff > POOL_SIZE) {
            tc_log_info(LOG_WARN, 0, "pool is full");
            pthread_cond_wait(&empty, &mutex);
        } else {
            break;
        }
        diff = next_w_cnt - read_counter;
    }

    cur_w_pos = write_counter & POOL_MASK;
    p_len     = (int *) (pool + cur_w_pos);
    p_content = (char *) ((unsigned char *) p_len + sizeof(int));
    
    write_counter = next_w_cnt;
    
    *p_len = record_len;
    ip_header->ihl = (sizeof(tc_ip_header_t)) >> 2;
    memcpy(p_content, ip_header, sizeof(tc_ip_header_t));
    p_content = p_content + sizeof(tc_ip_header_t);

    new_size_tcp = size_tcp;
    if (size_tcp > TCP_HEADER_MIN_LEN) {
        set_wscale(tcp_header);
        new_size_tcp = tcp_header->doff << 2;
    }   
    memcpy(p_content, tcp_header, new_size_tcp);

#if (TCPCOPY_MYSQL_ADVANCED) 
    if (cont_len > 0 && cont_len <= MAX_PAYLOAD_LEN) {
        p_content = p_content + new_size_tcp
        payload = (unsigned char *) ((char *) tcp_header + size_tcp);
        memcpy(p_content, payload, cont_len);
    }
#endif

    pthread_cond_signal(&full);
    pthread_mutex_unlock(&mutex);
}

tc_ip_header_t *
get_resp_ip_hdr_from_pool(char *resp, int *len)
{
    int       read_pos;
    char     *pos;

    pthread_mutex_lock(&mutex);

    if (read_counter >= write_counter) {
        pthread_cond_wait(&full, &mutex);
    }

    read_pos = read_counter & POOL_MASK;

    pos = pool + read_pos;
    *len = *(int *) (pos);

    pos = pos + sizeof(int);

    memcpy(resp, pos, *len);

    read_counter += (*len + sizeof(int));

    pthread_cond_signal(&empty);
    pthread_mutex_unlock(&mutex);

    return (tc_ip_header_t *) resp;
}

#endif

