#include "../core/xcopy.h"
#include "select_server.h"

static int                  max_fd;
static fd_set               read_set;
static select_server_func   callback_func;
static int                  valid_fds[MAX_FD_NUM];
static int                  fd_nums;


/* Set select event callback function */
void select_server_set_callback(select_server_func func)
{
    callback_func = func;
}

/* Add fd to select read set */
void select_server_add(int fd)
{
    if(fd > MAX_FD_VALUE){
        log_info(LOG_WARN, "fd:%d which is more than 1023", fd);
    }else{
        if(fd_nums >= MAX_FD_NUM){
            log_info(LOG_WARN, "too many fds");
        }else{
            FD_SET(fd, &read_set);
            if(fd > max_fd){
                max_fd = fd;
            }
            valid_fds[fd_nums] = fd;
            fd_nums++;
        }
    }
}

/* Delete fd from select read set */
void select_server_del(int fd)
{
    int i, j;
    if(fd <= MAX_FD_VALUE){
        FD_CLR(fd, &read_set);
        max_fd = 0;
        for(i = 0; i < fd_nums; i++){
            if(valid_fds[i] == fd){
                j = i;
                while(j < (fd_nums-1)){
                    valid_fds[j] = valid_fds[j + 1];
                    if(valid_fds[j] > max_fd){
                        max_fd = valid_fds[j];
                    }
                    j++;
                }
                fd_nums--;
                break;
            }
            if(valid_fds[i] > max_fd){
                max_fd = valid_fds[i];
            }
        }
    }
}

/* Run for receiving messages */
void select_server_run()
{
    fd_set r_set;
    int    i, ret;
    while(true){
        r_set = read_set;
        ret   = select(max_fd + 1, &r_set, NULL, NULL, NULL);
        if(-1 == ret){
            continue;
        }else if(0 == ret){
            continue;
        }else{
            for(i = 0; i < fd_nums; i++ ){
                if(FD_ISSET(valid_fds[i], &r_set)){
                    callback_func(valid_fds[i]);
                }
            }
        }
    }
}

