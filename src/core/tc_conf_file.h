#ifndef  TC_CONF_FILE_INCLUDED
#define  TC_CONF_FILE_INCLUDED

#include <xcopy.h>

#if (TC_PLUGIN)
#define TC_CONF_BLOCK_START 1
#define TC_CONF_BLOCK_DONE  2
#define TC_CONF_FILE_DONE   3

#define tc_file_size(sb)        (sb)->st_size
#define LF     (u_char) 10
#define CR     (u_char) 13
#define CRLF   "\x0d\x0a"

typedef struct {          
    int            len;      
    unsigned char *data;    
} tc_str_t;

struct tc_buf_s {
    unsigned char  *pos;
    unsigned char  *last;
    unsigned char  *start;
    unsigned char  *end;
};

struct tc_file_s {
    int         fd;
    off_t       offset;
    struct stat info;
};

typedef struct {
    tc_file_t      file;
    tc_buf_t      *buffer;
    int            line;
} tc_conf_file_t;

struct tc_cmd_s {
    tc_str_t              name;
    int                   conf;
    int                   offset;
    unsigned int          type;
    int                 (*set)(tc_conf_t *cf, tc_cmd_t *cmd);
    void                 *post;
};

struct tc_conf_s {
    tc_array_t          *args;
    tc_pool_t           *pool;
    tc_conf_file_t      *conf_file;
};

char *tc_conf_full_name(tc_pool_t *,char *, char *);
int tc_conf_parse(tc_module_t *plugin, tc_pool_t *pool, tc_conf_t *cf, 
        char *filename);
#endif

#endif
