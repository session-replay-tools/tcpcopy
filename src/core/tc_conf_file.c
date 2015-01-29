#include <xcopy.h>

#if (TC_PLUGIN)

#define TC_CONF_BUFFER  4096

static int tc_conf_handler(tc_cmd_t *, tc_conf_t *, int);
static int tc_conf_read_token(tc_conf_t *);

static int argument_number[] = {
    TC_CONF_NOARGS,
    TC_CONF_TAKE1,
    TC_CONF_TAKE2,
    TC_CONF_TAKE3,
};


char *
tc_conf_full_name(tc_pool_t *pool, char *prefix, char *name)
{
    size_t      name_len, pref_len;
    u_char     *p, *n;

    if (name[0] == '/') {
        return name;
    }

    pref_len = strlen(prefix);
    name_len = strlen(name);
    n = tc_palloc(pool, pref_len + name_len + 1);
    if (n == NULL) {
        return NULL;
    }

    p = memcpy(n, prefix, pref_len);
    p = p + pref_len;

    memcpy(p, name, name_len + 1);

    return (char *) n;
}


int
tc_conf_parse(tc_module_t *plugin, tc_pool_t *pool, tc_conf_t *cf, 
        char *filename)
{
    int             fd, rc;
    tc_buf_t        buf;
    tc_conf_file_t conf_file;

    if (filename) {

        fd = open((const char *) filename, O_RDONLY, 0);
        if (fd == -1) {
            tc_log_info(LOG_ERR, errno, "open %s failed", filename);
            return TC_ERR;
        }

        cf->conf_file = &conf_file;

        if (fstat(fd, &cf->conf_file->file.info) == -1) {
            tc_log_info(LOG_ERR, errno, "fstat %s failed", filename);
            return TC_ERR;
        }

        cf->conf_file->buffer = &buf;
        buf.start = tc_alloc(TC_CONF_BUFFER);
        
        if (buf.start == NULL) {
            return TC_ERR;
        }

        buf.pos = buf.start;
        buf.last = buf.start;
        buf.end = buf.last + TC_CONF_BUFFER;

        cf->conf_file->file.fd = fd;
        cf->conf_file->file.offset = 0; 
        cf->conf_file->line = 1; 

    } else {
        return TC_ERR;
    }


    for ( ;; ) {
        rc = tc_conf_read_token(cf);

        if (rc == TC_ERR) {
            return TC_ERR;
        }

        if (rc == TC_CONF_FILE_DONE) {
            return TC_OK;
        }

        if (plugin->cmds) {
            rc = tc_conf_handler(plugin->cmds, cf, rc);

            if (rc == TC_ERR) {
                return TC_ERR;
            }
        }
    }

    return TC_OK;
}


static int
tc_conf_handler(tc_cmd_t *cmd, tc_conf_t *cf, int last)
{
    int             found;
    tc_str_t       *name;

    name = cf->args->elts;

    found = 0;

    for ( /* void */ ; cmd->name.len; cmd++) {

        if (name->len != cmd->name.len) {
            continue;
        }

        if (strcmp((char *) name->data, (char *) cmd->name.data) != 0) {
            continue;
        }

        found = 1;


        if (cmd->type & TC_CONF_FLAG) {

            if (cf->args->nelts != 2) {
                goto invalid;
            }

        } else if (cmd->type & TC_CONF_1MORE) {

            if (cf->args->nelts < 2) {
                goto invalid;
            }

        } else if (cmd->type & TC_CONF_2MORE) {

            if (cf->args->nelts < 3) {
                goto invalid;
            }

        } else if (cf->args->nelts > TC_CONF_MAX_ARGS) {

            goto invalid;

        } else if (!(cmd->type & argument_number[cf->args->nelts - 1]))
        {
            goto invalid;
        }

        return cmd->set(cf, cmd);
    }

    if (found) {
        tc_log_info(LOG_ERR, 0,
                "\"%s\" directive is not allowed here", name->data);

        return TC_ERR;
    }

    tc_log_info(LOG_ERR, 0,
            "unknown directive \"%s\"", name->data);

    return TC_ERR;

invalid:

    tc_log_info(LOG_ERR, 0,
            "invalid number of arguments in \"%s\" directive",
            name->data);

    return TC_ERR;
}


static int 
tc_read_file(tc_file_t *file, unsigned char *buf, size_t size, off_t offset)
{
    ssize_t  n;
    n = pread(file->fd, buf, size, offset);
    if (n == -1) {
        tc_log_info(LOG_ERR, errno, "pread() failed");
        return TC_ERR;
    }

    file->offset += n;

    return (int) n;


}

static int
tc_conf_read_token(tc_conf_t *cf)
{
    u_char      *start, ch, *src, *dst;
    off_t        file_size;
    size_t       len;
    ssize_t      n, size;
    int          found, need_space, last_space, sharp_comment;
    int          quoted, s_quoted, d_quoted, start_line;
    tc_str_t    *word;
    tc_buf_t    *b;

    found = 0;
    need_space = 0;
    last_space = 1;
    sharp_comment = 0;
    quoted = 0;
    s_quoted = 0;
    d_quoted = 0;

    cf->args->nelts = 0;
    b = cf->conf_file->buffer;
    start = b->pos;
    start_line = cf->conf_file->line;

    file_size = tc_file_size(&cf->conf_file->file.info);

    for ( ;; ) {

        if (b->pos >= b->last) {

            if (cf->conf_file->file.offset >= file_size) {

                if (cf->args->nelts > 0 || !last_space) {

                    tc_log_info(LOG_ERR, 0,
                                  "unexpected end of file, "
                                  "expecting \";\"");
                    return TC_ERR;
                }

                return TC_CONF_FILE_DONE;
            }

            len = b->pos - start;

            if (len == TC_CONF_BUFFER) {
                cf->conf_file->line = start_line;

                if (d_quoted) {
                    ch = '"';

                } else if (s_quoted) {
                    ch = '\'';

                } else {
                    tc_log_info(LOG_ERR, 0,
                                       "too long parameter \"%*s...\" started",
                                       10, start);
                    return TC_ERR;
                }

                tc_log_info(LOG_ERR, 0,
                                   "too long parameter, probably "
                                   "missing terminating \"%c\" character", ch);
                return TC_ERR;
            }

            if (len) {
                memmove(b->start, start, len);
            }

            size = (ssize_t) (file_size - cf->conf_file->file.offset);

            if (size > b->end - (b->start + len)) {
                size = b->end - (b->start + len);
            }

            n = tc_read_file(&cf->conf_file->file, b->start + len, size,
                              cf->conf_file->file.offset);

            if (n == TC_ERR) {
                return TC_ERR;
            }

            if (n != size) {
                tc_log_info(LOG_ERR, 0,
                                   "returned only %z bytes instead of %z",
                                   n, size);
                return TC_ERR;
            }

            b->pos = b->start + len;
            b->last = b->pos + n;
            start = b->start;
        }

        ch = *b->pos++;

        if (ch == LF) {
            cf->conf_file->line++;

            if (sharp_comment) {
                sharp_comment = 0;
            }
        }

        if (sharp_comment) {
            continue;
        }

        if (quoted) {
            quoted = 0;
            continue;
        }

        if (need_space) {
            if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
                last_space = 1;
                need_space = 0;
                continue;
            }

            if (ch == ';') {
                return TC_OK;
            }

            if (ch == ')') {
                last_space = 1;
                need_space = 0;

            } else {
                 tc_log_info(LOG_ERR, 0,
                                    "unexpected \"%c\"", ch);
                 return TC_ERR;
            }
        }

        if (last_space) {
            if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
                continue;
            }

            start = b->pos - 1;
            start_line = cf->conf_file->line;

            switch (ch) {

            case ';':
            case '#':
                sharp_comment = 1;
                continue;

            case '\\':
                quoted = 1;
                last_space = 0;
                continue;

            case '"':
                start++;
                d_quoted = 1;
                last_space = 0;
                continue;

            case '\'':
                start++;
                s_quoted = 1;
                last_space = 0;
                continue;

            default:
                last_space = 0;
            }

        } else {

            if (ch == '\\') {
                quoted = 1;
                continue;
            }

            if (ch == '$') {
                continue;
            }

            if (d_quoted) {
                if (ch == '"') {
                    d_quoted = 0;
                    need_space = 1;
                    found = 1;
                }

            } else if (s_quoted) {
                if (ch == '\'') {
                    s_quoted = 0;
                    need_space = 1;
                    found = 1;
                }

            } else if (ch == ' ' || ch == '\t' || ch == CR || ch == LF
                       || ch == ';') 
            {
                last_space = 1;
                found = 1;
            }

            if (found) {
                word = tc_array_push(cf->args);
                if (word == NULL) {
                    return TC_ERR;
                }

                word->data = tc_palloc(cf->pool, b->pos - start + 1);
                if (word->data == NULL) {
                    return TC_ERR;
                }

                for (dst = word->data, src = start, len = 0;
                     src < b->pos - 1;
                     len++)
                {
                    if (*src == '\\') {
                        switch (src[1]) {
                        case '"':
                        case '\'':
                        case '\\':
                            src++;
                            break;

                        case 't':
                            *dst++ = '\t';
                            src += 2;
                            continue;

                        case 'r':
                            *dst++ = '\r';
                            src += 2;
                            continue;

                        case 'n':
                            *dst++ = '\n';
                            src += 2;
                            continue;
                        }

                    }
                    *dst++ = *src++;
                }
                *dst = '\0';
                word->len = len;

                if (ch == ';') {
                    return TC_OK;
                }

                found = 0;
            }
        }
    }
}
#endif
