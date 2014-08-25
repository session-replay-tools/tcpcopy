
#include <xcopy.h>

tc_uint_t  tc_pagesize;
tc_uint_t  tc_pagesize_shift;
tc_uint_t  tc_cacheline_size;


void *
tc_alloc(size_t size)
{
    void  *p;

    p = malloc(size);
    if (p == NULL) {
        tc_log_info(LOG_EMERG, errno,
                "malloc(%uz) failed", size);
    }

    return p;
}


#if (TC_HAVE_POSIX_MEMALIGN)

void *
tc_memalign(size_t alignment, size_t size)
{
    void  *p;
    int    err;

    err = posix_memalign(&p, alignment, size);

    if (err) {
        p = NULL;
    }

    return p;
}

#elif (TC_HAVE_MEMALIGN)

void *
tc_memalign(size_t alignment, size_t size)
{
    void  *p;

    p = memalign(alignment, size);
    if (p == NULL) {
        tc_log_info(LOG_EMERG, tc_errno,
                      "memalign(%uz, %uz) failed", alignment, size);
    }

    return p;
}

#endif
