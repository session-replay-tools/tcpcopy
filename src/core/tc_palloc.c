
#include <xcopy.h>

static void *tc_palloc_block(tc_pool_t *pool, size_t size);
static void *tc_palloc_large(tc_pool_t *pool, size_t size);


tc_pool_t *
tc_create_pool(int size, int sub_size, int pool_max)
{
    tc_pool_t  *p;

    if (size < (int) TC_MIN_POOL_SIZE) {
        tc_log_info(LOG_ERR, 0, "pool size must be no less than:%d", 
                TC_MIN_POOL_SIZE);
        size = TC_MIN_POOL_SIZE;
    }

    p = tc_memalign(TC_POOL_ALIGNMENT, size);
    if (p != NULL) {
        p->d.last = (u_char *) p + sizeof(tc_pool_t);
        p->d.end  = (u_char *) p + size;
        p->d.next = NULL;
        p->d.failed = 0;
        p->d.objs   = 0;
        p->d.cand_recycle = 0;
        p->d.need_check = 0;
        p->main_size = size;
        if (sub_size > (int) TC_MIN_POOL_SIZE) {
            p->sub_size = sub_size;
        } else {
            p->sub_size = p->main_size;
        }

        size = size - sizeof(tc_pool_t);
        
        if (pool_max && size >= pool_max) {
            p->sh_num.max = pool_max;
        } else {
            p->sh_num.max = (size < (int) TC_MAX_ALLOC_FROM_POOL) ? 
                size : (int) TC_MAX_ALLOC_FROM_POOL;
        }

        p->current = p;
        p->sh_pt.large = NULL;
    }
    
    return p;
}


void
tc_destroy_pool(tc_pool_t *pool)
{
#if (TC_DEBUG)
    int                 tot_size, sub_size;
#endif
    tc_pool_t          *p, *n;
    tc_pool_large_t    *l;

    for (l = pool->sh_pt.large; l; l = l->next) {

        if (l->alloc) {
            tc_free(l->alloc);
        }
    }

#if (TC_DEBUG)
    tot_size = pool->main_size - pool->sub_size;
    sub_size = pool->sub_size;
#endif
    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
#if (TC_DEBUG)
        tot_size += sub_size;
#endif
        tc_free(p);

        if (n == NULL) {
            break;
        }
    }

#if (TC_DEBUG)
    tc_log_info(LOG_NOTICE, 0, "pool occupy:%d", tot_size);
#endif

}


void *
tc_palloc(tc_pool_t *pool, size_t size)
{
    u_char            *m;
    tc_pool_t         *p;
    tc_mem_hid_info_t *hid;

    size = size + MEM_HID_INFO_SZ;

    if ((int) size <= pool->sh_num.max) {

        p = pool->current;

        do {
            m = tc_align_ptr(p->d.last, TC_ALIGNMENT);

            if ((size_t) (p->d.end - m) >= size) {            
#if (TC_DETECT_MEMORY)
                if (p->d.last >= p->d.end) {
                    tc_log_info(LOG_WARN, 0, "pool full");
                }
#endif
                p->d.objs++;
                p->d.last = m + size;
                hid = (tc_mem_hid_info_t *) m;
                hid->large = 0;
                hid->len = size;
                hid->try_rel_cnt = 0;
                hid->released = 0;

                return m + MEM_HID_INFO_SZ;
            }

            p = p->d.next;

        } while (p);

        m = tc_palloc_block(pool, size);
        if (m != NULL) {
            hid = (tc_mem_hid_info_t *) m;
            hid->large = 0;
            hid->len = size;
            hid->try_rel_cnt = 0;
            hid->released = 0;
            return m + MEM_HID_INFO_SZ;
        } else {
            return NULL;
        }
    }

    m = tc_palloc_large(pool, size);
    if (m != NULL) {
        hid = (tc_mem_hid_info_t *) m;
        hid->large = 1;
        hid->len = size;
        hid->try_rel_cnt = 0;
        hid->released = 0;
        return m + MEM_HID_INFO_SZ;
    } else {
        return NULL;
    }
}


static bool 
tc_check_block_free(tc_pool_t *root, tc_pool_t *p)
{
    int                i;
    u_char            *m;
    tc_mem_hid_info_t *hid;

    if (p->sh_pt.fp) {
        m = (u_char *) p->sh_pt.fp;
        i = p->sh_num.fn;
    } else {
        m = ((u_char *) p) + sizeof(tc_pool_t);
        m = tc_align_ptr(m, TC_ALIGNMENT);
        i = 0;
    }

    while (m < p->d.end) {
        hid = (tc_mem_hid_info_t *) m;
        if (!hid->released) {
            p->sh_pt.fp = hid;
            p->sh_num.fn = i;
            hid->try_rel_cnt++;
            if (hid->try_rel_cnt == REL_CNT_MAX_VALUE) {
                tc_log_info(LOG_INFO, 0, "pool:%llu,block:%llu,len:%u occupy", 
                        root, p, hid->len);
            }
            return false;
        }
        m += hid->len;
        m = tc_align_ptr(m, TC_ALIGNMENT);
        i++;

        if (i == p->d.objs) {
            break;
        }
    }

    return true;
}


static void *
tc_palloc_block(tc_pool_t *pool, size_t size)
{
    bool        reused;
    u_char     *m;
    size_t      psize;
    tc_pool_t  *p, *new, *current;

    reused = false;

    p  = pool->d.next;
    if (p && p->d.cand_recycle) {
        if (tc_check_block_free(pool, p)) {
            reused = true;
            m = (u_char *) p;
            new = p;
            pool->d.next = p->d.next;
            tc_log_debug2(LOG_INFO, 0, "pool:%llu recycle:%llu", pool, p);
        }
    }

    if (!reused) {
        if (pool->sub_size) {
            psize = pool->sub_size;
        } else {
            psize = (size_t) (pool->d.end - (u_char *) pool);
        }
        m = tc_memalign(TC_POOL_ALIGNMENT, psize);

        if (m == NULL) {
            return NULL;
        }
        new = (tc_pool_t *) m;
        new->d.end  = m + psize;
    }

    new->d.next = NULL;
    new->d.failed = 0;
    new->d.objs = 1;
    new->d.cand_recycle = 0;
    new->d.need_check = 1;
    new->sh_pt.fp = NULL;
    new->sh_num.fn = 0;

    m += sizeof(tc_pool_t);
    m = tc_align_ptr(m, TC_ALIGNMENT);
    new->d.last = m + size;

#if (TC_DETECT_MEMORY)
    if (new->d.last > new->d.end) {
        tc_log_info(LOG_WARN, 0, "pool overflow");
    }
#endif

    current = pool->current;

    for (p = current; p->d.next; p = p->d.next) {
        if (p->d.failed++ > 4) {
            if (p->d.need_check) {
                p->d.cand_recycle = 1;
            }
            current = p->d.next;
        }
    }

    p->d.next = new;

    pool->current = current ? current : new;

    return m;
}


static void *
tc_palloc_large(tc_pool_t *pool, size_t size)
{
    void              *p;
    tc_uint_t          n;
    tc_pool_large_t   *large;

    p = tc_alloc(size);
    if (p != NULL) {

        n = 0;

        for (large = pool->sh_pt.large; large; large = large->next) {
            if (large->alloc == NULL) {
                large->alloc = p;
                return p;
            }

            if (n++ > 3) {
                break;
            }
        }

        large = tc_palloc(pool, sizeof(tc_pool_large_t));
        if (large == NULL) {
            tc_free(p);
            return NULL;
        }

        large->alloc = p;
        large->next = pool->sh_pt.large;
        pool->sh_pt.large = large;
    }

    return p;
}


tc_int_t
tc_pfree(tc_pool_t *pool, void *p)
{
    tc_pool_large_t   *l, *prev;
    tc_mem_hid_info_t *act_p;
    
    if (p == NULL)
        return TC_OK;

    act_p = (tc_mem_hid_info_t *) ((u_char *) p - MEM_HID_INFO_SZ);

    if (act_p->large) {
        prev = NULL;
        for (l = pool->sh_pt.large; l; l = l->next) {
            if (act_p == l->alloc) {
                tc_free(l->alloc);
                l->alloc = NULL;

                if (prev) {
                    prev->next = l->next;
                } else {
                    pool->sh_pt.large = l->next;
                }

                act_p = (tc_mem_hid_info_t *) ((u_char *) l - MEM_HID_INFO_SZ);
                act_p->released = 1;
#if (TC_DETECT_MEMORY)
                if (act_p->len != TC_LARGE_OBJ_INFO_SIZE) {
                    tc_log_info(LOG_WARN, 0, "pool item wrong:%d != %d", 
                            act_p->len, TC_LARGE_OBJ_INFO_SIZE);
                }
#endif

                return TC_OK;
            }
            prev = l;
        }

#if (TC_DETECT_MEMORY)
        if (l == NULL) {
            tc_log_info(LOG_WARN, 0, "pool item not freed");
        }
#endif
    } else {
        act_p->released = 1;
    }

    return TC_DELAYED;
}



void *
tc_pcalloc(tc_pool_t *pool, size_t size)
{
    void *p;

    p = tc_palloc(pool, size);
    if (p) {
        tc_memzero(p, size);
    }

    return p;
}


