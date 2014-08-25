#include <xcopy.h>


tc_array_t *
tc_array_create(tc_pool_t *p, unsigned int n, size_t size)
{
    tc_array_t *a;

    a = tc_palloc(p, sizeof(tc_array_t));
    if (a == NULL) {
        return NULL;
    }

    if (tc_array_init(a, p, n, size) != TC_OK) {
        return NULL;
    }

    return a;
}


void
tc_array_destroy(tc_array_t *a)
{
    tc_pool_t  *p;

    p = a->pool;

    if ((u_char *) a->elts + a->size * a->nalloc == p->d.last) {
        p->d.last -= a->size * a->nalloc;
    }

    if ((u_char *) a + sizeof(tc_array_t) == p->d.last) {
        p->d.last = (u_char *) a;
    }
}


void *
tc_array_push(tc_array_t *a)
{
    void        *elt, *new;
    size_t       size;
    tc_pool_t  *p;

    if (a->nelts == a->nalloc) {

        /* the array is full */

        size = a->size * a->nalloc;

        p = a->pool;

        if ((u_char *) a->elts + size == p->d.last
            && p->d.last + a->size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            p->d.last += a->size;
            a->nalloc++;

        } else {
            /* allocate a new array */

            new = tc_palloc(p, 2 * size);
            if (new == NULL) {
                return NULL;
            }

            memcpy(new, a->elts, size);
            a->elts = new;
            a->nalloc *= 2;
        }
    }

    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts++;

    return elt;
}


void *
tc_array_push_n(tc_array_t *a, unsigned int n)
{
    void        *elt, *new;
    size_t       size;
    unsigned int   nalloc;
    tc_pool_t  *p;

    size = n * a->size;

    if (a->nelts + n > a->nalloc) {

        /* the array is full */

        p = a->pool;

        if ((u_char *) a->elts + a->size * a->nalloc == p->d.last
            && p->d.last + size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            p->d.last += size;
            a->nalloc += n;

        } else {
            /* allocate a new array */

            nalloc = 2 * ((n >= a->nalloc) ? n : a->nalloc);

            new = tc_palloc(p, nalloc * a->size);
            if (new == NULL) {
                return NULL;
            }

            memcpy(new, a->elts, a->nelts * a->size);
            a->elts = new;
            a->nalloc = nalloc;
        }
    }

    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts += n;

    return elt;
}
