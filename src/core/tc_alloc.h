#ifndef _TC_ALLOC_H_INCLUDED_
#define _TC_ALLOC_H_INCLUDED_


#include <xcopy.h>


void *tc_alloc(size_t size);

#define tc_free          free


#if (TC_HAVE_POSIX_MEMALIGN || TC_HAVE_MEMALIGN)

void *tc_memalign(size_t alignment, size_t size);

#else

#define tc_memalign(alignment, size)  tc_alloc(size)

#endif


extern tc_uint_t  tc_pagesize;
extern tc_uint_t  tc_pagesize_shift;
extern tc_uint_t  tc_cacheline_size;


#endif /* _TC_ALLOC_H_INCLUDED_ */
