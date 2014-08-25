
#ifndef _TC_CONFIG_H_INCLUDED_
#define _TC_CONFIG_H_INCLUDED_


 #include <tc_auto_headers.h> 



typedef intptr_t        tc_int_t;
typedef uintptr_t       tc_uint_t;
typedef intptr_t        tc_flag_t;


#define TC_INT32_LEN   sizeof("-2147483648") - 1
#define TC_INT64_LEN   sizeof("-9223372036854775808") - 1

#if (TC_PTR_SIZE == 4)
#define TC_INT_T_LEN   TC_INT32_LEN
#else
#define TC_INT_T_LEN   TC_INT64_LEN
#endif


#ifndef TC_ALIGNMENT
#define TC_ALIGNMENT   sizeof(unsigned long)    /* platform word */
#endif

#define tc_align(d, a)     (((d) + (a - 1)) & ~(a - 1))
#define tc_align_ptr(p, a)                                                   \
    (u_char *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))


#if ((__GNU__ == 2) && (__GNUC_MINOR__ < 8))
#define TC_MAX_UINT32_VALUE  (uint32_t) 0xffffffffLL
#else
#define TC_MAX_UINT32_VALUE  (uint32_t) 0xffffffff
#endif

#define TC_MAX_INT32_VALUE   (uint32_t) 0x7fffffff


#endif /* _TC_CONFIG_H_INCLUDED_ */
