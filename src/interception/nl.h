#ifndef  _NL_H_INC
#define  _NL_H_INC

#include "../core/xcopy.h"

    int  nl_init(int, int);
    void nl_set_mode(int sock, uint8_t mode, size_t range);
    ssize_t nl_recv(int, void *, size_t); 
    void *nl_get_payload(void *);

#endif   /* ----- #ifndef _NL_H_INC----- */

