#ifndef  _MANAGER_H_INC
#define  _MANAGER_H_INC

#include "../core/xcopy.h"

int tcp_copy_init();
void tcp_copy_over(const int sig);
void tcp_copy_exit();

#endif   /* ----- #ifndef _MANAGER_H_INC ----- */

