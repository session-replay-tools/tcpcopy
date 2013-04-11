#ifndef  PASSWORD_INCLUDED
#define  PASSWORD_INCLUDED


#if (TCPCOPY_MYSQL_ADVANCED) 
void scramble(char *to, const char *message, const char *password);
#endif

#endif   /* ----- #ifndef PASSWORD_INCLUDED  ----- */

