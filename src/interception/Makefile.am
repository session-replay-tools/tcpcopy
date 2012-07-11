bin_PROGRAMS=intercept

intercept_SOURCES=\
                  router.c router.h\
                  delay.c delay.h\
                  interception.c interception.h\
                  nl_firewall.c nl_firewall.h\
                  nl.c nl.h\
                  main.c
intercept_LDADD=\
                 ../core/libcore.a\
                 ../log/liblog.a\
                 ../util/libutil.a\
                 ../event/libevent.a\
                 ../communication/libmsg.a
