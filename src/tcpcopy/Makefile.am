bin_PROGRAMS=tcpcopy

tcpcopy_SOURCES=\
                address.c address.h\
                send.c send.h\
                manager.c manager.h\
                session.c session.h\
                main.c
tcpcopy_LDADD=\
               ../core/libcore.a\
               ../log/liblog.a\
               ../util/libutil.a\
               ../mysql/libmysql.a\
               ../event/libevent.a\
               ../communication/libmsg.a\
               -lcrypto -lm
