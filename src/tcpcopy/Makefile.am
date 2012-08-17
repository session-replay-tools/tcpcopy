bin_PROGRAMS=tcpcopy

tcpcopy_SOURCES=\
                tcpcopy.h\
                tc_address.c tc_address.h\
                tc_manager.c tc_manager.h\
                tc_session.c tc_session.h\
                main.c
tcpcopy_LDADD=\
               ../core/libcore.a\
               ../util/libutil.a\
               ../mysql/libmysql.a\
               ../event/libevent.a\
               ../communication/libcommunication.a\
               -lm
