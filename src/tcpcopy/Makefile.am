bin_PROGRAMS=tcpcopy

tcpcopy_SOURCES=\
                tcpcopy.h\
                address.c address.h\
                send.c send.h\
                manager.c manager.h\
                session.c session.h\
				tc_offline_module.c tc_offline_module.h\
				tc_packets_module.c tc_packets_module.h\
				tc_message_module.c tc_message_module.h\
                main.c
tcpcopy_LDADD=\
               ../core/libcore.a\
               ../util/libutil.a\
               ../mysql/libmysql.a\
               ../event/libevent.a\
               ../communication/libcommunication.a\
               -lm
