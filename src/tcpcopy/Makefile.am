if UDPCOPY
bin_PROGRAMS=udpcopy
udpcopy_SOURCES=\
                tcpcopy.h\
                tc_manager.c tc_manager.h\
                tc_udp_session.c tc_udp_session.h\
				tc_packets_module.c tc_packets_module.h\
				tc_message_module.c tc_message_module.h\
                main.c
udpcopy_LDADD=\
               ../core/libcore.a\
               ../util/libutil.a\
               ../event/libevent.a\
               -lm
else

bin_PROGRAMS=tcpcopy
tcpcopy_SOURCES=\
                tcpcopy.h\
                tc_manager.c tc_manager.h\
                tc_session.c tc_session.h\
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
endif
