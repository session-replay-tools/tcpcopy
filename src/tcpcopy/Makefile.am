bin_PROGRAMS=tcpcopy
if UDPCOPY
tcpcopy_SOURCES=\
                tcpcopy.h\
                tc_udp_session.c tc_udp_session.h\
                tc_packets_module.c tc_packets_module.h\
                tc_message_module.c tc_message_module.h\
                tc_manager.h tc_manager.c\
                main.c
tcpcopy_LDADD=\
               ../core/libcore.a\
               ../util/libutil.a\
               ../event/libevent.a\
               ../communication/libcommunication.a\
               -lm

else
tcpcopy_SOURCES=\
                tcpcopy.h\
                tc_session.h tc_session.c\
                tc_packets_module.h tc_packets_module.c\
                tc_message_module.h tc_message_module.c\
                tc_manager.h tc_manager.c\
                main.c
tcpcopy_LDADD=\
               ../core/libcore.a\
               ../util/libutil.a\
               ../digest/libdigest.a\
               ../mysql/libmysql.a\
               ../event/libevent.a\
               ../communication/libcommunication.a\
               -lm
endif
