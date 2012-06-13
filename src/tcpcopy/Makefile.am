bin_PROGRAMS=tcpcopy
tcpcopy_SOURCES=\
				address.c address.h\
				send.c send.h\
				session.c session.h\
				getopt.c getopt.h\
				main.c
tcpcopy_LDADD=\
				   ../core/libcore.a\
				   ../log/liblog.a\
				   ../util/util.a\
				   ../mysql/libmysql.a\
				   ../event/libevent.a\
				   ../communication/libmsg.a\
				   -lpthread -lcrypto
