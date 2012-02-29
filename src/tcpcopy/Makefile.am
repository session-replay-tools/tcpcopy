bin_PROGRAMS=tcpcopy
tcpcopy_SOURCES=\
				address.c address.h\
				send.cpp send.h\
				session.cpp session.h\
				getopt.c getopt.h\
				main.cpp
tcpcopy_LDADD=\
				   ../log/liblog.a\
				   ../mysql/libmysql.a\
				   ../event/libevent.a\
				   ../communication/libmsg.a\
				   -lpthread -lcrypto
