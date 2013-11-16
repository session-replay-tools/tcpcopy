bin_PROGRAMS=intercept

if ADVANCED
intercept_SOURCES=\
                  intercept.h\
                  tc_delay.c tc_delay.h\
                  tc_router.c tc_router.h\
                  tc_combine.c tc_combine.h\
                  tc_server_common.c tc_server_common.h\
                  tc_capture.c tc_interception.h\
                  main.c
else
intercept_SOURCES=\
                  intercept.h\
                  tc_router.c tc_router.h\
                  tc_delay.c tc_delay.h\
                  tc_combine.c tc_combine.h\
                  tc_server_common.c tc_server_common.h\
                  tc_interception.c tc_interception.h\
                  main.c
endif
intercept_LDADD=\
                 ../core/libcore.a\
                 ../util/libutil.a\
                 ../event/libevent.a\
                 ../communication/libcommunication.a
