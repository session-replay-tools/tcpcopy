#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(tcpcopy, 0.6.8, wangbin579@gmail.com)
AC_CONFIG_SRCDIR([src/interception/main.c])
AC_CONFIG_HEADER([src/core/config.h])


AM_INIT_AUTOMAKE(tcpcopy,0.6.8)


# Checks for programs.
AC_PROG_LN_S
AC_PROG_MAKE_SET

# Checks for libraries.

AC_PROG_LIBTOOL
AM_PROG_LIBTOOL

AC_ARG_ENABLE(debug, AS_HELP_STRING([--enable-debug],[compile tcpcopy with debug support(saved in a log file)]),,debug=no)
if test "x$enable_debug" = "xyes";then
	AC_DEFINE(TCPCOPY_DEBUG, 1, [Define if --enable-debug])
fi

#AC_ARG_ENABLE(epoll-module, AS_HELP_STRING([--enable-epoll-module],[use epoll module]),
#    AC_DEFINE(TCPCOPY_USE_EPOLL, 1, [Define if --enable-epoll-module]), )

AC_ARG_ENABLE(mysqlsgt, AS_HELP_STRING([--enable-mysqlsgt],[run tcpcopy at mysql skip-grant-tables mode]),,mysqlsgt=no)
if test "x$enable_mysqlsgt" = "xyes";then
	AC_DEFINE(TCPCOPY_MYSQL_SKIP, 1, [Define if --enable-mysqlsgt])
fi

AC_ARG_ENABLE(mysql, AS_HELP_STRING([--enable-mysql],[run tcpcopy at mysql mode]),,mysql=no)
if test "x$enable_mysql" = "xyes";then
	AC_DEFINE(TCPCOPY_MYSQL_NO_SKIP, 1, [Define if --enable-mysql])
fi

AC_ARG_ENABLE(offline, AS_HELP_STRING([--enable-offline],[run tcpcopy at offline mode]),,offline=no)
if test "x$enable_offline" = "xyes";then
	AC_DEFINE(TCPCOPY_OFFLINE, 1, [Define if --enable-offline])
fi

AC_ARG_ENABLE(nfqueue, AS_HELP_STRING([--enable-nfqueue],[ run tcpcopy server (i.e. intercept) at nfqueue mode (without this setting, ip queue will be used by default)]),,nfqueue=no)
if test "x$enable_nfqueue" = "xyes";then
	AC_DEFINE(INTERCEPT_NFQUEUE, 1, [Define if --enable-nfqueue])
fi

AC_ARG_ENABLE(pcap, AS_HELP_STRING([--enable-pcap],[ run tcpcopy client(i.e. tcpcopy) at pcap mode]),,pcap=no)
if test "x$enable_pcap" = "xyes";then
	AC_DEFINE(TCPCOPY_PCAP, 1, [Define if --enable-pcap])
fi

AC_ARG_ENABLE(thread, AS_HELP_STRING([--enable-thread],[run tcpcopy server(i.e. intercept) at multi-threading mode(valid only when using ip queue)]),,thread=no)
if test "x$enable_thread" = "xyes";then
    AC_DEFINE(INTERCEPT_THREAD, 1, [Define if --enable-thread])
fi

AC_ARG_ENABLE(dr, AS_HELP_STRING([--enable-dr],[run tcpcopy at direct routing  mode(such as lvs)]),,dr=no)
if test "x$enable_dr" = "xyes";then
    AC_DEFINE(TCPCOPY_DR, 1, [Define if --enable-dr])
fi

AC_ARG_ENABLE(single, AS_HELP_STRING([--enable-single],[run tcpcopy at non-distributed mode]),,single=no)
if test "x$enable_single" = "xyes";then
    AC_DEFINE(TCPCOPY_SINGLE, 1, [Define if --enable-single])
fi

AC_ARG_ENABLE(paper, AS_HELP_STRING([--enable-paper],[run tcpcopy at paper mode(only valid for high latency web applications)]),,paper=no)
if test "x$enable_paper" = "xyes";then
    AC_DEFINE(TCPCOPY_PAPER, 1, [Define if --enable-paper])
fi

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netinet/in.h stdint.h stdlib.h string.h sys/file.h sys/param.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_C_VOLATILE
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([atexit gettimeofday inet_ntoa memset select socket localtime_r])

if test "x$enable_offline" = "xyes";then
    LIBS="-lpcap"
fi

if test "x$enable_pcap" = "xyes";then
    LIBS="-lpcap"
fi


if test "x$enable_thread" = "xyes";then
    LIBS="$LIBS -lpthread "
fi

if test "x$enable_nfqueue" = "xyes";then
    LIBS="$LIBS -lnfnetlink -lnetfilter_queue "
fi

CFLAGS="-g -Wall -Wunused-function -pedantic -I../communication -I../core -I../event -I../interception -I../mysql -I../tcpcopy -I../util"

#AC_CONFIG_FILES([Makefile])
AC_OUTPUT([
Makefile
src/Makefile
src/core/Makefile
src/util/Makefile
src/mysql/Makefile
src/interception/Makefile
src/communication/Makefile
src/tcpcopy/Makefile
src/event/Makefile
])

