#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([TCPCopy], [0.9.10], [wangbin579@gmail.com], [tcpcopy])
AC_CONFIG_SRCDIR([src/interception/main.c])
AC_CONFIG_HEADER([src/core/config.h])
AM_INIT_AUTOMAKE


# Checks for programs.
AC_PROG_LN_S
AC_PROG_MAKE_SET

# Checks for libraries.

AC_PROG_LIBTOOL
AM_PROG_LIBTOOL

case "$host" in
*-*-linux*) ;;
*) AC_MSG_ERROR([Linux only!]);;
esac

AC_ARG_ENABLE(debug, AS_HELP_STRING([--enable-debug],[compile tcpcopy with debug support(saved in a log file)]),,debug=no)
if test "x$enable_debug" = "xyes";then
	AC_DEFINE(TCPCOPY_DEBUG, 1, [Define if --enable-debug])
fi

AC_ARG_ENABLE(mysqlsgt, AS_HELP_STRING([--enable-mysqlsgt],[run tcpcopy at mysql skip-grant-tables mode]),,mysqlsgt=no)
if test "x$enable_mysqlsgt" = "xyes";then
	AC_DEFINE(TCPCOPY_MYSQL_SKIP, 1, [Define if --enable-mysqlsgt])
fi

AC_ARG_ENABLE(mysql, AS_HELP_STRING([--enable-mysql],[run tcpcopy at mysql mode]),,mysql=no)
if test "x$enable_mysql" = "xyes";then
    AC_CHECK_HEADERS([openssl/evp.h], [], 
                     [AC_MSG_ERROR([openssl/evp.h not found.])], [])
	AC_DEFINE(TCPCOPY_MYSQL_NO_SKIP, 1, [Define if --enable-mysql])
fi

AC_ARG_ENABLE(offline, AS_HELP_STRING([--enable-offline],[run tcpcopy at offline mode]),,offline=no)
if test "x$enable_offline" = "xyes";then
	AC_DEFINE(TCPCOPY_OFFLINE, 1, [Define if --enable-offline])
	AC_CHECK_HEADERS([pcap.h], [], 
                     [AC_MSG_ERROR([pcap.h not found.])], [])

fi

AC_ARG_ENABLE(pcap, AS_HELP_STRING([--enable-pcap],[ run the tcpcopy at pcap mode]),,pcap=no)
if test "x$enable_pcap" = "xyes";then
    AC_CHECK_HEADERS([pcap.h], [], 
                     [AC_MSG_ERROR([pcap.h not found.])], [])
    AC_DEFINE(TCPCOPY_PCAP, 1, [Define if --enable-pcap])
    AC_SEARCH_LIBS([pcap_create], [pcap],
                   AC_DEFINE([HAVE_PCAP_CREATE], [1], [Define to 1 if pcap_create() is available.])
                   )
fi

AC_ARG_ENABLE(millions,AS_HELP_STRING([--enable-millions],[enable to support million connections]),
              [case "${enableval}" in
               yes) millions=true 
               AC_DEFINE(INTERCEPT_MILLION_SUPPORT, 1, [Define if --enable-millions])
               AC_DEFINE(TCPCOPY_MILLION_SUPPORT, 1, [Define if --enable-millions]) ;;
               no)  millions=false ;;
               *)   AC_MSG_ERROR(bad value ${enableval} for --enable-millions) ;;
           esac],[millions=false])


AC_ARG_ENABLE(advanced,AS_HELP_STRING([--enable-advanced],[turn on advanced tcpcopy]),
              [case "${enableval}" in
               yes) advanced=true 
               AC_DEFINE(INTERCEPT_ADVANCED, 1, [Define if --enable-advanced])
               AC_DEFINE(TCPCOPY_ADVANCED, 1, [Define if --enable-advanced]) ;;
               no)  advanced=false ;;
               *)   AC_MSG_ERROR(bad value ${enableval} for --enable-advanced) ;;
           esac],[advanced=false])


if test "x$advanced" = "xfalse";then
    AC_MSG_CHECKING([for the kernel version])
    AC_CHECK_HEADERS([linux/version.h], [], 
                     [AC_MSG_ERROR([linux/version.h not found.])], [])

    major=`uname -r | cut -d. -f1`;
    minor=`uname -r | cut -d. -f2`;

    if test $major -gt 3; then
        enable_nfqueue=yes
        echo "enable nfqueue"
    elif test $major -eq 3; then
        if test $minor -ge 5; then
            enable_nfqueue=yes
            echo "enable nfqueue"
        else
            echo "ip_queue could be supported"
        fi
    else
        echo "ip_queue could be supported"
    fi
else
    echo "no need to check nfqueue or ip_queue"
fi

AC_ARG_ENABLE(nfqueue, AS_HELP_STRING([--enable-nfqueue],[run tcpcopy at nfqueue mode (ip queue will be used by default and this option is only valid if the linux kernel version is less than 3.5, otherwise nfqueue will be used by default and ip queue is no longer supported by the linux kernel)]),,nfqueue=no)

if test "x$enable_nfqueue" = "xyes";then
    AC_DEFINE(INTERCEPT_NFQUEUE, 1, [Define if --enable-nfqueue])

    # nfqueue detection; swiped from Tor, modified a bit
    trynfqueuedir=""
    AC_ARG_WITH([nfqueue],
      [AS_HELP_STRING([--with-nfqueue=@<:@path@:>@], [specify path to nfqueue install])],
      [trynfqueuedir=$withval])
    LIBNFQUEUE_URL="http://www.netfilter.org/projects/libnetfilter_queue/index.html"
    AC_CACHE_CHECK([for nfqueue directory], [ac_cv_nfqueue_dir],
      [
        saved_LIBS="$LIBS"
        saved_LDFLAGS="$LDFLAGS"
        saved_CPPFLAGS="$CPPFLAGS"
        nf_found=no
        for nfdir in $trynfqueuedir "" $prefix /usr/local
        do
          LDFLAGS="$saved_LDFLAGS"
          LIBS="-lnfnetlink -lnetfilter_queue $saved_LIBS"

          # Skip the directory if it isn't there.
          AS_IF([test ! -z "$nfdir" -a ! -d "$nfdir"], [continue])
          AS_IF(
            [test ! -z "$nfdir"],
            [
              AS_IF(
                [test -d "$nfdir/lib"],
                [LDFLAGS="-L$nfdir/lib $LDFLAGS"],
                [LDFLAGS="-L$nfdir $LDFLAGS"]
              )
              AS_IF(
                [test -d "$nfdir/include"],
                [CPPFLAGS="-I$nfdir/include $CPPFLAGS"],
                [CPPFLAGS="-I$nfdir $CPPFLAGS"]
              )
            ]
          )

          # Can I compile and link it?
          AC_TRY_LINK(
            [
              #include <stddef.h>
              #include <netinet/in.h>
              #include <linux/netfilter.h> 
              #include <libnetfilter_queue/libnetfilter_queue.h>
            ],
            [
              struct nfq_handle *h;
              h = nfq_open();
              nfq_close(h);
            ],
            [nfqueue_linked=yes],
            [nfqueue_linked=no]
          )
          AS_IF(
            [test $nfqueue_linked = yes],
            [
              AS_IF(
                [test ! -z "$nfdir"],
                [ac_cv_nfqueue_dir=$nfdir],
                [ac_cv_nfqueue_dir="(system)"]
              )
              nf_found=yes
              break
            ]
          )
        done
        LIBS="$saved_LIBS"
        LDFLAGS="$saved_LDFLAGS"
        CPPFLAGS="$saved_CPPFLAGS"
        AS_IF(
          [test $nf_found = no],
          [AC_MSG_ERROR([nfqueue required. Install libnetfilter_queue(download it from $LIBNFQUEUE_URL) or specify its path using --with-nfqueue=/dir/])]
        )
      ]
    )
    AS_IF(
      [test $ac_cv_nfqueue_dir != "(system)"],
      [
        AS_IF(
          [test -d "$ac_cv_nfqueue_dir/lib"],
          [
            LDFLAGS="-L$ac_cv_nfqueue_dir/lib $LDFLAGS"
            nf_libdir="$ac_cv_nfqueue_dir/lib"
          ],
          [
            LDFLAGS="-L$ac_cv_nfqueue_dir $LDFLAGS"
            nf_libdir="$ac_cv_nfqueue_dir"
          ]
        )
        AS_IF(
          [test -d "$ac_cv_nfqueue_dir/include"],
          [CPPFLAGS="-I$ac_cv_nfqueue_dir/include $CPPFLAGS"]
          [CPPFLAGS="-I$ac_cv_nfqueue_dir $CPPFLAGS"]
        )
      ]
    )

fi

AC_ARG_ENABLE(dr, AS_HELP_STRING([--enable-dr],[run tcpcopy at direct routing mode (such as lvs)]),,dr=no)
if test "x$enable_dr" = "xyes";then
    AC_DEFINE(TCPCOPY_DR, 1, [Define if --enable-dr])
fi

AC_ARG_ENABLE(single, AS_HELP_STRING([--enable-single],[run tcpcopy at non-distributed mode]),,single=no)
if test "x$enable_single" = "xyes";then
    AC_DEFINE(TCPCOPY_SINGLE, 1, [Define if --enable-single])
fi

AC_ARG_ENABLE(dnat, AS_HELP_STRING([--enable-dnat],[run tcpcopy at non-distributed mode]),,dnat=no)
if test "x$enable_dnat" = "xyes";then
    AC_DEFINE(TCPCOPY_DNAT, 1, [Define if --enable-dnat])
fi

AC_ARG_ENABLE(combined, AS_HELP_STRING([--disable-combined],[disable combined response mode]),,combined=yes)
if test "x$enable_combined" != "xno";then
    AC_DEFINE(TCPCOPY_COMBINED, 1, [Define if --enable-combined])
    AC_DEFINE(INTERCEPT_COMBINED, 1, [Define if --enable-combined])
fi

AC_ARG_ENABLE(rlantency, AS_HELP_STRING([--enable-rlantency],[run tcpcopy at reverse lantency mode (only valid for high latency web applications)]),,rlantency=no)
if test "x$enable_rlantency" = "xyes";then
    AC_DEFINE(TCPCOPY_PAPER, 1, [Define if --enable-rlantency])
fi

AC_ARG_ENABLE(dlinject, AS_HELP_STRING([--enable-dlinject],[run tcpcopy at pcap sending mode]),,dlinject=no)
if test "x$enable_dlinject" = "xyes";then
    AC_DEFINE(TCPCOPY_PCAP_SEND, 1, [Define if --enable-dlinject])
    AC_CHECK_HEADERS([pcap.h], [], 
                     [AC_MSG_ERROR([pcap.h not found.])], [])
fi


AC_ARG_ENABLE(udp,AS_HELP_STRING([--enable-udp],[turn on udpcopy]),
               [case "${enableval}" in
                   yes) udp=true 
                        AC_DEFINE(TCPCOPY_UDP, 1, [Define if --enable-udp]) ;;
                   no)  udp=false ;;
                   *)   AC_MSG_ERROR(bad value ${enableval} for --enable-udp) ;;
               esac],[udp=false])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netinet/in.h stdint.h stdlib.h string.h sys/file.h sys/param.h sys/socket.h sys/time.h unistd.h getopt.h])

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

if test "x$enable_dlinject" = "xyes";then
    LIBS="-lpcap"
fi

if test "x$enable_mysql" = "xyes";then
    LIBS="$LIBS -lcrypto"
fi

if test "x$enable_nfqueue" = "xyes";then
    LIBS="$LIBS -lnfnetlink -lnetfilter_queue "
fi

CFLAGS="-g -O2 -std=gnu99 -D_FILE_OFFSET_BITS=64 -Wall -Wunused-function -pedantic -I../communication -I../core -I../event -I../interception -I../digest -I../mysql -I../tcpcopy -I../util"

AM_CONDITIONAL(ADVANCED, [test "x$advanced" = "xtrue"])
AM_CONDITIONAL(UDPCOPY, [test "x$udp" = "xtrue"])

#AC_CONFIG_FILES([Makefile])
AC_OUTPUT([
Makefile
src/Makefile
src/core/Makefile
src/util/Makefile
src/digest/Makefile
src/mysql/Makefile
src/interception/Makefile
src/communication/Makefile
src/tcpcopy/Makefile
src/event/Makefile
])

