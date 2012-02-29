/* Copyright (C) 2009 Sun Microsystems, Inc
 
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; version 2 of the License.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA */

#ifndef MY_CONFIG_H
#define MY_CONFIG_H
#define DOT_FRM_VERSION 6
/* Headers we may want to use. */
#define STDC_HEADERS 1
/* #undef _GNU_SOURCE */
/* #undef HAVE_ALLOCA_H */
/* #undef HAVE_AIO_H */
/* #undef HAVE_ARPA_INET_H */
/* #undef HAVE_ASM_MSR_H */
/* #undef HAVE_ASM_TERMBITS_H */
#define HAVE_BSEARCH 1
/* #undef HAVE_CRYPT_H */
/* #undef HAVE_CURSES_H */
/* #undef HAVE_CXXABI_H */
/* #undef HAVE_NCURSES_H */
/* #undef HAVE_NDIR_H */
/* #undef HAVE_DIRENT_H */
/* #undef HAVE_DLFCN_H */
/* #undef HAVE_EXECINFO_H */
#define HAVE_FCNTL_H 1
/* #undef HAVE_FENV_H */
#define HAVE_FLOAT_H 1
/* #undef HAVE_FLOATINGPOINT_H */
/* #undef HAVE_FNMATCH_H */
/* #undef HAVE_FPU_CONTROL_H */
/* #undef HAVE_GRP_H */
/* #undef HAVE_EXPLICIT_TEMPLATE_INSTANTIATION */
/* #undef HAVE_IA64INTRIN_H */
/* #undef HAVE_IEEEFP_H */
/* #undef HAVE_INTTYPES_H */
#define HAVE_LIMITS_H 1
#define HAVE_LOCALE_H 1
#define HAVE_MALLOC_H 1
#define HAVE_MEMORY_H 1
/* #undef HAVE_NETINET_IN_H */
/* #undef HAVE_PATHS_H */
/* #undef HAVE_POLL_H */
/* #undef HAVE_PORT_H */
/* #undef HAVE_PWD_H */
/* #undef HAVE_SCHED_H */
/* #undef HAVE_SELECT_H */
/* #undef HAVE_SOLARIS_LARGE_PAGES */
#define HAVE_STDDEF_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STDARG_H 1
/* #undef HAVE_STRINGS_H */
#define HAVE_STRING_H 1
/* #undef HAVE_STDINT_H */
/* #undef HAVE_SEMAPHORE_H */
/* #undef HAVE_SYNCH_H */
/* #undef HAVE_SYSENT_H */
/* #undef HAVE_SYS_DIR_H */
/* #undef HAVE_SYS_CDEFS_H */
/* #undef HAVE_SYS_FILE_H */
/* #undef HAVE_SYS_FPU_H */
/* #undef HAVE_SYS_IOCTL_H */
/* #undef HAVE_SYS_IPC_H */
/* #undef HAVE_SYS_MALLOC_H */
/* #undef HAVE_SYS_MMAN_H */
/* #undef HAVE_SYS_NDIR_H */
/* #undef HAVE_SYS_PTE_H */
/* #undef HAVE_SYS_PTEM_H */
/* #undef HAVE_SYS_PRCTL_H */
/* #undef HAVE_SYS_RESOURCE_H */
/* #undef HAVE_SYS_SELECT_H */
/* #undef HAVE_SYS_SHM_H */
/* #undef HAVE_SYS_SOCKET_H */
#define HAVE_SYS_STAT_H 1
/* #undef HAVE_SYS_STREAM_H */
/* #undef HAVE_SYS_TERMCAP_H */
#define HAVE_SYS_TIMEB_H 1
/* #undef HAVE_SYS_TIMES_H */
/* #undef HAVE_SYS_TIME_H */
#define HAVE_SYS_TYPES_H 1
/* #undef HAVE_SYS_UN_H */
/* #undef HAVE_SYS_VADVISE_H */
/* #undef HAVE_TERM_H */
/* #undef HAVE_TERMBITS_H */
/* #undef HAVE_TERMIOS_H */
/* #undef HAVE_TERMIO_H */
/* #undef HAVE_TERMCAP_H */
#define HAVE_TIME_H 1
/* #undef HAVE_UNISTD_H */
/* #undef HAVE_UTIME_H */
#define HAVE_VARARGS_H 1
/* #undef HAVE_VIS_H */
#define HAVE_SYS_UTIME_H 1
/* #undef HAVE_SYS_WAIT_H */
/* #undef HAVE_SYS_PARAM_H */

/* Libraries */
/* #undef HAVE_LIBPTHREAD */
/* #undef HAVE_LIBM */
/* #undef HAVE_LIBDL */
/* #undef HAVE_LIBRT */
/* #undef HAVE_LIBSOCKET */
/* #undef HAVE_LIBNSL */
/* #undef HAVE_LIBCRYPT */
/* #undef HAVE_LIBMTMALLOC */
/* #undef HAVE_LIBWRAP */
/* Does "struct timespec" have a "sec" and "nsec" field? */
/* #undef HAVE_TIMESPEC_TS_SEC */

/* Readline */
/* #undef HAVE_HIST_ENTRY */
/* #undef USE_LIBEDIT_INTERFACE */
/* #undef USE_NEW_READLINE_INTERFACE */

/* #undef FIONREAD_IN_SYS_IOCTL */
/* #undef GWINSZ_IN_SYS_IOCTL */
/* #undef TIOCSTAT_IN_SYS_IOCTL */

/* Functions we may want to use. */
/* #undef HAVE_AIOWAIT */
/* #undef HAVE_ALARM */
#define HAVE_ALLOCA 1
/* #undef HAVE_BFILL */
/* #undef HAVE_BMOVE */
/* #undef HAVE_BZERO */
/* #undef HAVE_INDEX */
/* #undef HAVE_CHOWN */
/* #undef HAVE_CLOCK_GETTIME */
/* #undef HAVE_CRYPT */
/* #undef HAVE_CUSERID */
#define HAVE_CXX_NEW 1
/* #undef HAVE_DIRECTIO */
/* #undef HAVE_DLERROR */
/* #undef HAVE_DLOPEN */
/* #undef HAVE_DOPRNT */
/* #undef HAVE_FCHMOD */
/* #undef HAVE_FCNTL */
/* #undef HAVE_FCONVERT */
/* #undef HAVE_FDATASYNC */
/* #undef HAVE_FESETROUND */
#define HAVE_FINITE 1
/* #undef HAVE_FP_EXCEPT */
/* #undef HAVE_FPSETMASK */
/* #undef HAVE_FSEEKO */
/* #undef HAVE_FSYNC */
#define HAVE_FTIME 1
#define HAVE_GETADDRINFO 1
#define HAVE_GETCWD 1
/* #undef HAVE_GETHOSTBYADDR_R */
/* #undef HAVE_GETHOSTBYNAME_R */
/* #undef HAVE_GETHRTIME */
/* #undef HAVE_GETLINE */
/* #undef HAVE_GETNAMEINFO */
/* #undef HAVE_GETPAGESIZE */
/* #undef HAVE_GETPASS */
/* #undef HAVE_GETPASSPHRASE */
/* #undef HAVE_GETPWNAM */
/* #undef HAVE_GETPWUID */
/* #undef HAVE_GETRLIMIT */
/* #undef HAVE_GETRUSAGE */
/* #undef HAVE_GETTIMEOFDAY */
/* #undef HAVE_GETWD */
/* #undef HAVE_GMTIME_R */
/* #undef gmtime_r */
/* #undef HAVE_INITGROUPS */
/* #undef HAVE_ISSETUGID */
#define HAVE_ISNAN 1
/* #undef HAVE_ISINF */
/* #undef HAVE_LARGE_PAGE_OPTION */
#define HAVE_LDIV 1
/* #undef HAVE_LRAND48 */
/* #undef HAVE_LOCALTIME_R */
/* #undef HAVE_LOG2 */
#define HAVE_LONGJMP 1
/* #undef HAVE_LSTAT */
/* #undef HAVE_MEMALIGN */
/* #undef HAVE_MLOCK */
/* #undef HAVE_NPTL */
/* #undef HAVE_NL_LANGINFO */
/* #undef HAVE_MADVISE */
/* #undef HAVE_DECL_MADVISE */
/* #undef HAVE_DECL_TGOTO */
/* #undef HAVE_DECL_MHA_MAPSIZE_VA */
/* #undef HAVE_MALLINFO */
#define HAVE_MEMCPY 1
#define HAVE_MEMMOVE 1
/* #undef HAVE_MKSTEMP */
/* #undef HAVE_MLOCKALL */
/* #undef HAVE_MMAP */
/* #undef HAVE_MMAP64 */
#define HAVE_PERROR 1
/* #undef HAVE_POLL */
/* #undef HAVE_PORT_CREATE */
/* #undef HAVE_POSIX_FALLOCATE */
/* #undef HAVE_PREAD */
/* #undef HAVE_PAUSE_INSTRUCTION */
/* #undef HAVE_FAKE_PAUSE_INSTRUCTION */
/* #undef HAVE_RDTSCLL */
/* #undef HAVE_READ_REAL_TIME */
/* #undef HAVE_PTHREAD_ATTR_CREATE */
/* #undef HAVE_PTHREAD_ATTR_GETSTACKSIZE */
/* #undef HAVE_PTHREAD_ATTR_SETPRIO */
/* #undef HAVE_PTHREAD_ATTR_SETSCHEDPARAM */
/* #undef HAVE_PTHREAD_ATTR_SETSCOPE */
/* #undef HAVE_PTHREAD_ATTR_SETSTACKSIZE */
/* #undef HAVE_PTHREAD_CONDATTR_CREATE */
/* #undef HAVE_PTHREAD_CONDATTR_SETCLOCK */
/* #undef HAVE_PTHREAD_INIT */
/* #undef HAVE_PTHREAD_KEY_DELETE */
/* #undef HAVE_PTHREAD_KEY_DELETE */
/* #undef HAVE_PTHREAD_KILL */
/* #undef HAVE_PTHREAD_RWLOCK_RDLOCK */
/* #undef HAVE_PTHREAD_SETPRIO_NP */
/* #undef HAVE_PTHREAD_SETSCHEDPARAM */
/* #undef HAVE_PTHREAD_SIGMASK */
/* #undef HAVE_PTHREAD_THREADMASK */
/* #undef HAVE_PTHREAD_YIELD_NP */
/* #undef HAVE_PTHREAD_YIELD_ZERO_ARG */
#define HAVE_PUTENV 1
/* #undef HAVE_RE_COMP */
/* #undef HAVE_REGCOMP */
/* #undef HAVE_READDIR_R */
/* #undef HAVE_READLINK */
/* #undef HAVE_REALPATH */
#define HAVE_RENAME 1
/* #undef HAVE_RINT */
/* #undef HAVE_RWLOCK_INIT */
/* #undef HAVE_SCHED_YIELD */
#define HAVE_SELECT 1
/* #undef HAVE_SETFD */
/* #undef HAVE_SETENV */
#define HAVE_SETLOCALE 1
/* #undef HAVE_SIGADDSET */
/* #undef HAVE_SIGEMPTYSET */
/* #undef HAVE_SIGHOLD */
/* #undef HAVE_SIGSET */
/* #undef HAVE_SIGSET_T */
/* #undef HAVE_SIGACTION */
/* #undef HAVE_SIGTHREADMASK */
/* #undef HAVE_SIGWAIT */
/* #undef HAVE_SLEEP */
#define HAVE_SNPRINTF 1
/* #undef HAVE_STPCPY */
#define HAVE_STRERROR 1
#define HAVE_STRCOLL 1
/* #undef HAVE_STRSIGNAL */
/* #undef HAVE_STRLCPY */
/* #undef HAVE_STRLCAT */
/* #undef HAVE_FGETLN */
#define HAVE_STRNLEN 1
#define HAVE_STRPBRK 1
/* #undef HAVE_STRSEP */
#define HAVE_STRSTR 1
#define HAVE_STRTOK_R 1
#define HAVE_STRTOL 1
#define HAVE_STRTOLL 1
#define HAVE_STRTOUL 1
#define HAVE_STRTOULL 1
/* #undef HAVE_SHMAT */
/* #undef HAVE_SHMCTL */
/* #undef HAVE_SHMDT */
/* #undef HAVE_SHMGET */
#define HAVE_TELL 1
#define HAVE_TEMPNAM 1
/* #undef HAVE_THR_SETCONCURRENCY */
/* #undef HAVE_THR_YIELD */
#define HAVE_TIME 1
/* #undef HAVE_TIMES */
/* #undef HAVE_VALLOC */
#define HAVE_VIO_READ_BUFF 1
/* #undef HAVE_VASPRINTF */
#define HAVE_VPRINTF 1
#define HAVE_VSNPRINTF 1
/* #undef HAVE_FTRUNCATE */
#define HAVE_TZNAME 1
/* #undef HAVE_AIO_READ */
/* Symbols we may use */
/* #undef HAVE_SYS_ERRLIST */
/* used by stacktrace functions */
/* #undef HAVE_BSS_START */
/* #undef HAVE_BACKTRACE */
/* #undef HAVE_BACKTRACE_SYMBOLS */
/* #undef HAVE_BACKTRACE_SYMBOLS_FD */
/* #undef HAVE_PRINTSTACK */
/* #undef HAVE_STRUCT_SOCKADDR_IN6 */
/* #undef HAVE_STRUCT_IN6_ADDR */
/* #undef HAVE_NETINET_IN6_H */
#define HAVE_IPV6 1
/* #undef ss_family */
/* #undef HAVE_SOCKADDR_IN_SIN_LEN */
/* #undef HAVE_SOCKADDR_IN6_SIN6_LEN */
/* #undef HAVE_TIMESPEC_TS_SEC */
/* #undef STRUCT_DIRENT_HAS_D_INO */
/* #undef STRUCT_DIRENT_HAS_D_NAMLEN */
#define SPRINTF_RETURNS_INT 1

#define USE_MB 1
#define USE_MB_IDENT 1

/* #undef HAVE_VALGRIND */

/* Types we may use */
#ifdef __APPLE__
  /*
    Special handling required for OSX to support universal binaries that 
    mix 32 and 64 bit architectures.
  */
  #if(__LP64__)
    #define SIZEOF_LONG 8
  #else
    #define SIZEOF_LONG 4
  #endif
  #define SIZEOF_VOIDP   SIZEOF_LONG
  #define SIZEOF_CHARP   SIZEOF_LONG
  #define SIZEOF_SIZE_T  SIZEOF_LONG
#else
/* No indentation, to fetch the lines from verification scripts */
#define SIZEOF_LONG   4
#define SIZEOF_VOIDP  4
#define SIZEOF_CHARP  4
#define SIZEOF_SIZE_T 4
#endif

#define SIZEOF_CHAR 1
#define HAVE_CHAR 1
#define HAVE_LONG 1
#define HAVE_CHARP 1
#define SIZEOF_SHORT 2
#define HAVE_SHORT 1
#define SIZEOF_INT 4
#define HAVE_INT 1
#define SIZEOF_LONG_LONG 8
#define HAVE_LONG_LONG 1
#define SIZEOF_OFF_T 4
#define HAVE_OFF_T 1
/* #undef SIZEOF_SIGSET_T */
/* #undef HAVE_SIGSET_T */
#define HAVE_SIZE_T 1
/* #undef SIZEOF_UCHAR */
/* #undef HAVE_UCHAR */
/* #undef SIZEOF_UINT */
/* #undef HAVE_UINT */
/* #undef SIZEOF_ULONG */
/* #undef HAVE_ULONG */
/* #undef SIZEOF_INT8 */
/* #undef HAVE_INT8 */
/* #undef SIZEOF_UINT8 */
/* #undef HAVE_UINT8 */
/* #undef SIZEOF_INT16 */
/* #undef HAVE_INT16 */
/* #undef SIZEOF_UINT16 */
/* #undef HAVE_UINT16 */
/* #undef SIZEOF_INT32 */
/* #undef HAVE_INT32 */
/* #undef SIZEOF_UINT32 */
/* #undef HAVE_UINT32 */
/* #undef SIZEOF_U_INT32_T */
/* #undef HAVE_U_INT32_T */
/* #undef SIZEOF_INT64 */
/* #undef HAVE_INT64 */
/* #undef SIZEOF_UINT64 */
/* #undef HAVE_UINT64 */
/* #undef SIZEOF_BOOL */
/* #undef HAVE_BOOL */

#define SOCKET_SIZE_TYPE int

/* #undef HAVE_MBSTATE_T */

#define MAX_INDEXES 64

#define QSORT_TYPE_IS_VOID 1
#define RETQSORTTYPE void

#define SIGNAL_RETURN_TYPE_IS_VOID 1
#define RETSIGTYPE void
#define VOID_SIGHANDLER 1
#define STRUCT_RLIMIT struct rlimit

#ifdef __APPLE__
  #if __BIG_ENDIAN
    #define WORDS_BIGENDIAN 1
  #endif
#else
/* #undef WORDS_BIGENDIAN */
#endif

/* Define to `__inline__' or `__inline' if that's what the C compiler calls
   it, or to nothing if 'inline' is not supported under any name.  */
/* #undef C_HAS_inline */
#if !(C_HAS_inline)
#ifndef __cplusplus
# define inline __inline
#endif
#endif


/* #undef TARGET_OS_LINUX */
/* #undef TARGET_OS_SOLARIS */

#define HAVE_WCTYPE_H 1
#define HAVE_WCHAR_H 1
/* #undef HAVE_LANGINFO_H */
/* #undef HAVE_MBRLEN */
/* #undef HAVE_MBSCMP */
/* #undef HAVE_MBSRTOWCS */
/* #undef HAVE_WCRTOMB */
/* #undef HAVE_MBRTOWC */
/* #undef HAVE_WCSCOLL */
/* #undef HAVE_WCSDUP */
/* #undef HAVE_WCWIDTH */
/* #undef HAVE_WCTYPE */
/* #undef HAVE_ISWLOWER */
/* #undef HAVE_ISWUPPER */
/* #undef HAVE_TOWLOWER */
/* #undef HAVE_TOWUPPER */
/* #undef HAVE_ISWCTYPE */
/* #undef HAVE_WCHAR_T */
/* #undef HAVE_WCTYPE_T */
/* #undef HAVE_WINT_T */


#define HAVE_STRCASECMP 1
#define HAVE_STRNCASECMP 1
#define HAVE_STRDUP 1
/* #undef HAVE_LANGINFO_CODESET */
/* #undef HAVE_TCGETATTR */
/* #undef HAVE_FLOCKFILE */

/* #undef HAVE_WEAK_SYMBOL */
/* #undef HAVE_ABI_CXA_DEMANGLE */


/* #undef HAVE_POSIX_SIGNALS */
/* #undef HAVE_BSD_SIGNALS */
/* #undef HAVE_SVR3_SIGNALS */
#define HAVE_V7_SIGNALS 1


/* #undef HAVE_SOLARIS_STYLE_GETHOST */
/* #undef HAVE_GETHOSTBYNAME_R_GLIBC2_STYLE */
/* #undef HAVE_GETHOSTBYNAME_R_RETURN_INT */

/* #undef MY_ATOMIC_MODE_DUMMY */
/* #undef MY_ATOMIC_MODE_RWLOCKS */
/* #undef HAVE_GCC_ATOMIC_BUILTINS */
/* #undef HAVE_SOLARIS_ATOMIC */
/* #undef HAVE_DECL_SHM_HUGETLB */
/* #undef HAVE_LARGE_PAGES */
/* #undef HUGETLB_USE_PROC_MEMINFO */
#define NO_FCNTL_NONBLOCK 1
#define NO_ALARM 1

/* #undef _LARGE_FILES */
#define _LARGEFILE_SOURCE 1
/* #undef _LARGEFILE64_SOURCE */
/* #undef _FILE_OFFSET_BITS */

/* #undef TIME_WITH_SYS_TIME */

#define STACK_DIRECTION -1

#define THREAD 1
#define THREAD_SAFE_CLIENT 1

#define SYSTEM_TYPE "Win32"
#define MACHINE_TYPE "x86"
/* #undef HAVE_DTRACE */

#define SIGNAL_WITH_VIO_CLOSE 1

/* Windows stuff, mostly functions, that have Posix analogs but named differently */
#define S_IROTH _S_IREAD
#define S_IFIFO _S_IFIFO
/* #undef IPPROTO_IPV6 */
/* #undef IPV6_V6ONLY */
#define sigset_t int
#define mode_t int
#define SIGQUIT SIGTERM
#define SIGPIPE SIGINT
#define isnan _isnan
#define finite _finite
#define popen _popen
#define pclose _pclose
#define ssize_t SSIZE_T
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#define snprintf _snprintf
#define strtoll _strtoi64
#define strtoull _strtoui64
/* #undef vsnprintf */
#if (_MSC_VER > 1310)
# define HAVE_SETENV
#define setenv(a,b,c) _putenv_s(a,b)
#endif




/*
  MySQL features
*/
#define ENABLED_LOCAL_INFILE 1
#define ENABLED_PROFILING 1
/* #undef EXTRA_DEBUG */
/* #undef BACKUP_TEST */
/* #undef CYBOZU */

/* Character sets and collations */
#define MYSQL_DEFAULT_CHARSET_NAME "latin1"
#define MYSQL_DEFAULT_COLLATION_NAME "latin1_swedish_ci"

#define USE_MB 1
#define USE_MB_IDENT 1
/* #undef USE_STRCOLL */

/* This should mean case insensitive file system */
#define FN_NO_CASE_SENSE 1

#define HAVE_CHARSET_armscii8 1
#define HAVE_CHARSET_ascii 1
#define HAVE_CHARSET_big5 1
#define HAVE_CHARSET_cp1250 1
#define HAVE_CHARSET_cp1251 1
#define HAVE_CHARSET_cp1256 1
#define HAVE_CHARSET_cp1257 1
#define HAVE_CHARSET_cp850 1
#define HAVE_CHARSET_cp852 1 
#define HAVE_CHARSET_cp866 1
#define HAVE_CHARSET_cp932 1
#define HAVE_CHARSET_dec8 1
#define HAVE_CHARSET_eucjpms 1
#define HAVE_CHARSET_euckr 1
#define HAVE_CHARSET_gb2312 1
#define HAVE_CHARSET_gbk 1
#define HAVE_CHARSET_geostd8 1
#define HAVE_CHARSET_greek 1
#define HAVE_CHARSET_hebrew 1
#define HAVE_CHARSET_hp8 1
#define HAVE_CHARSET_keybcs2 1
#define HAVE_CHARSET_koi8r 1
#define HAVE_CHARSET_koi8u 1
#define HAVE_CHARSET_latin1 1
#define HAVE_CHARSET_latin2 1
#define HAVE_CHARSET_latin5 1
#define HAVE_CHARSET_latin7 1
#define HAVE_CHARSET_macce 1
#define HAVE_CHARSET_macroman 1
#define HAVE_CHARSET_sjis 1
#define HAVE_CHARSET_swe7 1
#define HAVE_CHARSET_tis620 1
#define HAVE_CHARSET_ucs2 1
#define HAVE_CHARSET_ujis 1
#define HAVE_CHARSET_utf8mb4 1
/* #undef HAVE_CHARSET_utf8mb3 */
#define HAVE_CHARSET_utf8 1
#define HAVE_CHARSET_utf16 1
#define HAVE_CHARSET_utf32 1
#define HAVE_UCA_COLLATIONS 1
#define HAVE_COMPRESS 1


/*
  Stuff that always need to be defined (compile breaks without it)
*/
#define HAVE_SPATIAL 1
#define HAVE_RTREE_KEYS 1
#define HAVE_QUERY_CACHE 1
#define BIG_TABLES 1

/*
  Important storage engines (those that really need define 
  WITH_<ENGINE>_STORAGE_ENGINE for the whole server)
*/
#define WITH_MYISAM_STORAGE_ENGINE 1
#define WITH_MYISAMMRG_STORAGE_ENGINE 1
#define WITH_HEAP_STORAGE_ENGINE 1
#define WITH_CSV_STORAGE_ENGINE 1
#define WITH_PARTITION_STORAGE_ENGINE 1
#define WITH_PERFSCHEMA_STORAGE_ENGINE 1
/* #undef WITH_NDBCLUSTER_STORAGE_ENGINE */
#if (WITH_NDBCLUSTER_STORAGE_ENGINE) && !defined(EMBEDDED_LIBRARY)
# define HAVE_NDB_BINLOG 1
#endif

#define DEFAULT_MYSQL_HOME "C:/Program Files/MySQL/MySQL Server 5.5"
#define SHAREDIR "share"
#define DEFAULT_BASEDIR "C:/Program Files/MySQL/MySQL Server 5.5"
#define MYSQL_DATADIR "C:/Program Files/MySQL/MySQL Server 5.5/data"
#define DEFAULT_CHARSET_HOME "C:/Program Files/MySQL/MySQL Server 5.5"
#define PLUGINDIR "C:/Program Files/MySQL/MySQL Server 5.5/lib/plugin"
/* #undef DEFAULT_SYSCONFDIR */

/* #undef SO_EXT */

#define PACKAGE "mysql"
#define PACKAGE_BUGREPORT ""
#define PACKAGE_NAME "MySQL Server"
#define PACKAGE_STRING "MySQL Server 5.5.8"
#define PACKAGE_TARNAME "mysql"
#define PACKAGE_VERSION "5.5.8"
#define PROTOCOL_VERSION 10


#endif
