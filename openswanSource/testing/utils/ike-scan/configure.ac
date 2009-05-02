dnl $Id: configure.ac,v 1.1.1.1 2005/01/13 18:44:53 mcr Exp $
dnl Process this file with autoconf to produce a configure script.

AC_INIT([ike-scan],[1.7],[ike-scan@nta-monitor.com])
AC_PREREQ(2.59)
AC_REVISION($Revision: 1.1.1.1 $)
AC_CONFIG_SRCDIR([ike-scan.c])
AM_INIT_AUTOMAKE(1.8)	dnl Require Automake 1.8 or later

AM_CONFIG_HEADER([config.h])

dnl Check for programs.
AC_PROG_CC
 if test -n "$GCC"; then
      CFLAGS="$CFLAGS -Wall "
dnl Uncomment the line below for testing with stricter warnings.
dnl      CFLAGS="$CFLAGS -pedantic -Wshadow -Wpointer-arith -Wcast-qual -Wcast-align -Wwrite-strings -Wconversion -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wnested-externs "
 fi
AC_PROG_INSTALL
AC_PROG_LN_S
dnl Check endian-ness. MD5 and SHA1 hash functions need to know this.
AC_C_BIGENDIAN

dnl Check for libraries.
dnl Solaris 8 needs nsl and socket.  Linux and {Free,Open}BSD do not.
dnl We should only include these libraries if they are actually needed.
AC_SEARCH_LIBS([gethostbyname], [nsl])
AC_SEARCH_LIBS([socket], [socket])

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([inttypes.h stdint.h arpa/inet.h netdb.h netinet/in.h netinet/tcp.h sys/socket.h sys/time.h syslog.h unistd.h getopt.h signal.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME

dnl Check for the uint{8,16,32}_t types and, if we don't have them, define
dnl them using types which will work on most systems.
dnl We use these fixed-width types for constructing the IKE packet payloads.
AC_NTA_CHECK_TYPE(uint8_t, unsigned char)
AC_NTA_CHECK_TYPE(uint16_t, unsigned short)
AC_NTA_CHECK_TYPE(uint32_t, unsigned int)

dnl Checks for 64-bit integer types.  These checks are from postgresql.
dnl Check to see if we have a working 64-bit integer type.
dnl This breaks down into two steps:
dnl (1) figure out if the compiler has a 64-bit int type with working
dnl arithmetic, and if so
dnl (2) see whether snprintf() can format the type correctly.

PGAC_TYPE_64BIT_INT([long int])

if test x"$HAVE_LONG_INT_64" = x"yes" ; then
  INT64_TYPE="long int"
  UINT64_TYPE="unsigned long int"
else
  PGAC_TYPE_64BIT_INT([long long int])
    if test x"$HAVE_LONG_LONG_INT_64" = x"yes" ; then
      INT64_TYPE="long long int"
      UINT64_TYPE="unsigned long long int"
    else
      AC_MSG_ERROR([cannot determine 64-bit integer type])
    fi
fi

AC_DEFINE_UNQUOTED(IKE_INT64, $INT64_TYPE,
                   [Define to the appropriate type for 64-bit ints.])
AC_DEFINE_UNQUOTED(IKE_UINT64, $UINT64_TYPE,
                   [Define to the appropriate type for unsigned 64-bit ints.])

dnl If we found "long int" is 64 bits, assume snprintf handles it.  If
dnl we found we need to use "long long int", better check.  We cope with
dnl snprintfs that use %lld, %qd, or %I64d as the format.
dnl
if test "$HAVE_LONG_LONG_INT_64" = yes ; then
  PGAC_FUNC_SNPRINTF_LONG_LONG_INT_FORMAT
  if test "$LONG_LONG_INT_FORMAT" = ""; then
    AC_MSG_ERROR([cannot determine snprintf format string for long long int])
  fi
  LONG_LONG_UINT_FORMAT=`echo "$LONG_LONG_INT_FORMAT" | sed 's/d$/u/'`
  INT64_FORMAT="\"$LONG_LONG_INT_FORMAT\""
  UINT64_FORMAT="\"$LONG_LONG_UINT_FORMAT\""
else
  # Here if we are not using 'long long int' at all
  INT64_FORMAT='"%ld"'
  UINT64_FORMAT='"%lu"'
fi

AC_DEFINE_UNQUOTED(IKE_INT64_FORMAT, $INT64_FORMAT,
                   [Define to the appropriate snprintf format for 64-bit ints.])

AC_DEFINE_UNQUOTED(IKE_UINT64_FORMAT, $UINT64_FORMAT,
                   [Define to the appropriate snprintf format for unsigned 64-bit ints.])

dnl Checks for library functions.
AC_CHECK_FUNCS([malloc gethostbyname gettimeofday inet_ntoa memset select socket strerror])

dnl Determine type for 3rd arg to accept()
dnl This is normally socklen_t, but can sometimes be size_t or int.
AC_NTA_NET_SIZE_T

dnl Check if the Posix regular expression functions "regcomp" and "regexec"
dnl and the header file "regex.h" are present.
AC_MSG_CHECKING([for posix regular expression support])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <regex.h>]],
[[regcomp(0, 0, 0);
regexec(0, 0, 0, 0, 0)]])],
[ac_nta_posix_regex=yes],
[ac_nta_posic_regex=no])
AC_MSG_RESULT([$ac_nta_posix_regex])
if test $ac_nta_posix_regex = no; then
   AC_MSG_WARN([You don't seem to have posix regular expression support])
else
   AC_DEFINE(HAVE_REGEX_H, 1, [Define to 1 if you have posix regex support])
fi

dnl GNU systems e.g. Linux have getopt_long_only, but many other systems
dnl e.g. FreeBSD 4.3 and Solaris 8 do not.  For systems that don't have it,
dnl use the GNU getopt sources (obtained from glibc).
AC_CHECK_FUNC([getopt_long_only], ,
  [ AC_LIBOBJ(getopt)
    AC_LIBOBJ(getopt1)
    AC_LIBSOURCE(getopt.h) ])

dnl Do we have inet_aton?  Most systems do, but some e.g. Solaris don't
dnl If we don't have it, then use Russ Allbery's implementation as a
dnl replacement function.
AC_CHECK_FUNC(inet_aton, , [ AC_LIBOBJ(inet_aton) ])

dnl The big OpenSSL hunt.
dnl Check for OpenSSL headers and libraries if the --with-openssl[=PATH]
dnl option was specified.
dnl We search for "include/openssl/ssl.h" and "openssl/ssl.h" in the
dnl given path (if specified) plus a number of standard locations.
dnl When we find it, we use the directory we found it in to add the
dnl required -I option to CPPFLAGS (so we can find the include files),
dnl the -L option to LDFLAGS (so we can find the libraries), and add
dnl "-lcrypto" to LIBS (so we link against the OpenSSL libraries).
have_openssl="no"
AC_MSG_CHECKING([if OpenSSL libraries are required])
AC_ARG_WITH(openssl,
   AC_HELP_STRING([--with-openssl],
                  [Use the OpenSSL MD5 and SHA1 hash functions]),
   [
      if test "x$withval" != "xno" ; then
         AC_MSG_RESULT(yes)
         for ssldir in $withval /usr/local/ssl /usr/lib/ssl /usr/ssl /usr/pkg /usr/local /usr; do
            if test -f "${ssldir}/include/openssl/ssl.h"; then
               found_openssl="yes"
               CPPFLAGS="-I${ssldir}/include ${CPPFLAGS}"
               break
            fi
            if test -f "${ssldir}/openssl/ssl.h"; then
               found_openssl="yes"
               CPPFLAGS="-I${ssldir} ${CPPFLAGS}"
               break
            fi
         done
         if test x$found_openssl != xyes; then
            AC_MSG_ERROR([Cannot find OpenSSL libraries])
         else
            AC_MSG_NOTICE([OpenSSL libraries found in $ssldir])
         fi
         LDFLAGS="-L${ssldir}/lib ${LDFLAGS}"
         LIBS="-lcrypto $LIBS"

         AC_MSG_CHECKING([that OpenSSL libraries in ${ssldir} work])
         AC_LINK_IFELSE([AC_LANG_PROGRAM(
[[
#include <openssl/md5.h>
#include <openssl/sha.h>
]],
[[
MD5(0, 0, 0);
SHA1(0, 0, 0);
]] ) ],
[
AC_MSG_RESULT(yes)
AC_DEFINE(HAVE_OPENSSL, 1, [Define to 1 if you have the OpenSSL libraries and header files])
have_openssl="yes"
],
[
AC_MSG_RESULT(no)
AC_MSG_ERROR([OpenSSL libraries in ${ssldir} do not appear to work])
] )

      else
         AC_MSG_RESULT(no)
      fi
   ],
   [
      AC_MSG_RESULT(no)
   ]
)

dnl If we're not using OpenSSL, then use the replacement functions instead.
if test "x$have_openssl" = "xyes"; then
   AC_MSG_NOTICE([Using OpenSSL MD5 and SHA1 hash functions.])
else
   AC_MSG_NOTICE([Using ike-scan built in MD5 and SHA1 hash functions.])
   AC_MSG_NOTICE([])
   AC_MSG_NOTICE([If you plan to perform aggressive mode pre-shared key cracking, then])
   AC_MSG_NOTICE([you probably want to use the OpenSSL hash functions instead because])
   AC_MSG_NOTICE([they are generally faster than the built-in hash functions.])
   AC_MSG_NOTICE([])
   AC_MSG_NOTICE([You will need to have the OpenSSL libraries and headers installed])
   AC_MSG_NOTICE([to configure ike-scan with the OpenSSL hash functions.])
   AC_MSG_NOTICE([])
   AC_MSG_NOTICE([To use the OpenSSL hash functions, specify the following option])
   AC_MSG_NOTICE([to configure:])
   AC_MSG_NOTICE([   --with-openssl])
   AC_MSG_NOTICE([If the OpenSSL libraries are in a non-standard location, you can])
   AC_MSG_NOTICE([specify the base directory as an argument to --with-openssl.])
   AC_MSG_NOTICE([])
   AC_LIBOBJ(md5)
   AC_LIBSOURCE(md5.h)
   AC_LIBOBJ(sha1)
   AC_LIBSOURCE(sha1.h)
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
