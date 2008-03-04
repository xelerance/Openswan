#define TimeZoneOffset timezone
#define u8 unsigned char

#include <limits.h>
/* POSIX 1003.1-2001 says <unistd.h> defines this */
#define HOST_NAME_MAX _POSIX_HOST_NAME_MAX

#ifndef s6_addr16
# define s6_addr16 __u6_addr.__u6_addr16
#endif

#ifndef s6_addr32
# define s6_addr32 __u6_addr.__u6_addr32
#endif

