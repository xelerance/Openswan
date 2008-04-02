
#include <sysqueue.h>
#include <linux/types.h>
#define u8 __u8

#define TimeZoneOffset timezone

#include <limits.h>
/* POSIX 1003.1-2001 says <unistd.h> defines this */
#ifndef HOST_NAME_MAX
# define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
#endif

