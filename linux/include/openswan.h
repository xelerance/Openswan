#ifndef _OPENSWAN_H
/*
 * header file for FreeS/WAN library functions
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 */
#define	_OPENSWAN_H	/* seen it, no need to see it again */

/* you'd think this should be builtin to compiler... */
#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

/*
 * We've just got to have some datatypes defined...  And annoyingly, just
 * where we get them depends on whether we're in userland or not.
 */
/* things that need to come from one place or the other, depending */
#if defined(linux)
#if defined(__KERNEL__)
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <openswan/ipsec_kversion.h>
#include <openswan/ipsec_param.h>
#define user_assert(foo)  /*nothing*/

#else /* NOT in kernel */
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#define user_assert(foo) assert(foo)
#include <stdio.h>

#  define uint8_t u_int8_t
#  define uint16_t u_int16_t
#  define uint32_t u_int32_t
#  define uint64_t u_int64_t



#endif /* __KERNEL__ */

#endif /* linux */

#define DEBUG_NO_STATIC static

/*
 * Yes Virginia, we have started a windows port.
 */
#if defined(__CYGWIN32__)
#if !defined(WIN32_KERNEL)
/* get windows equivalents */
#include <stdio.h>
#include <string.h>
#include <win32/types.h>
#include <netinet/in.h>
#include <cygwin/socket.h>
#include <assert.h>
#define user_assert(foo) assert(foo)
#endif /* _KERNEL */
#endif /* WIN32 */

/*
 * Kovacs? A macosx port?
 */
#if defined(macintosh) || (defined(__MACH__) && defined(__APPLE__))
#include <TargetConditionals.h>
#include <AvailabilityMacros.h>
#include <machine/types.h>
#include <machine/endian.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <tcpd.h>
#include <assert.h>
#define user_assert(foo) assert(foo)
#define __u32  unsigned int
#define __u8  unsigned char
#define s6_addr16 __u6_addr.__u6_addr16
#define DEBUG_NO_STATIC static
#endif

/*
 * FreeBSD
 */
#if defined(__FreeBSD__)
#  define DEBUG_NO_STATIC static
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <assert.h>
#define user_assert(foo) assert(foo)
/* apparently this way to deal with an IPv6 address is not standard. */
#define s6_addr16 __u6_addr.__u6_addr16
#endif


#ifndef IPPROTO_COMP
#  define IPPROTO_COMP 108
#endif /* !IPPROTO_COMP */

#ifndef IPPROTO_INT
#  define IPPROTO_INT 61
#endif /* !IPPROTO_INT */

#if !defined(ESPINUDP_WITH_NON_IKE)
#define ESPINUDP_WITH_NON_IKE   1  /* draft-ietf-ipsec-nat-t-ike-00/01 */
#define ESPINUDP_WITH_NON_ESP   2  /* draft-ietf-ipsec-nat-t-ike-02    */
#endif

/*
 * Basic data types for the address-handling functions.
 * ip_address and ip_subnet are supposed to be opaque types; do not
 * use their definitions directly, they are subject to change!
 */

/* first, some quick fakes in case we're on an old system with no IPv6 */
#if !defined(s6_addr16) && defined(__CYGWIN32__)
struct in6_addr {
	union
	{
		u_int8_t	u6_addr8[16];
		u_int16_t	u6_addr16[8];
		u_int32_t	u6_addr32[4];
	} in6_u;
#define s6_addr			in6_u.u6_addr8
#define s6_addr16		in6_u.u6_addr16
#define s6_addr32		in6_u.u6_addr32
};
struct sockaddr_in6 {
	unsigned short int	sin6_family;    /* AF_INET6 */
	__u16			sin6_port;      /* Transport layer port # */
	__u32			sin6_flowinfo;  /* IPv6 flow information */
	struct in6_addr		sin6_addr;      /* IPv6 address */
	__u32			sin6_scope_id;  /* scope id (new in RFC2553) */
};
#endif	/* !s6_addr16 */

/* then the main types */
typedef struct {
	union {
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} u;
} ip_address;
typedef struct {
	ip_address addr;
	int maskbits;
} ip_subnet;
#define ip_address_family(a)	((a)->u.v4.sin_family)
#define ip_address_cmp(a, b) \
	(ip_address_family((a)) != ip_address_family((b)) || \
	(ip_address_family((a)) == AF_INET ? \
			((a)->u.v4.sin_addr.s_addr != (b)->u.v4.sin_addr.s_addr) : \
			memcmp((a)->u.v6.sin6_addr.s6_addr32, \
					(b)->u.v6.sin6_addr.s6_addr32, sizeof(u_int32_t) * 4) \
			))
#define	ip_address_isany(a) \
	(ip_address_family((a)) == AF_INET6 ? \
			((a)->u.v6.sin6_addr.s6_addr[0] == 0 && \
				(a)->u.v6.sin6_addr.s6_addr[1] == 0 && \
				(a)->u.v6.sin6_addr.s6_addr[2] == 0 && \
				(a)->u.v6.sin6_addr.s6_addr[3] == 0) : \
			((a)->u.v4.sin_addr.s_addr == 0))

/* and the SA ID stuff */
#ifdef __KERNEL__
typedef __u32 ipsec_spi_t;
#else
typedef u_int32_t ipsec_spi_t;
#endif
typedef struct {		/* to identify an SA, we need: */
        ip_address dst;		/* A. destination host */
        ipsec_spi_t spi;	/* B. 32-bit SPI, assigned by dest. host */
#		define	SPI_PASS	256	/* magic values... */
#		define	SPI_DROP	257	/* ...for use... */
#		define	SPI_REJECT	258	/* ...with SA_INT */
#		define	SPI_HOLD	259
#		define	SPI_TRAP	260
#		define  SPI_TRAPSUBNET  261
	int proto;		/* C. protocol */
#		define	SA_ESP	50	/* IPPROTO_ESP */
#		define	SA_AH	51	/* IPPROTO_AH */
#		define	SA_IPIP	4	/* IPPROTO_IPIP */
#		define	SA_COMP	108	/* IPPROTO_COMP */
#		define	SA_INT	61	/* IANA reserved for internal use */
} ip_said;

/* misc */
typedef const char *err_t;	/* error message, or NULL for success */
struct prng {			/* pseudo-random-number-generator guts */
	unsigned char sbox[256];
	int i, j;
	unsigned long count;
};


/*
 * definitions for user space, taken from freeswan/ipsec_sa.h
 */
typedef uint32_t IPsecSAref_t;

/* Translation to/from nfmark.
 *
 * use bits 16-31. Leave bit 32 as a indicate that IPsec processing
 * has already been done.
 */
#define IPSEC_SA_REF_TABLE_IDX_WIDTH 15
#define IPSEC_SA_REF_TABLE_OFFSET    16
#define IPSEC_SA_REF_MASK           ((1u<<IPSEC_SA_REF_TABLE_IDX_WIDTH)-1u)
#define IPSEC_NFMARK_IS_SAREF_BIT 0x80000000u

#define IPsecSAref2NFmark(x) (((x)&IPSEC_SA_REF_MASK) << IPSEC_SA_REF_TABLE_OFFSET)
#define NFmark2IPsecSAref(x) (((x) >> IPSEC_SA_REF_TABLE_OFFSET)&IPSEC_SA_REF_MASK)

#define IPSEC_SAREF_NULL ((IPsecSAref_t)0u)
/* Not representable as an nfmark */
#define IPSEC_SAREF_NA   ((IPsecSAref_t)0xffff0001)


/* GCC magic for use in function definitions! */
#ifdef GCC_LINT
# define PRINTF_LIKE(n) __attribute__ ((format(printf, n, n+1)))
# define NEVER_RETURNS __attribute__ ((noreturn))
# define UNUSED __attribute__ ((unused))
# define BLANK_FORMAT " "	/* GCC_LINT whines about empty formats */
#else
# define PRINTF_LIKE(n)	/* ignore */
# define NEVER_RETURNS /* ignore */
# define UNUSED /* ignore */
# define BLANK_FORMAT ""
#endif

#ifdef COMPILER_HAS_NO_PRINTF_LIKE
# undef PRINTF_LIKE
# define PRINTF_LIKE(n)	/* ignore */
#endif


/*
 * function to log stuff from libraries that may be used in multiple
 * places.
 */
typedef int (*openswan_keying_debug_func_t)(const char *message, ...);



/*
 * new IPv6-compatible functions
 */

/* text conversions */
err_t ttoul(const char *src, size_t srclen, int format, unsigned long *dst);
size_t ultot(unsigned long src, int format, char *buf, size_t buflen);
#define	ULTOT_BUF	(22+1)	/* holds 64 bits in octal */

/* looks up names in DNS */
err_t ttoaddr(const char *src, size_t srclen, int af, ip_address *dst);

/* does not look up names in DNS */
err_t ttoaddr_num(const char *src, size_t srclen, int af, ip_address *dst);

err_t tnatoaddr(const char *src, size_t srclen, int af, ip_address *dst);
size_t addrtot(const ip_address *src, int format, char *buf, size_t buflen);
size_t inet_addrtot(int type,const void *src, int format, char *buf, size_t buflen);
size_t sin_addrtot(const void *sin, int format, char *dst, size_t dstlen);
/* RFC 1886 old IPv6 reverse-lookup format is the bulkiest */
#define	ADDRTOT_BUF	(32*2 + 3 + 1 + 3 + 1 + 1)
err_t ttosubnet(const char *src, size_t srclen, int af, ip_subnet *dst);
size_t subnettot(const ip_subnet *src, int format, char *buf, size_t buflen);
#define	SUBNETTOT_BUF	(ADDRTOT_BUF + 1 + 3)
size_t subnetporttot(const ip_subnet *src, int format, char *buf, size_t buflen);
#define	SUBNETPROTOTOT_BUF	(SUBNETTOTO_BUF + ULTOT_BUF)
err_t ttosa(const char *src, size_t srclen, ip_said *dst);
size_t satot(const ip_said *src, int format, char *bufptr, size_t buflen);
#define	SATOT_BUF	(5 + ULTOA_BUF + 1 + ADDRTOT_BUF)
err_t ttodata(const char *src, size_t srclen, int base, char *buf,
						size_t buflen, size_t *needed);
err_t ttodatav(const char *src, size_t srclen, int base,
	       char *buf,  size_t buflen, size_t *needed,
	       char *errp, size_t errlen, unsigned int flags);
#define	TTODATAV_BUF	40	/* ttodatav's largest non-literal message */
#define TTODATAV_IGNORESPACE  (1<<1)  /* ignore spaces in base64 encodings*/
#define TTODATAV_SPACECOUNTS  0       /* do not ignore spaces in base64   */

size_t datatot(const unsigned char *src, size_t srclen, int format
	       , char *buf, size_t buflen);
size_t keyblobtoid(const unsigned char *src, size_t srclen, char *dst,
								size_t dstlen);
size_t splitkeytoid(const unsigned char *e, size_t elen, const unsigned char *m,
					size_t mlen, char *dst, size_t dstlen);
#define	KEYID_BUF	10	/* up to 9 text digits plus NUL */
err_t ttoprotoport(char *src, size_t src_len, u_int8_t *proto, u_int16_t *port,
                                                       int *has_port_wildcard);

/* initializations */
void initsaid(const ip_address *addr, ipsec_spi_t spi, int proto, ip_said *dst);
err_t loopbackaddr(int af, ip_address *dst);
err_t unspecaddr(int af, ip_address *dst);
err_t anyaddr(int af, ip_address *dst);
err_t initaddr(const unsigned char *src, size_t srclen, int af, ip_address *dst);
err_t add_port(int af, ip_address *addr, unsigned short port);
err_t initsubnet(const ip_address *addr, int maskbits, int clash, ip_subnet *dst);
err_t addrtosubnet(const ip_address *addr, ip_subnet *dst);

/* misc. conversions and related */
err_t rangetosubnet(const ip_address *from, const ip_address *to, ip_subnet *dst);
int addrtypeof(const ip_address *src);
int subnettypeof(const ip_subnet *src);
size_t addrlenof(const ip_address *src);
size_t addrbytesptr(const ip_address *src, unsigned char **const dst);
size_t addrbytesptr_write(ip_address *src, unsigned char **const dst);
size_t addrbytesof(const ip_address *src, unsigned char *dst, size_t dstlen);
int masktocount(const ip_address *src);
void networkof(const ip_subnet *src, ip_address *dst);
void maskof(const ip_subnet *src, ip_address *dst);

/* tests */
int sameaddr(const ip_address *a, const ip_address *b);
int addrcmp(const ip_address *a, const ip_address *b);
int samesubnet(const ip_subnet *a, const ip_subnet *b);
int addrinsubnet(const ip_address *a, const ip_subnet *s);
int subnetinsubnet(const ip_subnet *a, const ip_subnet *b);
int subnetishost(const ip_subnet *s);
int samesaid(const ip_said *a, const ip_said *b);
int sameaddrtype(const ip_address *a, const ip_address *b);
int samesubnettype(const ip_subnet *a, const ip_subnet *b);
int isvalidsubnet(const ip_subnet *a);
int isanyaddr(const ip_address *src);
int isunspecaddr(const ip_address *src);
int isloopbackaddr(const ip_address *src);

/* low-level grot */
int portof(const ip_address *src);
void setportof(int port, ip_address *dst);
struct sockaddr *sockaddrof(ip_address *src);
size_t sockaddrlenof(const ip_address *src);

/* PRNG */
void prng_init(struct prng *prng, const unsigned char *key, size_t keylen);
void prng_bytes(struct prng *prng, unsigned char *dst, size_t dstlen);
unsigned long prng_count(struct prng *prng);
void prng_final(struct prng *prng);

/* odds and ends */
const char *ipsec_version_code(void);
const char *ipsec_version_string(void);
const char **ipsec_copyright_notice(void);

const char *dns_string_rr(int rr, char *buf, int bufsize);
const char *dns_string_datetime(time_t seconds,
				char *buf,
				int bufsize);

/* from OpenBSD */
size_t strlcat(char *dst, const char *src, size_t siz);


/*
 * old functions, to be deleted eventually
 */

/* unsigned long */
const char *			/* NULL for success, else string literal */
atoul(
	const char *src,
	size_t srclen,		/* 0 means strlen(src) */
	int base,		/* 0 means figure it out */
	unsigned long *resultp
);
size_t				/* space needed for full conversion */
ultoa(
	unsigned long n,
	int base,
	char *dst,
	size_t dstlen
);
#define	ULTOA_BUF	21	/* just large enough for largest result, */
				/* assuming 64-bit unsigned long! */

/* Internet addresses */
const char *			/* NULL for success, else string literal */
atoaddr(
	const char *src,
	size_t srclen,		/* 0 means strlen(src) */
	struct in_addr *addr
);
size_t				/* space needed for full conversion */
addrtoa(
	struct in_addr addr,
	int format,		/* character; 0 means default */
	char *dst,
	size_t dstlen
);
#define	ADDRTOA_BUF	ADDRTOT_BUF

/* subnets */
const char *			/* NULL for success, else string literal */
atosubnet(
	const char *src,
	size_t srclen,		/* 0 means strlen(src) */
	struct in_addr *addr,
	struct in_addr *mask
);
size_t				/* space needed for full conversion */
subnettoa(
	struct in_addr addr,
	struct in_addr mask,
	int format,		/* character; 0 means default */
	char *dst,
	size_t dstlen
);
size_t				/* space needed for full conversion */
subnet6toa(
	struct in6_addr *addr,
	struct in6_addr *mask,
	int format,		/* character; 0 means default */
	char *dst,
	size_t dstlen
);
#define	SUBNETTOA_BUF SUBNETTOT_BUF	/* large enough for worst case result */

/* ranges */
const char *			/* NULL for success, else string literal */
atoasr(
	const char *src,
	size_t srclen,		/* 0 means strlen(src) */
	char *type,		/* 'a', 's', 'r' */
	struct in_addr *addrs	/* two-element array */
);
size_t				/* space needed for full conversion */
rangetoa(
	struct in_addr *addrs,	/* two-element array */
	int format,		/* character; 0 means default */
	char *dst,
	size_t dstlen
);
#define	RANGETOA_BUF	34	/* large enough for worst case result */

/* data types for SA conversion functions */

/* generic data, e.g. keys */
const char *			/* NULL for success, else string literal */
atobytes(
	const char *src,
	size_t srclen,		/* 0 means strlen(src) */
	char *dst,
	size_t dstlen,
	size_t *lenp		/* NULL means don't bother telling me */
);
size_t				/* 0 failure, else true size */
bytestoa(
	const unsigned char *src,
	size_t srclen,
	int format,		/* character; 0 means default */
	char *dst,
	size_t dstlen
);

/* old versions of generic-data functions; deprecated */
size_t				/* 0 failure, else true size */
atodata(
	const char *src,
	size_t srclen,		/* 0 means strlen(src) */
	char *dst,
	size_t dstlen
);
size_t				/* 0 failure, else true size */
datatoa(
	const unsigned char *src,
	size_t srclen,
	int format,		/* character; 0 means default */
	char *dst,
	size_t dstlen
);

/* part extraction and special addresses */
struct in_addr
subnetof(
	struct in_addr addr,
	struct in_addr mask
);
struct in_addr
hostof(
	struct in_addr addr,
	struct in_addr mask
);
struct in_addr
broadcastof(
	struct in_addr addr,
	struct in_addr mask
);

/* mask handling */
int
goodmask(
	struct in_addr mask
);
extern int masktobits(struct in_addr mask);
extern int mask6tobits(struct in6_addr *mask);
extern struct in_addr  bitstomask(int n);
extern struct in6_addr bitstomask6(int n);



/*
 * ENUM of klips debugging values. Not currently used in klips.
 * debug flag is actually 32 -bits, but only one bit is ever used,
 * so we can actually pack it all into a single 32-bit word.
 */
enum klips_debug_flags {
    KDF_VERBOSE     = 0,
    KDF_XMIT        = 1,
    KDF_NETLINK     = 2, /* obsolete */
    KDF_XFORM       = 3,
    KDF_EROUTE      = 4,
    KDF_SPI         = 5,
    KDF_RADIJ       = 6,
    KDF_ESP         = 7,
    KDF_AH          = 8, /* obsolete */
    KDF_RCV         = 9,
    KDF_TUNNEL      = 10,
    KDF_PFKEY       = 11,
    KDF_COMP        = 12,
    KDF_NATT        = 13,
};


/*
 * Debugging levels for pfkey_lib_debug
 */
#define PF_KEY_DEBUG_PARSE_NONE    0
#define PF_KEY_DEBUG_PARSE_PROBLEM 1
#define PF_KEY_DEBUG_PARSE_STRUCT  2
#define PF_KEY_DEBUG_PARSE_FLOW    4
#define PF_KEY_DEBUG_BUILD         8
#define PF_KEY_DEBUG_PARSE_MAX    15

extern unsigned int pfkey_lib_debug;  /* bits selecting what to report */

/*
 * pluto and lwdnsq need to know the maximum size of the commands to,
 * and replies from lwdnsq.
 */

#define LWDNSQ_CMDBUF_LEN      1024
#define LWDNSQ_RESULT_LEN_MAX  4096


/* syntax for passthrough SA */
#ifndef PASSTHROUGHNAME
#define	PASSTHROUGHNAME	"%passthrough"
#define	PASSTHROUGH4NAME	"%passthrough4"
#define	PASSTHROUGH6NAME	"%passthrough6"
#define	PASSTHROUGHIS	"tun0@0.0.0.0"
#define	PASSTHROUGH4IS	"tun0@0.0.0.0"
#define	PASSTHROUGH6IS	"tun0@::"
#define	PASSTHROUGHTYPE	"tun"
#define	PASSTHROUGHSPI	0
#define	PASSTHROUGHDST	0
#endif



#endif /* _OPENSWAN_H */
