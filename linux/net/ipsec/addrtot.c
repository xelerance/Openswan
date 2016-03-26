/*
 * addresses to text
 * Copyright (C) 2000  Henry Spencer.
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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

#if defined(__KERNEL__) && defined(__HAVE_ARCH_STRSTR)
#include <linux/string.h>
#endif

#if !defined(__KERNEL__)
# include <stdlib.h>
#endif

#include "openswan.h"

#define	IP4BYTES	4	/* bytes in an IPv4 address */
#define	PERBYTE		4	/* three digits plus a dot or NUL */
#define	IP6BYTES	16	/* bytes in an IPv6 address */

/* forwards */
static size_t normal4(const unsigned char *s, size_t len, char *b, char **dp);
static size_t normal6(const unsigned char *s, size_t len, char *b, char **dp, int squish);
static size_t reverse4(const unsigned char *s, size_t len, char *b, char **dp);
static size_t reverse6(const unsigned char *s, size_t len, char *b, char **dp);

#if defined(__KERNEL__) && !defined(__HAVE_ARCH_STRSTR)
#define strstr ipsec_strstr
/*
 * Find the first occurrence of find in s.
 * (from NetBSD 1.6's /src/lib/libc/string/strstr.c)
 */

static char *
ipsec_strstr(const char *s, const char *find)
{
	char c, sc;
	size_t len;

	if ((c = *find++) != 0) {
		len = strlen(find);
		do {
			do {
				if ((sc = *s++) == 0)
					return (NULL);
			} while (sc != c);
		} while (strncmp(s, find, len) != 0);
		s--;
	}
	/* LINTED interface specification */
	return ((char *)s);
}
#endif

/*
 - addrtot - convert binary address to text (dotted decimal or IPv6 string)
 */
size_t				/* space needed for full conversion */
addrtot(src, format, dst, dstlen)
const ip_address *src;
int format;			/* character */
char *dst;			/* need not be valid if dstlen is 0 */
size_t dstlen;
{
        unsigned char *b;
	size_t n;
	char buf[1+ADDRTOT_BUF+1];	/* :address: */
	char *p;
	int t;
#define	TF(t, f)	(((t)<<8) | (f))

        if(!src) {
                strncat(dst, "<none>", dstlen -1);
                return sizeof("<none>");
        }

	t = addrtypeof(src);
	n = addrbytesptr(src, &b);
	if (n == 0) {
	  dst[0]='\0';
	  strncat(dst, "<invalid>", dstlen -1); /* we hope possible truncation does not cause problems */
	  return sizeof("<invalid>");
	}

	switch (TF(t, format)) {
	case TF(AF_INET, 0):
		n = normal4(b, n, buf, &p);
		break;
	case TF(AF_INET6, 0):
		n = normal6(b, n, buf, &p, 1);
		break;
	case TF(AF_INET, 'Q'):
		n = normal4(b, n, buf, &p);
		break;
	case TF(AF_INET6, 'Q'):
		n = normal6(b, n, buf, &p, 0);
		break;
	case TF(AF_INET, 'r'):
		n = reverse4(b, n, buf, &p);
		break;
	case TF(AF_INET6, 'r'):
		n = reverse6(b, n, buf, &p);
		break;
	default:		/* including (AF_INET, 'R') */
		dst[0]='\0';
		strncat(dst, "<invalid>", dstlen - 1); /* we hope possible truncation does not cause problems */
		return sizeof("<invalid>");
	}

	if (dstlen > 0) {
		if (dstlen < n)
			p[dstlen - 1] = '\0';
		strcpy(dst, p);
	}
	return n;
}

/*
 - inet_addrtot - convert binary inet address to text (dotted decimal or IPv6 string)
 */
size_t				/* space needed for full conversion */
inet_addrtot(t, src, format, dst, dstlen)
int t;			/* AF_INET/AF_INET6 */
const void *src;
int format;			/* character */
char *dst;			/* need not be valid if dstlen is 0 */
size_t dstlen;
{
	size_t n;
	char buf[1+ADDRTOT_BUF+1];	/* :address: */
	char *p;

#	define	TF(t, f)	(((t)<<8) | (f))

	switch (t) {
	case AF_INET: n = IP4BYTES; break;
	case AF_INET6: n = IP6BYTES; break;
	default:
	  dst[0]='\0';
	  strncat(dst, "<invalid>", dstlen - 1); /* we hope possible truncation does not cause problems */
	  return sizeof("<invalid>");
	}

	switch (TF(t, format)) {
	case TF(AF_INET, 0):
		n = normal4(src, n, buf, &p);
		break;
	case TF(AF_INET6, 0):
		n = normal6(src, n, buf, &p, 1);
		break;
	case TF(AF_INET, 'Q'):
		n = normal4(src, n, buf, &p);
		break;
	case TF(AF_INET6, 'Q'):
		n = normal6(src, n, buf, &p, 0);
		break;
	case TF(AF_INET, 'r'):
		n = reverse4(src, n, buf, &p);
		break;
	case TF(AF_INET6, 'r'):
		n = reverse6(src, n, buf, &p);
		break;
	default:		/* including (AF_INET, 'R') */
	  	dst[0]='\0';
	  	strncat(dst, "<invalid>", dstlen - 1); /* we hope possible truncation does not cause problems */
	  	return sizeof("<invalid>");
	}

	if (dstlen > 0) {
		if (dstlen < n)
			p[dstlen - 1] = '\0';
		strcpy(dst, p);
	}
	return n;
}

/*
 * sin_addrtot - convert binary sockaddr_in/sockaddr_in6 address to text
 * (dotted decimal or IPv6 string)
 */
size_t				/* space needed for full conversion */
sin_addrtot(src, format, dst, dstlen)
const void *src;
int format;			/* character */
char *dst;			/* need not be valid if dstlen is 0 */
size_t dstlen;
{
	const union SINSIN6 {
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} *sinp = (const union SINSIN6 *) src;

	switch (sinp->sin.sin_family) {
	case AF_INET:
		return inet_addrtot(AF_INET,&sinp->sin.sin_addr,format,dst,dstlen);
	case AF_INET6:
		return inet_addrtot(AF_INET6,&sinp->sin6.sin6_addr,format,dst,dstlen);
	default:
		dst[0]='\0';
		strncat(dst, "<invalid>", dstlen - 1); /* we hope possible truncation does not cause problems */
		return sizeof("<invalid>");
	}
}

/*
 - normal4 - normal IPv4 address-text conversion
 */
static size_t			/* size of text, including NUL */
normal4(srcp, srclen, buf, dstp)
const unsigned char *srcp;
size_t srclen;
char *buf;			/* guaranteed large enough */
char **dstp;			/* where to put result pointer */
{
	int i;
	char *p;

	if (srclen != IP4BYTES)	/* "can't happen" */
		return 0;
	p = buf;
	for (i = 0; i < IP4BYTES; i++) {
		p += ultot(srcp[i], 10, p, PERBYTE);
		if (i != IP4BYTES - 1)
			*(p-1) = '.';	/* overwrites the NUL */
	}
	*dstp = buf;
	return p - buf;
}

/*
 - normal6 - normal IPv6 address-text conversion
 */
static size_t			/* size of text, including NUL */
normal6(srcp, srclen, buf, dstp, squish)
const unsigned char *srcp;
size_t srclen;
char *buf;			/* guaranteed large enough, plus 2 */
char **dstp;			/* where to put result pointer */
int    squish;                  /* whether to squish out 0:0 */
{
	int i;
	unsigned long piece;
	char *p;
	char *q;

	if (srclen != IP6BYTES)	/* "can't happen" */
		return 0;
	p = buf;
	*p++ = ':';
	for (i = 0; i < IP6BYTES/2; i++) {
		piece = (srcp[2*i] << 8) + srcp[2*i + 1];
		p += ultot(piece, 16, p, 5);	/* 5 = abcd + NUL */
		*(p-1) = ':';	/* overwrites the NUL */
	}
	*p = '\0';
	q = strstr(buf, ":0:0:");
	if (squish && q != NULL) {	/* zero squishing is possible */
		p = q + 1;
		while (*p == '0' && *(p+1) == ':')
			p += 2;
		q++;
		*q++ = ':';	/* overwrite first 0 */
		while (*p != '\0')
			*q++ = *p++;
		*q = '\0';
		if (!(*(q-1) == ':' && *(q-2) == ':'))
			*--q = '\0';	/* strip final : unless :: */
		p = buf;
		if (!(*p == ':' && *(p+1) == ':'))
			p++;	/* skip initial : unless :: */
	} else {
		q = p;
		*--q = '\0';	/* strip final : */
		p = buf + 1;	/* skip initial : */
	}
	*dstp = p;
	return q - p + 1;
}

/*
 - reverse4 - IPv4 reverse-lookup conversion
 */
static size_t			/* size of text, including NUL */
reverse4(srcp, srclen, buf, dstp)
const unsigned char *srcp;
size_t srclen;
char *buf;			/* guaranteed large enough */
char **dstp;			/* where to put result pointer */
{
	int i;
	char *p;

	if (srclen != IP4BYTES)	/* "can't happen" */
		return 0;
	p = buf;
	for (i = IP4BYTES-1; i >= 0; i--) {
		p += ultot(srcp[i], 10, p, PERBYTE);
		*(p-1) = '.';	/* overwrites the NUL */
	}
	strcpy(p, "IN-ADDR.ARPA.");
	*dstp = buf;
	return strlen(buf) + 1;
}

/*
 - reverse6 - IPv6 reverse-lookup conversion (RFC 1886)
 * A trifle inefficient, really shouldn't use ultot...
 */
static size_t			/* size of text, including NUL */
reverse6(srcp, srclen, buf, dstp)
const unsigned char *srcp;
size_t srclen;
char *buf;			/* guaranteed large enough */
char **dstp;			/* where to put result pointer */
{
	int i;
	unsigned long piece;
	char *p;

	if (srclen != IP6BYTES)	/* "can't happen" */
		return 0;
	p = buf;
	for (i = IP6BYTES-1; i >= 0; i--) {
		piece = srcp[i];
		p += ultot(piece&0xf, 16, p, 2);
		*(p-1) = '.';
		p += ultot(piece>>4, 16, p, 2);
		*(p-1) = '.';
	}
	strcpy(p, "IP6.ARPA.");
	*dstp = buf;
	return strlen(buf) + 1;
}

/*
 - reverse6 - modern IPv6 reverse-lookup conversion (RFC 2874)
 * this version removed as it was obsoleted in the end.
 */

#ifdef ADDRTOT_MAIN

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void regress(void);

int
main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s {addr|net/mask|begin...end|-r}\n",
								argv[0]);
		exit(2);
	}

	if (strcmp(argv[1], "-r") == 0) {
		regress();
		fprintf(stderr, "regress() returned?!?\n");
		exit(1);
	}
	exit(0);
}

struct rtab {
	char *input;
        char  format;
	char *output;			/* NULL means error expected */
} rtab[] = {
	{"1.2.3.0",			0, "1.2.3.0"},
	{"1:2::3:4",                    0, "1:2::3:4"},
	{"1:2::3:4",                   'Q', "1:2:0:0:0:0:3:4"},
	{"1:2:0:0:3:4:0:0",             0, "1:2::3:4:0:0"},
	{"1.2.3.4",                    'r' , "4.3.2.1.IN-ADDR.ARPA."},
 	/*                                    0 1 2 3 4 5 6 7 8 9 a b c d e f 0 1 2 3 4 5 6 7 8 9 a b c d e f */
	{"1:2::3:4",                   'r', "4.0.0.0.3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.1.0.0.0.IP6.ARPA."},
	 {NULL,				0, NULL}
};

void
regress()
{
	struct rtab *r;
	int status = 0;
	ip_address a;
	char in[100];
	char buf[100];
	const char *oops;
	size_t n;

	for (r = rtab; r->input != NULL; r++) {
		strcpy(in, r->input);

		/* convert it *to* internal format */
		oops = ttoaddr(in, strlen(in), 0, &a);

		/* now convert it back */

		n = addrtot(&a, r->format, buf, sizeof(buf));

		if (n == 0 && r->output == NULL)
			{}		/* okay, error expected */

		else if (n == 0) {
			printf("`%s' atoasr failed\n", r->input);
			status = 1;

		} else if (r->output == NULL) {
			printf("`%s' atoasr succeeded unexpectedly '%c'\n",
							r->input, r->format);
			status = 1;
		} else {
		  if (strcasecmp(r->output, buf) != 0) {
		    printf("`%s' '%c' gave `%s', expected `%s'\n",
			   r->input, r->format, buf, r->output);
		    status = 1;
		  }
		}
	}
	exit(status);
}

#endif /* ADDRTOT_MAIN */

/*
 * Local variables:
 * c-file-style: "linux"
 * End:
 */
