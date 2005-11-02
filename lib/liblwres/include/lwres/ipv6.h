/*
 * Copyright (C) 2004  Internet Systems Consortium, Inc. ("ISC")
 * Copyright (C) 2000, 2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: ipv6.h,v 1.3 2005/08/05 01:18:30 mcr Exp $ */

#ifndef LWRES_IPV6_H
#define LWRES_IPV6_H 1

/*****
 ***** Module Info
 *****/

/*
 * IPv6 definitions for systems which do not support IPv6.
 */

/***
 *** Imports.
 ***/

#include <lwres/int.h>
#include <lwres/platform.h>

#if 0
/***
 *** Types.
 ***/

struct in6_pktinfo {
	struct in6_addr ipi6_addr;    /* src/dst IPv6 address */
	unsigned int    ipi6_ifindex; /* send/recv interface index */
};
#endif

#endif /* LWRES_IPV6_H */
