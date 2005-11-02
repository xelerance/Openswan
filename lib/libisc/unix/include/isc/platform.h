/*
 * Copyright (C) 2004  Internet Systems Consortium, Inc. ("ISC")
 * Copyright (C) 2001  Internet Software Consortium.
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

/* $ISC-Id:platform.h,v 1.5.12.6 2004/04/19 06:39:56 marka Exp $ */
/* $Id: platform.h,v 1.3 2005/08/21 23:25:46 mcr Exp $ */

#ifndef ISC_PLATFORM_H
#define ISC_PLATFORM_H 1

/*****
 ***** Platform-dependent defines.
 *****/

#undef ISC_PLATFORM_USETHREADS
/***
 *** Network.
 ***/

#define ISC_PLATFORM_HAVEIN6PKTINFO
#undef ISC_PLATFORM_NEEDSTRSEP
#define ISC_PLATFORM_NEEDSTRLCPY
#define LIBISC_EXTERNAL_DATA 
#define LIBDNS_EXTERNAL_DATA 

#endif /* ISC_PLATFORM_H */
