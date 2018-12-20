/*
 * extract parts of an ip_subnet, and related
 * Copyright (C) 2000  Henry Spencer.
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
 */

#include "internal.h"
#include "openswan.h"

/*
 - subnettypeof - get the address type of an ip_subnet
 */
int
subnettypeof(src)
const ip_subnet *src;
{
	return src->addr.u.v4.sin_family;
}

/*
 * subnetsize - return order of addresses in subnet
 *
 * for example:
 *   returns  0 if the subnet is 1 IP (mask of /32 for ipv4)
 *   returns  1 if the subnet is 2 IP (mask of /127 for ipv6)
 *   returns -1 if there is no subnet (0.0.0.0/0 or ::/0)
 *   returns -2 if something is off
 */
int subnetsize(const ip_subnet *src)
{
	int addr_bytes, addr_bits, i;
	unsigned char *adrp = NULL;

	addr_bytes = addrbytesptr(&src->addr, &adrp);
	if (!addr_bytes || !adrp)
		return -1;

	/* handle the special case of ::/0, returning 0 */
	if (!src->maskbits) {
		int allzero = 1;
		for (i=0; i<addr_bytes; i++) {
			if (!adrp[i])
				continue;
			allzero = 0;
			break;
		}
		if (allzero)
			return -1;
	}

	addr_bits = addr_bytes * 8;
	if (src->maskbits > addr_bits)
		return -2;

	return addr_bits - src->maskbits;
}

/*
 - networkof - get the network address of a subnet
 */
void
networkof(src, dst)
const ip_subnet *src;
ip_address *dst;
{
	*dst = src->addr;
}

/*
 - maskof - get the mask of a subnet, as an address
 */
void
maskof(src, dst)
const ip_subnet *src;
ip_address *dst;
{
	int b;
	unsigned char buf[16];
	size_t n = addrlenof(&src->addr);
	unsigned char *p;

	if (src->maskbits > n*8 || n > sizeof(buf))
		return;		/* "can't happen" */

	p = buf;
	for (b = src->maskbits; b >= 8; b -= 8)
		*p++ = 0xff;
	if (b != 0)
		*p++ = (0xff << (8 - b)) & 0xff;
	while (p - buf < n)
		*p++ = 0;

	(void) initaddr(buf, n, addrtypeof(&src->addr), dst);
}

/*
 - masktocount - convert a mask, expressed as an address, to a bit count
 */
int				/* -1 if not valid mask */
masktocount(src)
const ip_address *src;
{
	int b;
	unsigned char *bp;
	size_t n;
	unsigned const char *p;
	unsigned const char *stop;

	n = addrbytesptr(src, &bp);
	if (n == 0)
		return -1;

	p = bp;
	stop = bp + n;

	n = 0;
	while (p < stop && *p == 0xff) {
		p++;
		n += 8;
	}
	if (p < stop && *p != 0) {	/* boundary in mid-byte */
		b = *p++;
		while (b&0x80) {
			b <<= 1;
			n++;
		}
		if ((b&0xff) != 0)
			return -1;	/* bits not contiguous */
	}
	while (p < stop && *p == 0)
		p++;

	if (p != stop)
		return -1;

	return n;
}
