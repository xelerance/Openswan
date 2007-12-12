/*
 * more minor utilities for mask length calculations for IKEv2
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
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
 * RCSID $Id: goodmask.c,v 1.12 2004/07/10 07:43:47 mcr Exp $
 */
#include "openswan.h"
#include "openswan/passert.h"

/*
 * this is stupid implementation, see goodmask.c for ideas
 * on doing it better, but note that this counts zero bits, not
 * 1 bits, and it doesn't assume that the mask is properly formed.
 *
 */
int ikev2_highorder_zerobits(ip_address b)
{
    int i, j, val;
    u_int32_t mask;
    int zerobits = 0;

    switch(b.u.v4.sin_family) {
    case AF_INET:
	mask = 1UL << 31;
	val  = ntohl(b.u.v4.sin_addr.s_addr);
	for(i=31; i>=0; i--) {
	    if(val & mask) return i;
	    mask >>= 1;
	}
	return 0;

    case AF_INET6:
	mask = 1UL << 8;
	zerobits = 0;
	for(j=0; j<7; j++) {
	    mask = 1UL << 7;
	    val  = b.u.v6.sin6_addr.s6_addr[j];
	    for(i=7; i>=0; i--) {
		if(val & mask) return zerobits+i;
		mask >>= 1;
	    }
	    zerobits += 8;
	}
	return 128;

    default:
	impossible();
    }

    return 0;
}

int ikev2_calc_iprangediff(ip_address low, ip_address high)
{
    ip_address diff;
    int i;
    int carry = 0;

    switch(low.u.v4.sin_family) {
    case AF_INET:
	diff.u.v4.sin_addr.s_addr =
	    htonl(ntohl(high.u.v4.sin_addr.s_addr)-
		  ntohl(low.u.v4.sin_addr.s_addr));
	
	break;
	
    case AF_INET6:
	for(i=7; i>=0; i++) {
	    int val=
		high.u.v6.sin6_addr.s6_addr[i]-
		low.u.v6.sin6_addr.s6_addr[i]-carry;
	    
	    if(val < 0) {
		val += 256;
		carry=1;
	    } else {
		carry=0;
	    }
	    diff.u.v6.sin6_addr.s6_addr[i]=val;
	}
	break;
    }

    return ikev2_highorder_zerobits(diff);
}

