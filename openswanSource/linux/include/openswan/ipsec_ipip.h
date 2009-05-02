/*
 * Copyright (C) 2003 Michael Richardson <mcr@sandelman.ottawa.on.ca>
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * RCSID $Id: ipsec_ipip.h,v 1.2 2004/04/05 19:55:05 mcr Exp $
 */

#ifndef _IPSEC_IPIP_H_

#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP 4
#endif /* IPPROTO_ESP */

extern struct xform_functions ipip_xform_funcs[];

#define _IPSEC_IPIP_H_

#endif /* _IPSEC_IPIP_H_ */

/*
 * $Log: ipsec_ipip.h,v $
 * Revision 1.2  2004/04/05 19:55:05  mcr
 * Moved from linux/include/freeswan/ipsec_ipip.h,v
 *
 * Revision 1.1  2003/12/13 19:10:16  mcr
 * 	refactored rcv and xmit code - same as FS 2.05.
 *
 * Revision 1.1  2003/12/11 20:14:58  mcr
 * 	refactored the xmit code, to move all encapsulation
 * 	code into protocol functions. Note that all functions
 * 	are essentially done by a single function, which is probably
 * 	wrong.
 * 	the rcv_functions structures are renamed xform_functions.
 *
 *
 */
