/*
 * @(#) definition of ipsec_stats structure
 *
 * Copyright (C) 2001  Richard Guy Briggs  <rgb@freeswan.org>
 *                 and Michael Richardson  <mcr@freeswan.org>
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
 * RCSID $Id: ipsec_stats.h,v 1.6 2004/04/05 19:55:07 mcr Exp $
 *
 */

/* 
 * This file describes the errors/statistics that FreeSWAN collects.
 */

#ifndef _IPSEC_STATS_H_

struct ipsec_stats {
	__u32		ips_alg_errs;	       /* number of algorithm errors */
	__u32		ips_auth_errs;	       /* # of authentication errors */
	__u32		ips_encsize_errs;      /* # of encryption size errors*/
	__u32		ips_encpad_errs;       /* # of encryption pad  errors*/
	__u32		ips_replaywin_errs;    /* # of pkt sequence errors */
};

extern int ipsec_snprintf(char * buf, ssize_t size, const char *fmt, ...);

#define _IPSEC_STATS_H_
#endif /* _IPSEC_STATS_H_ */

/*
 * $Log: ipsec_stats.h,v $
 * Revision 1.6  2004/04/05 19:55:07  mcr
 * Moved from linux/include/freeswan/ipsec_stats.h,v
 *
 * Revision 1.5  2004/04/05 19:41:05  mcr
 * 	merged alg-branch code.
 *
 * Revision 1.4  2004/03/28 20:27:19  paul
 * Included tested and confirmed fixes mcr made and dhr verified for
 * snprint statements. Changed one other snprintf to use ipsec_snprintf
 * so it wouldnt break compatibility with 2.0/2.2 kernels. Verified with
 * dhr. (thanks dhr!)
 *
 * Revision 1.4  2004/03/24 01:58:31  mcr
 *     sprintf->snprintf for formatting into proc buffer.
 *
 * Revision 1.3.34.1  2004/04/05 04:30:46  mcr
 * 	patches for alg-branch to compile/work with 2.x openswan
 *
 * Revision 1.3  2002/04/24 07:36:47  mcr
 * Moved from ./klips/net/ipsec/ipsec_stats.h,v
 *
 * Revision 1.2  2001/11/26 09:16:16  rgb
 * Merge MCR's ipsec_sa, eroute, proc and struct lifetime changes.
 *
 * Revision 1.1.2.1  2001/09/25 02:27:00  mcr
 * 	statistics moved to seperate structure.
 *
 *
 *
 * Local variables:
 * c-file-style: "linux"
 * End:
 *
 */
