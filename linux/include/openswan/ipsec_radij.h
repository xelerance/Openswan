/*
 * @(#) Definitions relevant to the IPSEC <> radij tree interfacing
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs.
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
 * RCSID $Id: ipsec_radij.h,v 1.22 2004/07/10 19:08:41 mcr Exp $
 */

#ifndef _IPSEC_RADIJ_H

#include <openswan.h>

int ipsec_walk(char *);

int ipsec_rj_walker_procprint(struct radij_node *, void *);
int ipsec_rj_walker_delete(struct radij_node *, void *);

/* This structure is used to pass information between
 * ipsec_eroute_get_info and ipsec_rj_walker_procprint
 * (through rj_walktree) and between calls of ipsec_rj_walker_procprint.
 */
struct wsbuf
{
       /* from caller of ipsec_eroute_get_info: */
       char *const buffer;     /* start of buffer provided */
       const int length;       /* length of buffer provided */
       const off_t offset;     /* file position of first character of interest */
       /* accumulated by ipsec_rj_walker_procprint: */
       int len;        /* number of character filled into buffer */
       off_t begin;    /* file position contained in buffer[0] (<=offset) */
};

extern struct radij_node_head *rnh;
extern spinlock_t eroute_lock;

struct eroute * ipsec_findroute(struct sockaddr_encap *);

#define O1(x) (int)(((x)>>24)&0xff)
#define O2(x) (int)(((x)>>16)&0xff)
#define O3(x) (int)(((x)>>8)&0xff)
#define O4(x) (int)(((x))&0xff)

#ifdef CONFIG_KLIPS_DEBUG
extern int debug_radij;
void rj_dumptrees(void);

#define DB_RJ_DUMPTREES	0x0001
#define DB_RJ_FINDROUTE 0x0002
#endif /* CONFIG_KLIPS_DEBUG */

#define _IPSEC_RADIJ_H
#endif

/*
 * $Log: ipsec_radij.h,v $
 * Revision 1.22  2004/07/10 19:08:41  mcr
 * 	CONFIG_IPSEC -> CONFIG_KLIPS.
 *
 * Revision 1.21  2004/04/29 11:06:42  ken
 * Last bits from 2.06 procfs updates
 *
 * Revision 1.20  2004/04/06 02:49:08  mcr
 * 	pullup of algo code from alg-branch.
 *
 * Revision 1.19  2004/04/05 19:55:06  mcr
 * Moved from linux/include/freeswan/ipsec_radij.h,v
 *
 * Revision 1.18  2002/04/24 07:36:47  mcr
 * Moved from ./klips/net/ipsec/ipsec_radij.h,v
 *
 * Revision 1.17  2001/11/26 09:23:49  rgb
 * Merge MCR's ipsec_sa, eroute, proc and struct lifetime changes.
 *
 * Revision 1.16.2.1  2001/09/25 02:21:17  mcr
 * 	ipsec_proto.h created to keep prototypes rather than deal with
 * 	cyclic dependancies of structures and prototypes in .h files.
 *
 * Revision 1.16  2001/09/15 16:24:04  rgb
 * Re-inject first and last HOLD packet when an eroute REPLACE is done.
 *
 * Revision 1.15  2001/09/14 16:58:37  rgb
 * Added support for storing the first and last packets through a HOLD.
 *
 * Revision 1.14  2001/09/08 21:13:32  rgb
 * Added pfkey ident extension support for ISAKMPd. (NetCelo)
 *
 * Revision 1.13  2001/06/14 19:35:09  rgb
 * Update copyright date.
 *
 * Revision 1.12  2001/05/27 06:12:11  rgb
 * Added structures for pid, packet count and last access time to eroute.
 * Added packet count to beginning of /proc/net/ipsec_eroute.
 *
 * Revision 1.11  2000/09/08 19:12:56  rgb
 * Change references from DEBUG_IPSEC to CONFIG_IPSEC_DEBUG.
 *
 * Revision 1.10  1999/11/17 15:53:39  rgb
 * Changed all occurrences of #include "../../../lib/freeswan.h"
 * to #include <freeswan.h> which works due to -Ilibfreeswan in the
 * klips/net/ipsec/Makefile.
 *
 * Revision 1.9  1999/10/01 00:01:23  rgb
 * Added eroute structure locking.
 *
 * Revision 1.8  1999/04/11 00:28:59  henry
 * GPL boilerplate
 *
 * Revision 1.7  1999/04/06 04:54:26  rgb
 * Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
 * patch shell fixes.
 *
 * Revision 1.6  1999/01/22 06:23:26  rgb
 * Cruft clean-out.
 *
 * Revision 1.5  1998/10/25 02:42:08  rgb
 * Change return type on ipsec_breakroute and ipsec_makeroute and add an
 * argument to be able to transmit more infomation about errors.
 *
 * Revision 1.4  1998/10/19 14:44:29  rgb
 * Added inclusion of freeswan.h.
 * sa_id structure implemented and used: now includes protocol.
 *
 * Revision 1.3  1998/07/28 00:03:31  rgb
 * Comment out temporary inet_nto4u() kluge.
 *
 * Revision 1.2  1998/07/14 18:22:00  rgb
 * Add function to clear the eroute table.
 *
 * Revision 1.1  1998/06/18 21:27:49  henry
 * move sources from klips/src to klips/net/ipsec, to keep stupid
 * kernel-build scripts happier in the presence of symlinks
 *
 * Revision 1.5  1998/05/25 20:30:38  rgb
 * Remove temporary ipsec_walk, rj_deltree and rj_delnodes functions.
 *
 * Rename ipsec_rj_walker (ipsec_walk) to ipsec_rj_walker_procprint and
 * add ipsec_rj_walker_delete.
 *
 * Revision 1.4  1998/05/21 13:02:56  rgb
 * Imported definitions from ipsec_radij.c and radij.c to support /proc 3k
 * limit fix.
 *
 * Revision 1.3  1998/04/21 21:29:09  rgb
 * Rearrange debug switches to change on the fly debug output from user
 * space.  Only kernel changes checked in at this time.  radij.c was also
 * changed to temporarily remove buggy debugging code in rj_delete causing
 * an OOPS and hence, netlink device open errors.
 *
 * Revision 1.2  1998/04/14 17:30:39  rgb
 * Fix up compiling errors for radij tree memory reclamation.
 *
 * Revision 1.1  1998/04/09 03:06:10  henry
 * sources moved up from linux/net/ipsec
 *
 * Revision 1.1.1.1  1998/04/08 05:35:04  henry
 * RGB's ipsec-0.8pre2.tar.gz ipsec-0.8
 *
 * Revision 0.4  1997/01/15 01:28:15  ji
 * No changes.
 *
 * Revision 0.3  1996/11/20 14:39:04  ji
 * Minor cleanups.
 * Rationalized debugging code.
 *
 * Revision 0.2  1996/11/02 00:18:33  ji
 * First limited release.
 *
 *
 */
