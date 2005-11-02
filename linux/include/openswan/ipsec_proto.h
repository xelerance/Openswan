/*
 * @(#) prototypes for FreeSWAN functions 
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
 * RCSID $Id: ipsec_proto.h,v 1.9 2004/07/10 19:08:41 mcr Exp $
 *
 */

#ifndef _IPSEC_PROTO_H_

#include "ipsec_param.h"

/* 
 * This file is a kernel only file that declares prototypes for
 * all intra-module function calls and global data structures.
 *
 * Include this file last.
 *
 */

/* ipsec_init.c */
extern struct prng ipsec_prng;

/* ipsec_sa.c */
extern struct ipsec_sa *ipsec_sadb_hash[SADB_HASHMOD];
extern spinlock_t       tdb_lock;
extern int ipsec_sadb_init(void);

extern struct ipsec_sa *ipsec_sa_getbyid(ip_said *);
extern int ipsec_sa_put(struct ipsec_sa *);
extern /* void */ int ipsec_sa_del(struct ipsec_sa *);
extern /* void */ int ipsec_sa_delchain(struct ipsec_sa *);
extern /* void */ int ipsec_sa_add(struct ipsec_sa *);

extern int ipsec_sadb_cleanup(__u8);
extern int ipsec_sa_wipe(struct ipsec_sa *);

/* debug declarations */

/* ipsec_proc.c */
extern int  ipsec_proc_init(void);
extern void ipsec_proc_cleanup(void);

/* ipsec_radij.c */
extern int ipsec_makeroute(struct sockaddr_encap *ea,
			   struct sockaddr_encap *em,
			   ip_said said,
			   uint32_t pid,
			   struct sk_buff *skb,
			   struct ident *ident_s,
			   struct ident *ident_d);

extern int ipsec_breakroute(struct sockaddr_encap *ea,
			    struct sockaddr_encap *em,
			    struct sk_buff **first,
			    struct sk_buff **last);

int ipsec_radijinit(void);
int ipsec_cleareroutes(void);
int ipsec_radijcleanup(void);

/* ipsec_life.c */
extern enum ipsec_life_alive ipsec_lifetime_check(struct ipsec_lifetime64 *il64,
						  const char *lifename,
						  const char *saname,
						  enum ipsec_life_type ilt,
						  enum ipsec_direction idir,
						  struct ipsec_sa *ips);


extern int ipsec_lifetime_format(char *buffer,
				 int   buflen,
				 char *lifename,
				 enum ipsec_life_type timebaselife,
				 struct ipsec_lifetime64 *lifetime);

extern void ipsec_lifetime_update_hard(struct ipsec_lifetime64 *lifetime,
				       __u64 newvalue);

extern void ipsec_lifetime_update_soft(struct ipsec_lifetime64 *lifetime,
				       __u64 newvalue);




#ifdef CONFIG_KLIPS_DEBUG

extern int debug_xform;
extern int debug_eroute;
extern int debug_spi;
extern int debug_netlink;

#endif /* CONFIG_KLIPS_DEBUG */




#define _IPSEC_PROTO_H
#endif /* _IPSEC_PROTO_H_ */

/*
 * $Log: ipsec_proto.h,v $
 * Revision 1.9  2004/07/10 19:08:41  mcr
 * 	CONFIG_IPSEC -> CONFIG_KLIPS.
 *
 * Revision 1.8  2004/04/05 19:55:06  mcr
 * Moved from linux/include/freeswan/ipsec_proto.h,v
 *
 * Revision 1.7  2003/10/31 02:27:05  mcr
 * 	pulled up port-selector patches and sa_id elimination.
 *
 * Revision 1.6.30.1  2003/10/29 01:10:19  mcr
 * 	elimited "struct sa_id"
 *
 * Revision 1.6  2002/05/23 07:13:48  rgb
 * Added ipsec_sa_put() for releasing an ipsec_sa refcount.
 *
 * Revision 1.5  2002/05/14 02:36:40  rgb
 * Converted reference from ipsec_sa_put to ipsec_sa_add to avoid confusion
 * with "put" usage in the kernel.
 *
 * Revision 1.4  2002/04/24 07:36:47  mcr
 * Moved from ./klips/net/ipsec/ipsec_proto.h,v
 *
 * Revision 1.3  2002/04/20 00:12:25  rgb
 * Added esp IV CBC attack fix, disabled.
 *
 * Revision 1.2  2001/11/26 09:16:15  rgb
 * Merge MCR's ipsec_sa, eroute, proc and struct lifetime changes.
 *
 * Revision 1.1.2.1  2001/09/25 02:21:01  mcr
 * 	ipsec_proto.h created to keep prototypes rather than deal with
 * 	cyclic dependancies of structures and prototypes in .h files.
 *
 *
 *
 * Local variables:
 * c-file-style: "linux"
 * End:
 *
 */

