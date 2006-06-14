/* declarations of routines that interface with the kernel's pfkey mechanism
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2003  Herbert Xu
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
 * RCSID $Id: kernel_pfkey.h,v 1.1 2003/07/31 18:14:23 mcr Exp $
 */

#ifdef KLIPS
extern void init_pfkey(void);
extern void pfkey_register_proto(unsigned satype, const char *satypename);
extern void pfkey_close(void);

extern void klips_pfkey_register_response(const struct sadb_msg *msg);
extern void pfkey_dequeue(void);
extern void pfkey_event(void);
extern void klips_pfkey_register(void);
extern bool pfkey_add_sa(const struct kernel_sa *sa, bool replace);
extern bool pfkey_grp_sa(const struct kernel_sa *sa0, const struct kernel_sa *sa1);
extern bool pfkey_del_sa(const struct kernel_sa *sa);
extern bool pfkey_sag_eroute(struct state *st, struct spd_route *sr
			     , unsigned op, const char *opname);
extern bool pfkey_was_eroute_idle(struct state *st, time_t idle_max);
extern void pfkey_set_debug(int cur_debug
			    , openswan_keying_debug_func_t debug_func
			    , openswan_keying_debug_func_t error_func);
extern void pfkey_remove_orphaned_holds(int transport_proto
					, const ip_subnet *ours
					, const ip_subnet *his);

extern bool pfkey_raw_eroute(const ip_address *this_host
			     , const ip_subnet *this_client
			     , const ip_address *that_host
			     , const ip_subnet *that_client
			     , ipsec_spi_t spi
			     , unsigned int proto UNUSED
			     , unsigned int transport_proto
			     , unsigned int satype
			     , const struct pfkey_proto_info *proto_info UNUSED
			     , time_t use_lifetime UNUSED
			     , enum pluto_sadb_operations op
			     , const char *text_said);

extern bool pfkey_shunt_eroute(struct connection *c
			       , struct spd_route *sr
			       , enum routing_t rt_kind
			       , enum pluto_sadb_operations op, const char *opname);

extern int pfkeyfd;

#endif
