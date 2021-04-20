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
 */

#include "kernel_alg.h"  /* for kernel_alg_info */

#if defined(linux) && defined(NETKEY_SUPPORT)
extern const struct kernel_ops netkey_kernel_ops;
extern sparse_names xfrm_type_names;

extern void linux_pfkey_register_response(const struct sadb_msg *msg);
extern void netlink_process_msg(void);
extern bool netlink_raw_eroute(const ip_address *this_host
		   , const ip_subnet *this_client
		   , const ip_address *that_host
		   , const ip_subnet *that_client
		   , ipsec_spi_t spi
		   , unsigned int proto
		   , unsigned int transport_proto
		   , enum eroute_type esatype
		   , const struct pfkey_proto_info *proto_info
		   , time_t use_lifetime UNUSED
		   , enum pluto_sadb_operations sadb_op
		   , const char *text_said
		   , char *policy_label
                   , uint32_t vti_mark
                   , uint32_t vti_markmask
		   );

extern bool netlink_add_sa(struct kernel_sa *sa, bool replace);
extern bool netlink_get_sa(const struct kernel_sa *sa, u_int *bytes);
extern bool netlink_del_sa(const struct kernel_sa *sa);

extern ipsec_spi_t netlink_get_spi(const ip_address *src
                                   , const ip_address *dst
                                   , int proto
                                   , bool tunnel_mode
                                   , unsigned reqid
                                   , ipsec_spi_t min
                                   , ipsec_spi_t max
                                   , const char *text_said);

extern void netlink_process_raw_ifaces(struct raw_iface *rifaces);
extern bool netlink_shunt_eroute(struct connection *c
                                 , const struct spd_route *sr
                                 , enum routing_t rt_kind
                                 , enum pluto_sadb_operations op
                                 , const char *opname);
extern bool netlink_sag_eroute(struct state *st, const struct spd_route *sr
                               , unsigned op, const char *opname);
extern bool netlink_eroute_idle(struct state *st, time_t idle_max);

extern void xfrm_kernel_alg_add(struct kernel_alg_info *kai);
extern struct kernel_alg_info *xfrm_kernel_alg_find(enum ikev2_trans_type alg_type
                                                    , u_int32_t trans_num);

extern void xfrm_init_base_algorithms(void);


#endif
