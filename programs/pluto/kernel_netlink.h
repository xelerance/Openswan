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

#ifndef _KERNEL_FORCES_H

#include "kernel_forces.h"

extern bool send_netlink_msg(struct nlmsghdr *hdr, struct nlmsghdr *rbuf, size_t rbuf_len
                             , const char *description, const char *text_said);

extern bool netlink_policy(struct nlmsghdr *hdr, bool enoent_ok, const char *text_said);
extern bool netlink_get(void);
extern void netlink_process_msg(void);
extern bool netkey_do_command(struct connection *c, const struct spd_route *sr
                              , const char *verb, const char *verb_suffix
                              , struct state *st);

extern void netlink_acquire(struct nlmsghdr *n);
extern void netlink_policy_expire(struct nlmsghdr *n);
extern void init_netlink(void);
extern void linux_pfkey_register(void);

extern int netlink_bcast_fd;

#ifndef DEFAULT_UPDOWN
# define DEFAULT_UPDOWN "ipsec _updown"
#endif


#define _KERNEL_FORCES_H
#endif
