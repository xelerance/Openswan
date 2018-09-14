/* routines to manipulate a struct iface_port.
 *
 * Copyright (C) 2016 Michael Richardson <mcr@xelerance.com>
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
 */

#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>
#include "openswan/pfkeyv2.h"

#include "sysdep.h"
#include "constants.h"
#include "oswalloc.h"
#include "oswtime.h"
#include "oswlog.h"
#include "pluto/keys.h"

#include "pluto/server.h"

void init_iface_port(struct iface_port *q)
{
  const struct af_info *afi = aftoinfo(addrtypeof(&q->ip_addr));

  sin_addrtot(&q->ip_addr, 0, q->addrname, sizeof(q->addrname));
  q->socktypename = afi->name;

  switch(q->ip_addr.u.v4.sin_family) {
  case AF_INET6:
    q->ip_addr.u.v4.sin_port  = htons(q->port);
    break;

  default:
  case AF_INET:
    q->ip_addr.u.v6.sin6_port = htons(q->port);
    break;
  }
}


