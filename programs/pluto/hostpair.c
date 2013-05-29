/* information about connections between hosts and clients
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2008-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
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
#include "kameipsec.h"

#include "sysdep.h"
#include "constants.h"
#include "oswalloc.h"
#include "oswtime.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "secrets.h"

#include "defs.h"
#include "ac.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "connections.h"	/* needs id.h */
#include "pending.h"
#include "foodgroups.h"
#include "packet.h"
#include "demux.h"	/* needs packet.h */
#include "state.h"
#include "timer.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "server.h"
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "keys.h"
#include "adns.h"	/* needs <resolv.h> */
#include "dnskey.h"	/* needs keys.h and adns.h */
#include "whack.h"
#include "alg_info.h"
#include "spdb.h"
#include "ike_alg.h"
#include "plutocerts.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "xauth.h"
#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

#include "virtual.h"

#include "hostpair.h"

/* struct host_pair: a nexus of information about a pair of hosts.
 * A host is an IP address, UDP port pair.  This is a debatable choice:

 * - should port be considered (no choice of port in standard)?
 * - should ID be considered (hard because not always known)?
 * - should IP address matter on our end (we don't know our end)?
 * Only oriented connections are registered.
 * Unoriented connections are kept on the unoriented_connections
 * linked list (using hp_next).  For them, host_pair is NULL.
 */

struct host_pair *host_pairs = NULL;

void host_pair_enqueue_pending(const struct connection *c
			       , struct pending *p
			       , struct pending **pnext)
{
    *pnext = c->host_pair->pending;
    c->host_pair->pending = p;
}

struct pending **host_pair_first_pending(const struct connection *c)
{
    if(c->host_pair == NULL) return NULL;

    return &c->host_pair->pending;
}


/* check to see that Ids of peers match */
bool
same_peer_ids(const struct connection *c, const struct connection *d
, const struct id *his_id)
{
    return same_id(&c->spd.this.id, &d->spd.this.id)
	&& same_id(his_id == NULL? &c->spd.that.id : his_id, &d->spd.that.id);
}

/** returns a host pair based upon addresses.
 *
 * find_host_pair is given a pair of addresses, plus UDP ports, and
 * returns a host_pair entry that covers it. It also moves the relevant
 * pair description to the beginning of the list, so that it can be
 * found faster next time.
 *
 */
struct host_pair *
find_host_pair(const ip_address *myaddr
	       , u_int16_t myport
	       , const ip_address *hisaddr
	       , u_int16_t hisport)
{
    struct host_pair *p, *prev;

    /* default hisaddr to an appropriate any */
    if (hisaddr == NULL) {
#if 0
	/* broken */
	const struct af_info *af = aftoinfo(addrtypeof(myaddr));

	if(af == NULL) {
	    af = aftoinfo(AF_INET);
	}

	if(af) {
	    hisaddr = af->any;
	}
#else
	hisaddr = aftoinfo(addrtypeof(myaddr))->any;
#endif
    }

    /*
     * look for a host-pair that has the right set of ports/address.
     *
     */

    /*
     * for the purposes of comparison, port 500 and 4500 are identical,
     * but other ports are not.
     * So if any port==4500, then set it to 500.
     */
    if(myport == 4500) myport=500;
    if(hisport== 4500) hisport=500;

    for (prev = NULL, p = host_pairs; p != NULL; prev = p, p = p->next)
    {
	DBG(DBG_CONTROLMORE,
	    char b1[ADDRTOT_BUF];
	    char b2[ADDRTOT_BUF];
	    DBG_log("find_host_pair: comparing to %s:%d %s:%d\n"
		      , (addrtot(&p->me.addr, 0, b1, sizeof(b1)), b1)
		      , p->me.host_port
		      , (addrtot(&p->him.addr, 0, b2, sizeof(b2)), b2)
		      , p->him.host_port));

	if (sameaddr(&p->me.addr, myaddr)
	    && (!p->me.host_port_specific || p->me.host_port == myport)
	    && sameaddr(&p->him.addr, hisaddr)
	    && (!p->him.host_port_specific || p->him.host_port == hisport)
	    )
	{
	    if (prev != NULL)
	    {
		prev->next = p->next;	/* remove p from list */
		p->next = host_pairs;	/* and stick it on front */
		host_pairs = p;
	    }
	    break;
	}
    }
    return p;
}

void remove_host_pair(struct host_pair *hp)
{
    list_rm(struct host_pair, next, hp, host_pairs);
}

/* find head of list of connections with this pair of hosts */
struct connection *
find_host_pair_connections(const char *func
			   , const ip_address *myaddr, u_int16_t myport
			   , const ip_address *hisaddr, u_int16_t hisport)
{
    struct host_pair *hp = find_host_pair(myaddr, myport, hisaddr, hisport);

    DBG(DBG_CONTROLMORE,
	char b1[ADDRTOT_BUF];
	char b2[ADDRTOT_BUF];
	DBG_log("find_host_pair_conn (%s): %s:%d %s:%d -> hp:%s\n"
		  , func
		  , (addrtot(myaddr,  0, b1, sizeof(b1)), b1)
		  , myport
		  , hisaddr ? (addrtot(hisaddr, 0, b2, sizeof(b2)), b2) : "%any"
		  , hisport
		  , (hp && hp->connections) ? hp->connections->name : "none"));

    return hp == NULL? NULL : hp->connections;
}

void
connect_to_host_pair(struct connection *c)
{
    if (oriented(*c))
    {
	struct host_pair *hp = find_host_pair(&c->spd.this.host_addr
					      , c->spd.this.host_port
					      , &c->spd.that.host_addr
					      , c->spd.that.host_port);


	DBG(DBG_CONTROLMORE,
	    char b1[ADDRTOT_BUF];
	    char b2[ADDRTOT_BUF];
	    DBG_log("connect_to_host_pair: %s:%d %s:%d -> hp:%s\n"
		      , (addrtot(&c->spd.this.host_addr, 0, b1,sizeof(b1)), b1)
		      , c->spd.this.host_port
		      , (addrtot(&c->spd.that.host_addr, 0, b2,sizeof(b2)), b2)
		      , c->spd.that.host_port
		      , (hp && hp->connections) ? hp->connections->name : "none"));

	if (hp == NULL)
	{
	    /* no suitable host_pair -- build one */
	    hp = alloc_thing(struct host_pair, "host_pair");
	    hp->me.addr = c->spd.this.host_addr;
	    hp->him.addr = c->spd.that.host_addr;
#ifdef NAT_TRAVERSAL
	    hp->me.host_port = nat_traversal_enabled ? pluto_port : c->spd.this.host_port;
	    hp->him.host_port = nat_traversal_enabled ? pluto_port : c->spd.that.host_port;
#else
	    hp->me.host_port = c->spd.this.host_port;
 	    hp->him.host_port = c->spd.that.host_port;
#endif
	    hp->connections = NULL;
	    hp->pending = NULL;
	    hp->next = host_pairs;
	    host_pairs = hp;
	}
	c->host_pair = hp;
	c->hp_next = hp->connections;
	hp->connections = c;
    }
    else
    {
	/* since this connection isn't oriented, we place it
	 * in the unoriented_connections list instead.
	 */
	c->host_pair = NULL;
	c->hp_next = unoriented_connections;
	unoriented_connections = c;
    }
}

void
release_dead_interfaces(void)
{
    struct host_pair *hp;

    for (hp = host_pairs; hp != NULL; hp = hp->next)
    {
	struct connection **pp
	    , *p;

	for (pp = &hp->connections; (p = *pp) != NULL; )
	{
	    if (p->interface->change == IFN_DELETE)
	    {
		/* this connection's interface is going away */
		enum connection_kind k = p->kind;

		release_connection(p, TRUE);

		if (k <= CK_PERMANENT)
		{
		    /* The connection should have survived release:
		     * move it to the unoriented_connections list.
		     */
		    passert(p == *pp);
		    
		    terminate_connection(p->name);
		    p->interface = NULL;

		    *pp = p->hp_next;	/* advance *pp */
		    p->host_pair = NULL;
		    p->hp_next = unoriented_connections;
		    unoriented_connections = p;
		}
		else
		{
		    /* The connection should have vanished,
		     * but the previous connection remains.
		     */
		    passert(p != *pp);
		}
	    }
	    else
	    {
		pp = &p->hp_next;	/* advance pp */
	    }
	}
    }
}



/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
