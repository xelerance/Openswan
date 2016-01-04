/* how to arrange connections: which end am I?
 * Copyright (C) 2015 Michael Richardson <mcr@xelerance.com>
 *
 * based upon ../../programs/pluto/initiate.c
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
#include "pluto/connections.h"	/* needs id.h */

static void swap_ends(struct spd_route *sr)
{
    struct end t = sr->this;

    sr->this = sr->that;
    sr->that = t;
}



static bool osw_end_has_private_key(struct end *him)
{
    if(him->cert.type != CERT_NONE) {
        return osw_asymmetric_key(him->cert)
            && osw_has_private_key(pluto_secrets, him->cert);
    } else {
        /* in raw RSA case, the end has a name, and the key is associated with the name. */
        struct pubkey * himkey = osw_get_public_key_by_end(him);

        if(himkey) {
            return has_private_rawkey(himkey);
        } else {
            return FALSE;
        }
    }
}


bool
orient(struct connection *c, unsigned int pluto_port)
{
    struct spd_route *sr;

    if (!oriented(*c))
    {
	struct iface_port *p;

	for (sr = &c->spd; sr; sr = sr->next)
	{
	    /* There can be more then 1 spd policy associated - required
	     * for cisco split networking when remote_peer_type=cisco
	     */
	    if(c->remotepeertype == CISCO && sr != &c->spd ) continue;

	    /* Note: this loop does not stop when it finds a match:
	     * it continues checking to catch any ambiguity.
	     */
	    for (p = interfaces; p != NULL; p = p->next)
	    {
                DBG(DBG_CONTROLMORE, DBG_log("orient %s checking against if: %s", c->name, p->ip_dev->id_rname));
#ifdef NAT_TRAVERSAL
		if (p->ike_float) continue;
#endif

#ifdef HAVE_LABELED_IPSEC
		if (c->loopback && sameaddr(&sr->this.host_addr, &p->ip_addr)) {
		DBG(DBG_CONTROLMORE,
			DBG_log("loopback connections \"%s\" with interface %s!"
			 , c->name, p->ip_dev->id_rname));
			c->interface = p;
                        c->ip_oriented = TRUE;
			break;
		}
#endif

		for (;;)
		{
		    /* check if this interface matches this end */
		    if (sameaddr(&sr->this.host_addr, &p->ip_addr)
			&& (kern_interface != NO_KERNEL
			    || sr->this.host_port == pluto_port))
		    {
			if (oriented(*c))
			{
			    if (c->interface->ip_dev == p->ip_dev)
				loglog(RC_LOG_SERIOUS
				       , "both sides of \"%s\" are our interface %s!"
				       , c->name, p->ip_dev->id_rname);
			    else
				loglog(RC_LOG_SERIOUS, "two interfaces match \"%s\" (%s, %s)"
				       , c->name, c->interface->ip_dev->id_rname, p->ip_dev->id_rname);
			    terminate_connection(c->name);
			    c->interface = NULL;	/* withdraw orientation */
			    return FALSE;
			}
			c->interface = p;
                        c->ip_oriented = TRUE;
		    }

		    /* done with this interface if it doesn't match that end */
		    if (!(sameaddr(&sr->that.host_addr, &p->ip_addr)
			  && (kern_interface!=NO_KERNEL
			      || sr->that.host_port == pluto_port)))
			break;

		    /* swap ends and try again.
		     * It is a little tricky to see that this loop will stop.
		     * Only continue if the far side matches.
		     * If both sides match, there is an error-out.
		     */
                    swap_ends(sr);
		}
	    }

            if(!oriented(*c)) {
                DBG(DBG_CONTROLMORE, DBG_log("orient %s matching on public/private keys", c->name));

                /* if %any, then check if we have a matching private key! */
                if((sr->this.host_type == KH_DEFAULTROUTE
                    || sr->this.host_type == KH_ANY)
                   && osw_end_has_private_key(&sr->this)) {
                    /*
                     * orientated is determined by selecting an interface,
                     * and this will pick first interface in the list...
                     * want to pick wildcard outgoing interface.
                     */
                    c->interface = interfaces;
                    c->ip_oriented = FALSE;

                } else if((sr->that.host_type == KH_DEFAULTROUTE
                           || sr->that.host_type == KH_ANY)
                          && osw_end_has_private_key(&sr->that)) {
                    swap_ends(sr);

                    c->interface = interfaces;
                    c->ip_oriented = FALSE;

                } else if(!osw_end_has_private_key(&sr->that)
                          && sr->this.host_type==KH_DEFAULTROUTE) {
                    /* if still not oriented, then look for an end
                     * that hasn't a key, but which hasn't a private key,
                     * and defaultroute */

                    c->interface = interfaces;
                    c->ip_oriented = FALSE;

                } else if(!osw_end_has_private_key(&sr->this)
                          && sr->that.host_type==KH_DEFAULTROUTE) {
                    /* if still not oriented, then look for an end that
                     * hasn't a key, but which hasn't a private key,
                     and defaultroute */

                    swap_ends(sr);

                    c->interface = interfaces;
                    c->ip_oriented = FALSE;
                }
            }
        }
    }

    return oriented(*c);
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
