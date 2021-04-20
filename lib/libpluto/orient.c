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
#include "oswconf.h"
#include "pluto/keys.h"

#include "pluto/server.h"
#include "pluto/connections.h"	/* needs id.h */

/*
 * this variable is set in production pluto when using
 * kern_interface == NO_KERNEL,  but must remain unset
 * at other times, including regression testing.
 *
 */
static void swap_ends(struct spd_route *sr)
{
    struct end t = sr->this;

    sr->this = sr->that;
    sr->that = t;
}

/*
 * pick the next matching interface in the list, starting at iflist.
 * iflist is always "interfaces" here, but other calls will resume the
 * search from the previously returned value.
 */
struct iface_port *pick_matching_interfacebyfamily(struct iface_port *iflist,
                                                   int pluto_port,
                                                   int family, struct spd_route *sr)
{
    struct iface_port *ifp = NULL;
    struct end        *e1  = &sr->this;
    const struct af_info *afi;
    unsigned int       desired_port;
    int family1= sr->this.host_addr.u.v4.sin_family;
    int family2= sr->that.host_addr.u.v4.sin_family;
    struct iface_port *best_ifp;
    unsigned int       best_score;

    switch(family) {
    case AF_INET6:
        desired_port = e1->host_addr.u.v6.sin6_port;
        break;

    default:
    case AF_INET:
        desired_port = e1->host_addr.u.v4.sin_port;
        break;
    }
    if(desired_port == 0) desired_port = pluto_port;

    if(family == 0) {
        family = family1 ? family1 : family2;
    }
    afi = aftoinfo(family);
    if(family1 == 0) {
        e1 = &sr->that;
    }

    best_ifp = NULL;
    best_score = 0;

    DBG(DBG_CONTROLMORE,
        DBG_log("pick_if looking for port: %u, family: %u",
                desired_port, family));

    for(ifp = iflist; ifp != NULL; ifp = ifp->next) {
        int score = 0;

        DBG(DBG_CONTROLMORE,
            DBG_log("  considering %s %s port: %u, family: %u, best: %s/%u %d",
                    ifp->ip_dev->id_rname, ifp->addrname,
                    ifp->port, ifp->ip_addr.u.v4.sin_family,
                    best_ifp ? best_ifp->ip_dev->id_rname : "<none>",
                    best_score,
                    isloopbackaddr(&iflist->ip_addr)));

        /* the port must always match, not a best case */
        if(ifp->port != desired_port) continue;

        /* the family MUST match, unless it is zero */
        if(ifp->ip_addr.u.v4.sin_family != family && family !=0) continue;

        /* if family==0, then give this us 10 points if this IF if
         * INET4, and 20 points if this IF is INET6
         */
        switch(ifp->ip_addr.u.v4.sin_family) {
        case AF_INET:
            score = 10;

            /* if the IF is *not* a loopback device, take another 10 points */
            if(!isloopbackaddr(&ifp->ip_addr)) {
                score += 10;
            }

            /* if the IF interface address matches the the IP address directly, then
             * take another 20 points.
             */
#if 0
            DBG_log("%08x vs %08x",
                    ntohl(ifp->ip_addr.u.v4.sin_addr.s_addr), ntohl(e1->host_addr.u.v4.sin_addr.s_addr));
#endif

            if(ifp->ip_addr.u.v4.sin_addr.s_addr ==  e1->host_addr.u.v4.sin_addr.s_addr && e1->host_addr.u.v4.sin_addr.s_addr != 0) {
                score += 20;
            }
            break;

        case AF_INET6:
            /* if the IF is *not* a loopback device, take another 10 points */
            if(!isloopbackaddr(&ifp->ip_addr)) {
                score += 10;
            }

            /* if the IF is *not* a ULA, then take another 10 points */
            if((ifp->ip_addr.u.v6.sin6_addr.s6_addr[0] & 0xfe) != 0xfc)
                score += 10;

            /*
             * if the IF interface address exactly matches the the IP address directly, then
             * take another 128 points: so has to be bigger than 10+10 above.
             */
            if(memcmp(&ifp->ip_addr.u.v6.sin6_addr, &e1->host_addr.u.v6.sin6_addr, 16)==0) {
                score += 128;
            }

            /* partial matches on IPv6 might be worth while too? */

        }

        if(score > best_score) {
            best_ifp = ifp;
            best_score = score;
        }
    }

    DBG(DBG_CONTROLMORE,
        DBG_log("  picking maching interface for family[%u,%u]: %s resulted in: %s"
                , family, family2
                , afi ? afi->name : "<family:0>", best_ifp ? best_ifp->addrname : "none"));

    return best_ifp;
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
    bool result;
    unsigned int family = c->end_addr_family;
    const struct osw_conf_options *oco = osw_init_options();

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
                DBG(DBG_CONTROLMORE, DBG_log("orient %s checking against if: %s (%s:%s:%u)", c->name, p->ip_dev->id_rname, p->socktypename, p->addrname, p->port));
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
			&& (oco->orient_same_addr_ok
                            || sr->this.host_port == p->port))
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
                        DBG(DBG_CONTROLMORE,
                            DBG_log("    orient matched on IP"));
		    }

		    /* done with this interface if it doesn't match that end */
		    if (!(sameaddr(&sr->that.host_addr, &p->ip_addr)
			  && (oco->orient_same_addr_ok
			      || sr->that.host_port == p->port)))
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
                bool this_has_private_key = osw_end_has_private_key(&sr->this);
                bool that_has_private_key = osw_end_has_private_key(&sr->that);
                char thishosttype[KEYWORD_NAME_BUFLEN];
                char thathosttype[KEYWORD_NAME_BUFLEN];
                DBG(DBG_CONTROLMORE,
                    DBG_log("orient %s matching on public/private keys: this=%s[%s] that=%s[%s]"
                            , c->name
                            , this_has_private_key ? "yes" : "no"
                            , keyword_name(&kw_host_list, sr->this.host_type, thishosttype)
                            , that_has_private_key ? "yes" : "no"
                            , keyword_name(&kw_host_list, sr->that.host_type, thathosttype)));



                /* if %any, then check if we have a matching private key! */
                if((sr->this.host_type == KH_DEFAULTROUTE
                    || sr->this.host_type == KH_ANY)
                   && this_has_private_key) {
                    /*
                     * orientated is determined by selecting an interface,
                     * and this will pick first interface in the list...
                     * want to pick wildcard outgoing interface.
                     */
                    DBG(DBG_CONTROLMORE,
                        DBG_log("  orient %s matched on this having private key", c->name));

                    /* take the family from the other end */
                    c->interface   = pick_matching_interfacebyfamily(interfaces, pluto_port, family, sr);
                    c->ip_oriented = FALSE;

                } else if((sr->that.host_type == KH_DEFAULTROUTE
                           || sr->that.host_type == KH_ANY)
                          && that_has_private_key) {

                    DBG(DBG_CONTROLMORE,
                        DBG_log("  orient %s matched on that having private key", c->name));

                    swap_ends(sr);

                    c->interface   = pick_matching_interfacebyfamily(interfaces, pluto_port, family, sr);
                    c->ip_oriented = FALSE;

                } else if(!that_has_private_key
                          && sr->this.host_type==KH_DEFAULTROUTE) {
                    /* if still not oriented, then look for an end
                     * that hasn't a key, but which hasn't a private key,
                     * and defaultroute */

                    DBG(DBG_CONTROLMORE,
                        DBG_log("  orient %s matched on this being defaultroute, and that lacking private key", c->name));

                    c->interface   = pick_matching_interfacebyfamily(interfaces, pluto_port, family, sr);
                    c->ip_oriented = FALSE;

                } else if(!this_has_private_key
                          && sr->that.host_type==KH_DEFAULTROUTE) {
                    /* if still not oriented, then look for an end that
                     * hasn't a key, but which hasn't a private key,
                     and defaultroute */

                    DBG(DBG_CONTROLMORE,
                        DBG_log("  orient %s matched on that being defaultroute, and this lacking private key", c->name));
                    swap_ends(sr);

                    c->interface   = pick_matching_interfacebyfamily(interfaces, pluto_port, family, sr);
                    c->ip_oriented = FALSE;
                }
            }
        }
    }

    result = oriented(*c);
    DBG(DBG_CONTROLMORE, DBG_log("  orient %s finished with: %u [%s]"
                                 , c->name, result, c->interface ? c->interface->addrname : "none"));

    return result;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
