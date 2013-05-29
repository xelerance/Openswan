/* routines that interface with the kernel's IPsec mechanism
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2010  D. Hugh Redelmeier.
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2009-2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2010 Avesh Agarwal <avagarwa@redhat.com>
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

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "sysdep.h"
#include "constants.h"
#include "oswlog.h"

#include "defs.h"
#include "rnd.h"
#include "id.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "timer.h"
#include "kernel.h"
#include "kernel_netlink.h"
#include "kernel_pfkey.h"
#include "kernel_noklips.h"
#include "kernel_bsdkame.h"
#include "packet.h"
#include "x509.h"
#include "log.h"
#include "server.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */
#include "keys.h"

#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif

#ifdef NAT_TRAVERSAL
#include "packet.h"  /* for pb_stream in nat_traversal.h */
#include "nat_traversal.h"
#endif

bool can_do_IPcomp = TRUE;  /* can system actually perform IPCOMP? */

/* test if the routes required for two different connections agree
 * It is assumed that the destination subnets agree; we are only
 * testing that the interfaces and nexthops match.
 */
#define routes_agree(c, d) ((c)->interface->ip_dev == (d)->interface->ip_dev \
        && sameaddr(&(c)->spd.this.host_nexthop, &(d)->spd.this.host_nexthop))

/* forward declaration */
static void set_text_said(char *text_said
                          , const ip_address *dst
                          , ipsec_spi_t spi
                          , int proto);

const struct pfkey_proto_info null_proto_info[2] = {
        {
                proto: IPPROTO_ESP,
                encapsulation: ENCAPSULATION_MODE_TRANSPORT,
                reqid: 0
        },
        {
                proto: 0,
                encapsulation: 0,
                reqid: 0
        }
};

static struct bare_shunt *bare_shunts = NULL;
#ifdef IPSEC_CONNECTION_LIMIT
static int num_ipsec_eroute = 0;
#endif

static void free_bare_shunt(struct bare_shunt **pp);

#ifdef DEBUG
void
DBG_bare_shunt_log(const char *op, const struct bare_shunt *bs)
{
    DBG(DBG_KLIPS,
        {
            int ourport = ntohs(portof(&(bs)->ours.addr));
            int hisport = ntohs(portof(&(bs)->his.addr));
            char ourst[SUBNETTOT_BUF];
            char hist[SUBNETTOT_BUF];
            char sat[SATOT_BUF];
            char prio[POLICY_PRIO_BUF];

            subnettot(&(bs)->ours, 0, ourst, sizeof(ourst));
            subnettot(&(bs)->his, 0, hist, sizeof(hist));
            satot(&(bs)->said, 0, sat, sizeof(sat));
            fmt_policy_prio(bs->policy_prio, prio);
            DBG_log("%s bare shunt %p %s:%d --%d--> %s:%d => %s %s    %s"
                , op, (const void *)(bs), ourst, ourport, (bs)->transport_proto, hist, hisport
                , sat, prio, (bs)->why);
        });
}
#endif

void
record_and_initiate_opportunistic(const ip_subnet *ours
                                  , const ip_subnet *his
                                  , int transport_proto
#ifdef HAVE_LABELED_IPSEC
                                  , struct xfrm_user_sec_ctx_ike *uctx
#endif
                                  , const char *why)
{
    passert(samesubnettype(ours, his));

    /* Add the kernel shunt to the pluto bare shunt list.
     * We need to do this because the shunt was installed by KLIPS
     * which can't do this itself.
     */
    {
        struct bare_shunt *bs = alloc_thing(struct bare_shunt, "bare shunt");

        bs->why = clone_str(why, "story for bare shunt");
        bs->ours = *ours;
        bs->his = *his;
        bs->transport_proto = transport_proto;
        bs->policy_prio = BOTTOM_PRIO;

        bs->said.proto = SA_INT;
        bs->said.spi = htonl(SPI_HOLD);
        bs->said.dst = *aftoinfo(subnettypeof(ours))->any;

        bs->count = 0;
        bs->last_activity = now();

        bs->next = bare_shunts;
        bare_shunts = bs;
        DBG_bare_shunt("add", bs);
    }

    /* actually initiate opportunism / ondemand */
    {
        ip_address src, dst;

        networkof(ours, &src);
        networkof(his, &dst);
        if (initiate_ondemand(&src, &dst, transport_proto
				, TRUE, NULL_FD,
#ifdef HAVE_LABELED_IPSEC
				uctx,
#endif
				"acquire") == 0) {
			/* if we didn't do any ondemand stuff the shunt is not needed */
			struct bare_shunt **bspp = bare_shunt_ptr(ours,his,transport_proto);
			if (bspp) {
				passert(*bspp == bare_shunts);
				free_bare_shunt(bspp);
			}
		}
    }

    pexpect(kernel_ops->remove_orphaned_holds != NULL);
    if(kernel_ops->remove_orphaned_holds) {
	(*kernel_ops->remove_orphaned_holds)(transport_proto, ours, his);
    }
}

static unsigned get_proto_reqid(unsigned base, int proto)
{
    switch (proto)
    {
    default:
    case IPPROTO_COMP:
        base++;
        /* fall through */
    case IPPROTO_ESP:
        base++;
        /* fall through */
    case IPPROTO_AH:
        break;
    }

    return base;
}

/* Generate Unique SPI numbers.
 *
 * The specs say that the number must not be less than IPSEC_DOI_SPI_MIN.
 * Pluto generates numbers not less than IPSEC_DOI_SPI_OUR_MIN,
 * reserving numbers in between for manual keying (but we cannot so
 * restrict numbers generated by our peer).
 * XXX This should be replaced by a call to the kernel when
 * XXX we get an API.
 * The returned SPI is in network byte order.
 * We use a random number as the initial SPI so that there is
 * a good chance that different Pluto instances will choose
 * different SPIs.  This is good for two reasons.
 * - the keying material for the initiator and responder only
 *   differs if the SPIs differ.
 * - if Pluto is restarted, it would otherwise recycle the SPI
 *   numbers and confuse everything.  When the kernel generates
 *   SPIs, this will no longer matter.
 * We then allocate numbers sequentially.  Thus we don't have to
 * check if the number was previously used (assuming that no
 * SPI lives longer than 4G of its successors).
 */
ipsec_spi_t
get_ipsec_spi(ipsec_spi_t avoid, int proto, struct spd_route *sr, bool tunnel)
{
    static ipsec_spi_t spi = 0; /* host order, so not returned directly! */
    char text_said[SATOT_BUF];

    set_text_said(text_said, &sr->this.host_addr, 0, proto);

    if (kernel_ops->get_spi)
        return kernel_ops->get_spi(&sr->that.host_addr
            , &sr->this.host_addr, proto, tunnel
            , get_proto_reqid(sr->reqid, proto)
            , IPSEC_DOI_SPI_OUR_MIN, 0xffffffff
            , text_said);

    spi++;
    while (spi < IPSEC_DOI_SPI_OUR_MIN || spi == ntohl(avoid))
        get_rnd_bytes((u_char *)&spi, sizeof(spi));

    DBG(DBG_CONTROL,
        {
            ipsec_spi_t spi_net = htonl(spi);

            DBG_dump("generate SPI:", (u_char *)&spi_net, sizeof(spi_net));
        });

    return htonl(spi);
}

/* Generate Unique CPI numbers.
 * The result is returned as an SPI (4 bytes) in network order!
 * The real bits are in the nework-low-order 2 bytes.
 * Modelled on get_ipsec_spi, but range is more limited:
 * 256-61439.
 * If we can't find one easily, return 0 (a bad SPI,
 * no matter what order) indicating failure.
 */
ipsec_spi_t
get_my_cpi(struct spd_route *sr, bool tunnel)
{
    static cpi_t
        first_busy_cpi = 0,
        latest_cpi;
    char text_said[SATOT_BUF];

    set_text_said(text_said, &sr->this.host_addr, 0, IPPROTO_COMP);

    if (kernel_ops->get_spi)
        return kernel_ops->get_spi(&sr->that.host_addr
            , &sr->this.host_addr, IPPROTO_COMP, tunnel
            , get_proto_reqid(sr->reqid, IPPROTO_COMP)
            , IPCOMP_FIRST_NEGOTIATED, IPCOMP_LAST_NEGOTIATED
            , text_said);

    while (!(IPCOMP_FIRST_NEGOTIATED <= first_busy_cpi && first_busy_cpi < IPCOMP_LAST_NEGOTIATED))
    {
        get_rnd_bytes((u_char *)&first_busy_cpi, sizeof(first_busy_cpi));
        latest_cpi = first_busy_cpi;
    }

    latest_cpi++;

    if (latest_cpi == first_busy_cpi)
        find_my_cpi_gap(&latest_cpi, &first_busy_cpi);

    if (latest_cpi > IPCOMP_LAST_NEGOTIATED)
        latest_cpi = IPCOMP_FIRST_NEGOTIATED;

    return htonl((ipsec_spi_t)latest_cpi);
}

/* form the command string */
int
fmt_common_shell_out(char *buf, int blen, struct connection *c
		     , struct spd_route *sr, struct state *st)
{
    int result;
    char
	me_str[ADDRTOT_BUF],
	myid_str2[IDTOA_BUF],
	srcip_str[ADDRTOT_BUF+sizeof("PLUTO_MY_SOURCEIP=")+4],
	myclient_str[SUBNETTOT_BUF],
	myclientnet_str[ADDRTOT_BUF],
	myclientmask_str[ADDRTOT_BUF],
	peer_str[ADDRTOT_BUF],
	peerid_str[IDTOA_BUF],
	metric_str[sizeof("PLUTO_METRIC")+5],
	connmtu_str[sizeof("PLUTO_MTU")+5],
	peerclient_str[SUBNETTOT_BUF],
	peerclientnet_str[ADDRTOT_BUF],
	peerclientmask_str[ADDRTOT_BUF],
	secure_myid_str[IDTOA_BUF] = "",
	secure_peerid_str[IDTOA_BUF] = "",
	secure_peerca_str[IDTOA_BUF] = "",
	nexthop_str[sizeof("PLUTO_NEXT_HOP='' ")+ADDRTOT_BUF],
	secure_xauth_username_str[IDTOA_BUF] = "";

    ip_address ta;

    nexthop_str[0]='\0';
    if(addrbytesptr(&sr->this.host_nexthop, NULL)
       && !isanyaddr(&sr->this.host_nexthop))
    {
	char *n;
	strcpy(nexthop_str, "PLUTO_NEXT_HOP='");
	n = nexthop_str + strlen(nexthop_str);
	addrtot(&sr->this.host_nexthop, 0,
		n, sizeof(nexthop_str)-strlen(nexthop_str));
	strncat(nexthop_str, "' ", sizeof(nexthop_str));
    }

    addrtot(&sr->this.host_addr, 0, me_str, sizeof(me_str));
    idtoa(&sr->this.id, myid_str2, sizeof(myid_str2));
    escape_metachar(myid_str2, secure_myid_str, sizeof(secure_myid_str));
    subnettot(&sr->this.client, 0, myclient_str, sizeof(myclientnet_str));
    networkof(&sr->this.client, &ta);
    addrtot(&ta, 0, myclientnet_str, sizeof(myclientnet_str));
    maskof(&sr->this.client, &ta);
    addrtot(&ta, 0, myclientmask_str, sizeof(myclientmask_str));

    addrtot(&sr->that.host_addr, 0, peer_str, sizeof(peer_str));
    idtoa(&sr->that.id, peerid_str, sizeof(peerid_str));
    escape_metachar(peerid_str, secure_peerid_str, sizeof(secure_peerid_str));
    subnettot(&sr->that.client, 0, peerclient_str, sizeof(peerclientnet_str));
    networkof(&sr->that.client, &ta);
    addrtot(&ta, 0, peerclientnet_str, sizeof(peerclientnet_str));
    maskof(&sr->that.client, &ta);
    addrtot(&ta, 0, peerclientmask_str, sizeof(peerclientmask_str));

    metric_str[0]='\0';
    if (c->metric)
    	snprintf(metric_str, sizeof(metric_str), "PLUTO_METRIC=%d", c->metric);

    connmtu_str[0]='\0';
    if (c->connmtu)
    	snprintf(connmtu_str, sizeof(connmtu_str), "PLUTO_MTU=%d", c->connmtu);

    secure_xauth_username_str[0]='\0';
    if (st != NULL && st->st_xauth_username) {
	size_t len;
	strcpy(secure_xauth_username_str, "PLUTO_XAUTH_USERNAME='");

	len = strlen(secure_xauth_username_str);
	remove_metachar((unsigned char *)st->st_xauth_username
			,secure_xauth_username_str+len
			,sizeof(secure_xauth_username_str)-(len+2));
	strncat(secure_xauth_username_str, "'", sizeof(secure_xauth_username_str)-1);
    }

    srcip_str[0]='\0';
    if(addrbytesptr(&sr->this.host_srcip, NULL) != 0
       && !isanyaddr(&sr->this.host_srcip))
    {
	char *p;
	int   l;
	strncat(srcip_str, "PLUTO_MY_SOURCEIP=", sizeof(srcip_str));
	strncat(srcip_str, "'", sizeof(srcip_str)-strlen(srcip_str)-1);
	l = strlen(srcip_str);
	p = srcip_str + l;

	addrtot(&sr->this.host_srcip, 0, p, sizeof(srcip_str));
	strncat(srcip_str, "'", sizeof(srcip_str)-strlen(srcip_str)-1);
    }

    {
	struct pubkey_list *p;
	char peerca_str[IDTOA_BUF];

	for (p = pluto_pubkeys; p != NULL; p = p->next)
	{
	    struct pubkey *key = p->key;
	    int pathlen;

	    if (key->alg == PUBKEY_ALG_RSA && same_id(&sr->that.id, &key->id)
		&& trusted_ca(key->issuer, sr->that.ca, &pathlen))
	    {
		dntoa_or_null(peerca_str, IDTOA_BUF, key->issuer, "");
		escape_metachar(peerca_str, secure_peerca_str, sizeof(secure_peerca_str));
		break;
	    }
	}
    }

    result = snprintf(buf, blen,
		    "PLUTO_VERSION='2.0' "  /* change VERSION when interface spec changes */
		    "PLUTO_CONNECTION='%s' "
		    "PLUTO_INTERFACE='%s' "
		    "%s"      /* possible PLUTO_NEXT_HOP */
		    "PLUTO_ME='%s' "
		    "PLUTO_MY_ID='%s' "
		    "PLUTO_MY_CLIENT='%s' "
		    "PLUTO_MY_CLIENT_NET='%s' "
		    "PLUTO_MY_CLIENT_MASK='%s' "
		    "PLUTO_MY_PORT='%u' "
		    "PLUTO_MY_PROTOCOL='%u' "
		    "PLUTO_PEER='%s' "
		    "PLUTO_PEER_ID='%s' "
		    "PLUTO_PEER_CLIENT='%s' "
		    "PLUTO_PEER_CLIENT_NET='%s' "
		    "PLUTO_PEER_CLIENT_MASK='%s' "
		    "PLUTO_PEER_PORT='%u' "
		    "PLUTO_PEER_PROTOCOL='%u' "
		    "PLUTO_PEER_CA='%s' "
		    "PLUTO_STACK='%s' "
		    "%s "           /* optional metric */
		    "%s "           /* optional mtu */
		    "PLUTO_CONN_POLICY='%s' "
		    "PLUTO_CONN_ADDRFAMILY='ipv%d' "
#ifdef XAUTH
		    "%s "           /* XAUTH username - if any */
#endif
		    "%s "           /* PLUTO_MY_SRCIP - if any */
#ifdef XAUTH
		    "PLUTO_IS_PEER_CISCO='%u' "
		    "PLUTO_CISCO_DNS_INFO='%s' "
		    "PLUTO_CISCO_DOMAIN_INFO='%s' "
		    "PLUTO_PEER_BANNER='%s' "
#endif /* XAUTH */
#ifdef HAVE_NM
		    "PLUTO_NM_CONFIGURED='%u' "
#endif

		    , c->name
		    , c->interface->ip_dev->id_vname
		    , nexthop_str
		    , me_str
		    , secure_myid_str
		    , myclient_str
		    , myclientnet_str
		    , myclientmask_str
		    , sr->this.port
		    , sr->this.protocol
		    , peer_str
		    , secure_peerid_str
		    , peerclient_str
		    , peerclientnet_str
		    , peerclientmask_str
		    , sr->that.port
		    , sr->that.protocol
		    , secure_peerca_str
		    , kernel_ops->kern_name
		    , metric_str
		    , connmtu_str
		    , prettypolicy(c->policy)
		    , (c->addr_family == AF_INET) ? 4 : 6
#ifdef XAUTH
		    , secure_xauth_username_str
#endif
		    , srcip_str
#ifdef XAUTH
		    , c->remotepeertype
		    , c->cisco_dns_info ? c->cisco_dns_info : ""
		    , c->cisco_domain_info ? c->cisco_domain_info : ""
		    , c->cisco_banner ? c->cisco_banner : ""
#endif /* XAUTH */
#ifdef HAVE_NM
		    , c->nmconfigured
#endif
		);
	/*
	 * works for both old and new way of snprintf() returning
	 * eiter -1 or the output length  -- by Carsten Schlote
	 */
	return ((result>=blen) || (result<0))? -1 : result;
}

bool
do_command(struct connection *c, struct spd_route *sr, const char *verb, struct state *st)
{
    const char *verb_suffix;

    /* figure out which verb suffix applies for logging purposes */
    {
        const char *hs, *cs;

        switch (addrtypeof(&sr->this.host_addr))
        {
            case AF_INET:
                hs = "-host";
                cs = "-client";
                break;
            case AF_INET6:
                hs = "-host-v6";
                cs = "-client-v6";
                break;
            default:
                loglog(RC_LOG_SERIOUS, "unknown address family");
                return FALSE;
        }
        verb_suffix = subnetisaddr(&sr->this.client, &sr->this.host_addr)
            ? hs : cs;
    }

    DBG(DBG_CONTROL, DBG_log("command executing %s%s"
			     , verb, verb_suffix));

    if(kernel_ops->docommand != NULL) {
	return (*kernel_ops->docommand)(c,sr, verb, st);
    } else {
	DBG(DBG_CONTROL, DBG_log("no do_command for method %s"
				 , kernel_ops->kern_name));
    }
    return TRUE;
}


/* Check that we can route (and eroute).  Diagnose if we cannot. */

enum routability {
    route_impossible = 0,
    route_easy = 1,
    route_nearconflict = 2,
    route_farconflict = 3,
    route_unnecessary = 4
};

static enum routability
could_route(struct connection *c)
{
    struct spd_route *esr, *rosr;
    struct connection *ero      /* who, if anyone, owns our eroute? */
        , *ro = route_owner(c, &c->spd, &rosr, &ero, &esr); /* who owns our route? */

    DBG(DBG_CONTROL,
        DBG_log("could_route called for %s (kind=%s)"
                , c->name
                , enum_show(&connection_kind_names, c->kind)));

    /* it makes no sense to route a connection that is ISAKMP-only */
    if (!NEVER_NEGOTIATE(c->policy) && !HAS_IPSEC_POLICY(c->policy))
    {
        loglog(RC_ROUTE, "cannot route an ISAKMP-only connection");
        return route_impossible;
    }

    /*
     * if this is a transport SA, and overlapping SAs are supported, then
     * this route is not necessary at all.
     */
    if(kernel_ops->overlap_supported && !LIN(POLICY_TUNNEL, c->policy)) {
	return route_unnecessary;
    }

    /* if this is a Road Warrior template, we cannot route.
     * Opportunistic template is OK.
     */
    if (!c->spd.that.has_client
	&& c->kind == CK_TEMPLATE
	&& !(c->policy & POLICY_OPPO))
    {
        loglog(RC_ROUTE, "cannot route template policy of %s",
               prettypolicy(c->policy));
        return route_impossible;
    }

#if 0
    /* if we don't know nexthop, we cannot route */
    if (isanyaddr(&c->spd.this.host_nexthop))
    {
        loglog(RC_ROUTE, "cannot route connection without knowing our nexthop");
        return route_impossible;
    }
#endif

    /* if routing would affect IKE messages, reject */
    if (kern_interface != NO_KERNEL
#ifdef NAT_TRAVERSAL
	&& c->spd.this.host_port != NAT_T_IKE_FLOAT_PORT
#endif
	&& c->spd.this.host_port != IKE_UDP_PORT
	&& addrinsubnet(&c->spd.that.host_addr, &c->spd.that.client))
    {
        loglog(RC_LOG_SERIOUS, "cannot install route: peer is within its client");
        return route_impossible;
    }

    /* If there is already a route for peer's client subnet
     * and it disagrees about interface or nexthop, we cannot steal it.
     * Note: if this connection is already routed (perhaps for another
     * state object), the route will agree.
     * This is as it should be -- it will arise during rekeying.
     */
    if (ro != NULL && !routes_agree(ro, c))
    {
        loglog(RC_LOG_SERIOUS, "cannot route -- route already in use for \"%s\""
            , ro->name);
        /* We ignore this if the stack supports overlapping, and this
         * connection was marked that overlapping is OK.  Below we will
         * check the other eroute, ero. */
	if (!compatible_overlapping_connections(c, ero))
		return route_impossible;  /* another connection already using the
                                             eroute. TODO: NETKEY can do this? */
    }

    /* if there is an eroute for another connection, there is a problem */
    if (ero != NULL && ero != c)
    {
        struct connection *ero2;
        struct connection *inside, *outside;

        /*
         * note, wavesec (PERMANENT) goes *outside* and
         * OE goes *inside* (TEMPLATE)
         */
        inside = NULL;
        outside= NULL;
        if (ero->kind == CK_PERMANENT
           && c->kind == CK_TEMPLATE)
        {
            outside = ero;
            inside = c;
        }
        else if (c->kind == CK_PERMANENT
                && ero->kind == CK_TEMPLATE)
        {
            outside = c;
            inside = ero;
        }

        /* okay, check again, with correct order */
        if (outside && outside->kind == CK_PERMANENT
            && inside && inside->kind == CK_TEMPLATE)
        {
            char inst[CONN_INST_BUF];

            /* this is a co-terminal attempt of the "near" kind. */
            /* when chaining, we chain from inside to outside */

            /* XXX permit multiple deep connections? */
            passert(inside->policy_next == NULL);

            inside->policy_next = outside;

            /* since we are going to steal the eroute from the secondary
             * policy, we need to make sure that it no longer thinks that
             * it owns the eroute.
             */
            outside->spd.eroute_owner = SOS_NOBODY;
            outside->spd.routing = RT_UNROUTED_KEYED;

            /* set the priority of the new eroute owner to be higher
             * than that of the current eroute owner
             */
            inside->prio = outside->prio + 1;

            fmt_conn_instance(inside, inst);

            loglog(RC_LOG_SERIOUS
                   , "conflict on eroute (%s), switching eroute to %s and linking %s"
                   , inst, inside->name, outside->name);

            return route_nearconflict;
        }

        /* look along the chain of policies for one with the same name */


        for (ero2 = ero; ero2 != NULL; ero2 = ero->policy_next)
        {
            if (ero2->kind == CK_TEMPLATE
            && streq(ero2->name, c->name))
                break;
        }

        /* If we fell of the end of the list, then we found no TEMPLATE
         * so there must be a conflict that we can't resolve.
         * As the names are not equal, then we aren't replacing/rekeying.
         */
        if (ero2 == NULL)
        {
            char inst[CONN_INST_BUF];

            fmt_conn_instance(ero, inst);

            if(!LIN(POLICY_OVERLAPIP, c->policy)
                        || !LIN(POLICY_OVERLAPIP, ero->policy)) {
                    loglog(RC_LOG_SERIOUS
                        , "cannot install eroute -- it is in use for \"%s\"%s #%lu"
                        , ero->name, inst, esr->eroute_owner);
                    return FALSE;       /* another connection already using the eroute,
                                           TODO: NETKEY apparently can do this though */
            }

            DBG(DBG_CONTROL,
                DBG_log("overlapping permitted with \"%s\"%s #%lu"
                        , ero->name, inst, esr->eroute_owner));
        }
    }
    return route_easy;
}

bool
trap_connection(struct connection *c)
{
    switch (could_route(c))
    {
    case route_impossible:
        return FALSE;

    case route_nearconflict:
    case route_easy:
        /* RT_ROUTED_TUNNEL is treated specially: we don't override
         * because we don't want to lose track of the IPSEC_SAs etc.
         */
        if (c->spd.routing < RT_ROUTED_TUNNEL)
        {
            return route_and_eroute(c, &c->spd, NULL);
        }
        return TRUE;

    case route_farconflict:
        return FALSE;

    case route_unnecessary:
        return TRUE;
    }

    return FALSE;
}

static bool shunt_eroute(struct connection *c
		  , struct spd_route *sr
		  , enum routing_t rt_kind
		  , enum pluto_sadb_operations op
		  , const char *opname)
{
    if(kernel_ops->shunt_eroute) {
	return kernel_ops->shunt_eroute(c, sr, rt_kind, op, opname);
    }
    loglog(RC_COMMENT, "no shunt_eroute implemented for %s interface", kernel_ops->kern_name);
    return TRUE;
}

static bool sag_eroute(struct state *st
		  , struct spd_route *sr
		  , enum pluto_sadb_operations op
		  , const char *opname)
{
    pexpect(kernel_ops->sag_eroute != NULL);
    if(kernel_ops->sag_eroute) {
	return kernel_ops->sag_eroute(st, sr, op, opname);
    }
    return FALSE;
}


/* delete any eroute for a connection and unroute it if route isn't shared */
void
unroute_connection(struct connection *c)
{
    struct spd_route *sr;
    enum routing_t cr;

    for (sr = &c->spd; sr; sr = sr->next)
    {
        cr = sr->routing;

        if (erouted(cr))
        {
            /* cannot handle a live one */
            passert(sr->routing != RT_ROUTED_TUNNEL);
	    if(kernel_ops->shunt_eroute) {
		kernel_ops->shunt_eroute(c, sr, RT_UNROUTED
					 , ERO_DELETE, "delete");
	    }
	    else loglog(RC_COMMENT, "no shunt_eroute implemented for %s interface"
				, kernel_ops->kern_name);
#ifdef IPSEC_CONNECTION_LIMIT
	    num_ipsec_eroute--;
#endif
        }

        sr->routing = RT_UNROUTED;  /* do now so route_owner won't find us */

        /* only unroute if no other connection shares it */
        if (routed(cr) && route_owner(c, sr, NULL, NULL, NULL) == NULL)
            (void) do_command(c, sr, "unroute", NULL);
    }
}

#include "alg_info.h"
#include "kernel_alg.h"


static void
set_text_said(char *text_said, const ip_address *dst, ipsec_spi_t spi, int proto)
{
    ip_said said;

    initsaid(dst, spi, proto, &said);
    satot(&said, 0, text_said, SATOT_BUF);
}

/* find an entry in the bare_shunt table.
 * Trick: return a pointer to the pointer to the entry;
 * this allows the entry to be deleted.
 */
struct bare_shunt **
bare_shunt_ptr(const ip_subnet *ours, const ip_subnet *his, int transport_proto)
{
    struct bare_shunt *p, **pp;

    for (pp = &bare_shunts; (p = *pp) != NULL; pp = &p->next)
    {
        if (samesubnet(ours, &p->ours)
        && samesubnet(his, &p->his)
        && transport_proto == p->transport_proto
        && portof(&ours->addr) == portof(&p->ours.addr)
        && portof(&his->addr) == portof(&p->his.addr))
            return pp;
    }
    return NULL;
}

/* free a bare_shunt entry, given a pointer to the pointer */
static void
free_bare_shunt(struct bare_shunt **pp)
{
    if (pp == NULL)
    {
        DBG(DBG_CONTROL,
            DBG_log("delete bare shunt: null pointer")
        )
    }
    else
    {
        struct bare_shunt *p = *pp;

        *pp = p->next;
        DBG_bare_shunt("delete", p);
        pfree(p->why);
        pfree(p);
    }
}

void
show_shunt_status(void)
{
    struct bare_shunt *bs;

    for (bs = bare_shunts; bs != NULL; bs = bs->next)
    {
        /* Print interesting fields.  Ignore count and last_active. */

        int ourport = ntohs(portof(&bs->ours.addr));
        int hisport = ntohs(portof(&bs->his.addr));
        char ourst[SUBNETTOT_BUF];
        char hist[SUBNETTOT_BUF];
        char sat[SATOT_BUF];
        char prio[POLICY_PRIO_BUF];

        subnettot(&(bs)->ours, 0, ourst, sizeof(ourst));
        subnettot(&(bs)->his, 0, hist, sizeof(hist));
        satot(&(bs)->said, 0, sat, sizeof(sat));
        fmt_policy_prio(bs->policy_prio, prio);

        whack_log(RC_COMMENT, "%s:%d -%d-> %s:%d => %s %s    %s"
            , ourst, ourport, bs->transport_proto, hist, hisport, sat
            , prio, bs->why);
    }
}

/* Setup an IPsec route entry.
 * op is one of the ERO_* operators.
 */

static bool
raw_eroute(const ip_address *this_host
           , const ip_subnet *this_client
           , const ip_address *that_host
           , const ip_subnet *that_client
           , ipsec_spi_t spi
           , unsigned int proto
           , unsigned int transport_proto
           , enum eroute_type esatype
           , const struct pfkey_proto_info *proto_info
           , time_t use_lifetime
           , enum pluto_sadb_operations op
           , const char *opname USED_BY_DEBUG
#ifdef HAVE_LABELED_IPSEC
	   , char *policy_label
#endif
	   )
{
    char text_said[SATOT_BUF];
    bool result;

    set_text_said(text_said, that_host, spi, proto);

    DBG(DBG_CONTROL | DBG_KLIPS,
        {
            int sport = ntohs(portof(&this_client->addr));
            int dport = ntohs(portof(&that_client->addr));
            char mybuf[SUBNETTOT_BUF];
            char peerbuf[SUBNETTOT_BUF];

            subnettot(this_client, 0, mybuf, sizeof(mybuf));
            subnettot(that_client, 0, peerbuf, sizeof(peerbuf));
            DBG_log("%s eroute %s:%d --%d-> %s:%d => %s (raw_eroute)"
                    , opname, mybuf, sport, transport_proto, peerbuf, dport
                    , text_said);
#ifdef HAVE_LABELED_IPSEC
		if(policy_label) {
		DBG_log("policy security label %s", policy_label);
		}
#endif
        });

    result = kernel_ops->raw_eroute(this_host, this_client
                                  , that_host, that_client
                                  , spi, proto
                                  , transport_proto
                                  , esatype, proto_info
                                  , use_lifetime, op, text_said
#ifdef HAVE_LABELED_IPSEC
				  , policy_label
#endif
				  );

    if(result == FALSE || DBGP(DBG_CONTROL|DBG_KLIPS)) {
	   DBG_log("raw_eroute result=%u\n", result);
    }

    return result;
}

/* test to see if %hold remains */
bool
has_bare_hold(const ip_address *src, const ip_address *dst, int transport_proto)
{
    ip_subnet this_client, that_client;
    struct bare_shunt **bspp;

    passert(addrtypeof(src) == addrtypeof(dst));
    happy(addrtosubnet(src, &this_client));
    happy(addrtosubnet(dst, &that_client));
    bspp = bare_shunt_ptr(&this_client, &that_client, transport_proto);
    return bspp != NULL
        && (*bspp)->said.proto == SA_INT && (*bspp)->said.spi == htonl(SPI_HOLD);
}

/*
 * clear any bare shunt holds that overlap with the network we have just
 * routed
 */
static void
clear_narrow_holds(
    const ip_subnet *ours,
    const ip_subnet *his,
    int transport_proto)
{
    struct bare_shunt *p, **pp;

    for (pp = &bare_shunts; (p = *pp) != NULL; )
    {
	ip_subnet po, ph;

	/* for now we only care about host-host narrow holds specifically */
	if (p->ours.maskbits != 32 || p->his.maskbits != 32) {
	    pp = &p->next;
	    continue;
	}

	if (p->said.spi != htonl(SPI_HOLD)) {
	    pp = &p->next;
	    continue;
	}

	initsubnet(&p->ours.addr, ours->maskbits, '0', &po);
	initsubnet(&p->his.addr, his->maskbits, '0', &ph);

	if (samesubnet(ours, &po) && samesubnet(his, &ph)
		&& transport_proto == p->transport_proto
		&& portof(&ours->addr) == portof(&p->ours.addr)
		&& portof(&his->addr) == portof(&p->his.addr)) {

	    (void) replace_bare_shunt(&p->ours.addr, &p->his.addr
		    , BOTTOM_PRIO
		    , SPI_PASS	/* not used */
		    , FALSE, transport_proto
		    , "removing clashing narrow holds");

	    /* restart from beginning as we just removed and entry */
	    pp = &bare_shunts;
	    continue;
	}
	pp = &p->next;
    }
}

/* Replace (or delete) a shunt that is in the bare_shunts table.
 * Issues the PF_KEY commands and updates the bare_shunts table.
 */
bool
replace_bare_shunt(const ip_address *src, const ip_address *dst
                   , policy_prio_t policy_prio
                   , ipsec_spi_t shunt_spi      /* in host order! */
                   , bool repl  /* if TRUE, replace; if FALSE, delete */
                   , int transport_proto
                   , const char *why)
{
    ip_subnet this_client, that_client;
    const ip_address *null_host = aftoinfo(addrtypeof(src))->any;

    passert(addrtypeof(src) == addrtypeof(dst));
    happy(addrtosubnet(src, &this_client));
    happy(addrtosubnet(dst, &that_client));

    /*
     * if the transport protocol is not the wildcard, then we need
     * to look for a host<->host shunt, and replace that with the
     * shunt spi, and then we add a %HOLD for what was there before.
     *
     * this is at odds with repl == 0, which should delete things.
     *
     */

    if(transport_proto != 0) {
        ip_subnet this_broad_client, that_broad_client;

        this_broad_client = this_client;
        that_broad_client = that_client;
        setportof(0, &this_broad_client.addr);
        setportof(0, &that_broad_client.addr);

        if (repl)
            {
                struct bare_shunt **bs_pp = bare_shunt_ptr(&this_broad_client
                                                           , &that_broad_client, 0);

                /* is there already a broad host-to-host bare shunt? */
                if (bs_pp == NULL)
                    {
			DBG(DBG_KLIPS, DBG_log("replacing broad host-to-host bare shunt"));
                        if (raw_eroute(null_host, &this_broad_client
                                       , null_host, &that_broad_client
                                       , htonl(shunt_spi), SA_INT
                                       , transport_proto
                                       , ET_INT, null_proto_info
                                       , SHUNT_PATIENCE, ERO_REPLACE, why
#ifdef HAVE_LABELED_IPSEC
				       , NULL
#endif
				       ))
                            {
                                struct bare_shunt *bs = alloc_thing(struct bare_shunt, "bare shunt");

                                bs->ours = this_broad_client;
                                bs->his =  that_broad_client;
                                bs->transport_proto = transport_proto;
                                bs->said.proto = SA_INT;
                                bs->why = clone_str(why, "bare shunt story");
                                bs->policy_prio = policy_prio;
                                bs->said.spi = htonl(shunt_spi);
                                bs->said.dst = *null_host;
                                bs->count = 0;
                                bs->last_activity = now();
                                bs->next = bare_shunts;
                                bare_shunts = bs;
                                DBG_bare_shunt("add", bs);
                            }
                    }
                shunt_spi = SPI_HOLD;
            }

	DBG(DBG_KLIPS, DBG_log("adding specific host-to-host bare shunt"));
        if (raw_eroute(null_host, &this_client, null_host, &that_client
                       , htonl(shunt_spi)
                       , SA_INT
                       , transport_proto
                       , ET_INT, null_proto_info
                       , SHUNT_PATIENCE, ERO_ADD, why
#ifdef HAVE_LABELED_IPSEC
		       , NULL
#endif
		       ))
            {
                struct bare_shunt **bs_pp = bare_shunt_ptr(&this_client, &that_client
                                                           , transport_proto);

                /* delete bare eroute */
                free_bare_shunt(bs_pp);

                return TRUE;
            }
        else
            {
                return FALSE;
            }
    }
    else {
        unsigned int op = repl ? ERO_REPLACE : ERO_DELETE;

	DBG(DBG_KLIPS, DBG_log("%s specific host-to-host bare shunt", repl ? "replacing" : "removing"));
        if (raw_eroute(null_host, &this_client, null_host, &that_client
                       , htonl(shunt_spi), SA_INT
                       , 0 /* transport_proto */
                       , ET_INT, null_proto_info
                       , SHUNT_PATIENCE, op, why
#ifdef HAVE_LABELED_IPSEC
		       , NULL
#endif
		       ))
            {
                struct bare_shunt **bs_pp = bare_shunt_ptr(&this_client
                                                           , &that_client, 0);

		passert(bs_pp != NULL);
                if (repl)
                    {
                        /* change over to new bare eroute
			 * ours, his, transport_proto are the same.
			 */
                        struct bare_shunt *bs = *bs_pp;

                        pfree(bs->why);
                        bs->why = clone_str(why, "bare shunt story");
                        bs->policy_prio = policy_prio;
                        bs->said.spi = htonl(shunt_spi);
                        bs->said.proto = SA_INT;
                        bs->said.dst = *null_host;
                        bs->count = 0;
                        bs->last_activity = now();
                        DBG_bare_shunt("change", bs);
                    }
                else
                    {
                        /* delete bare eroute */
                        free_bare_shunt(bs_pp);
                    }
                return TRUE;
            }
        else
            {
                return FALSE;
            }
    }

}

bool eroute_connection(struct spd_route *sr
		       , ipsec_spi_t spi, unsigned int proto
		       , enum eroute_type esatype
		       , const struct pfkey_proto_info *proto_info
		       , unsigned int op, const char *opname
#ifdef HAVE_LABELED_IPSEC
		       , char *policy_label
#endif
		       )
{
    const ip_address *peer = &sr->that.host_addr;
    char buf2[256];

    snprintf(buf2, sizeof(buf2)
             , "eroute_connection %s", opname);

    if (proto == SA_INT)
        peer = aftoinfo(addrtypeof(peer))->any;

    return raw_eroute(&sr->this.host_addr, &sr->this.client
                      , peer
                      , &sr->that.client
                      , spi
                      , proto
                      , sr->this.protocol
                      , esatype
                      , proto_info, 0, op, buf2
#ifdef HAVE_LABELED_IPSEC
		      , policy_label
#endif
		      );
}

/* assign a bare hold to a connection */

bool
assign_hold(struct connection *c USED_BY_DEBUG
            , struct spd_route *sr
            , int transport_proto
            , const ip_address *src, const ip_address *dst)
{
    /* either the automatically installed %hold eroute is broad enough
     * or we try to add a broader one and delete the automatic one.
     * Beware: this %hold might be already handled, but still squeak
     * through because of a race.
     */
    enum routing_t ro = sr->routing     /* routing, old */
        , rn = ro;                      /* routing, new */

    passert(LHAS(LELEM(CK_PERMANENT) | LELEM(CK_INSTANCE), c->kind));
    /* figure out what routing should become */
    switch (ro)
    {
    case RT_UNROUTED:
        rn = RT_UNROUTED_HOLD;
        break;
    case RT_ROUTED_PROSPECTIVE:
        rn = RT_ROUTED_HOLD;
        break;
    default:
        /* no change: this %hold is old news and should just be deleted */
        break;
    }

    DBG(DBG_CONTROL,
        DBG_log("assign hold, routing was %s, needs to be %s"
                , enum_name(&routing_story, ro)
                , enum_name(&routing_story, rn)));

    if (eclipsable(sr))
    {
        /* although %hold is appropriately broad, it will no longer be bare
         * so we must ditch it from the bare table.
         */
        free_bare_shunt(bare_shunt_ptr(&sr->this.client, &sr->that.client, sr->this.protocol));
    }
    else
    {
        /* we need a broad %hold, not the narrow one.
         * First we ensure that there is a broad %hold.
         * There may already be one (race condition): no need to create one.
         * There may already be a %trap: replace it.
         * There may not be any broad eroute: add %hold.
         * Once the broad %hold is in place, delete the narrow one.
         */
        if (rn != ro)
        {
	    int op;
	    const char *reason;

	    if(erouted(ro)) {
		op = ERO_REPLACE;
		reason= "replace %trap with broad %hold";
	    } else {
		op = ERO_ADD;
		reason= "add broad %hold";
	    }

            if(!eroute_connection(sr, htonl(SPI_HOLD)
				  , SA_INT, ET_INT
				  , null_proto_info
				  , op
				  , reason
#ifdef HAVE_LABELED_IPSEC
				  , c->policy_label
#endif
				  )) {
                return FALSE;
            }
        }

        if (!replace_bare_shunt(src, dst
                                , BOTTOM_PRIO
                                , SPI_HOLD
                                , FALSE
                                , transport_proto
                                , "delete narrow %hold"))
            return FALSE;
    }
    sr->routing = rn;
    return TRUE;
}

/* compute a (host-order!) SPI to implement the policy in connection c */
ipsec_spi_t
shunt_policy_spi(struct connection *c, bool prospective)
{
    /* note: these are in host order :-( */
    static const ipsec_spi_t shunt_spi[] =
    {
        SPI_TRAP,       /* --initiateontraffic */
        SPI_PASS,       /* --pass */
        SPI_DROP,       /* --drop */
        SPI_REJECT,     /* --reject */
    };

    static const ipsec_spi_t fail_spi[] =
    {
        0,      /* --none*/
        SPI_PASS,       /* --failpass */
        SPI_DROP,       /* --faildrop */
        SPI_REJECT,     /* --failreject */
    };

    return prospective
        ? shunt_spi[(c->policy & POLICY_SHUNT_MASK) >> POLICY_SHUNT_SHIFT]
        : fail_spi[(c->policy & POLICY_FAIL_MASK) >> POLICY_FAIL_SHIFT];
}

static bool
del_spi(ipsec_spi_t spi, int proto
	, const ip_address *src, const ip_address *dest)
{
    char text_said[SATOT_BUF];
    struct kernel_sa sa;

    set_text_said(text_said, dest, spi, proto);

    DBG(DBG_KLIPS, DBG_log("delete %s", text_said));

    memset(&sa, 0, sizeof(sa));
    sa.spi = spi;
    sa.proto = proto;
    sa.src = src;
    sa.dst = dest;
    sa.text_said = text_said;

    passert(kernel_ops->del_sa != NULL);
    return kernel_ops->del_sa(&sa);
}

/*
 * Setup a pair of SAs.
 *
 */
static bool
setup_half_ipsec_sa(struct state *st, bool inbound)
{
    /* Build an inbound or outbound SA */

    struct connection *c = st->st_connection;
    ip_subnet src, dst;
    ip_subnet src_client, dst_client;
    ipsec_spi_t inner_spi = 0;
    unsigned int proto = 0;
    enum eroute_type esatype = ET_UNSPEC;
    bool replace;
    bool outgoing_ref_set = FALSE;
    bool incoming_ref_set = FALSE;
    IPsecSAref_t refhim = st->st_refhim;
    IPsecSAref_t new_refhim = IPSEC_SAREF_NULL;

    /* SPIs, saved for spigrouping or undoing, if necessary */
    struct kernel_sa
        said[EM_MAXRELSPIS],
        *said_next = said;

    char text_said[SATOT_BUF];
    int encapsulation;

    replace = inbound && (kernel_ops->get_spi != NULL);

    src.maskbits = 0;
    dst.maskbits = 0;

    if (inbound)
    {
        src.addr = c->spd.that.host_addr;
        dst.addr = c->spd.this.host_addr;
        src_client = c->spd.that.client;
        dst_client = c->spd.this.client;
    }
    else
    {
        src.addr = c->spd.this.host_addr,
        dst.addr = c->spd.that.host_addr;
        src_client = c->spd.this.client;
        dst_client = c->spd.that.client;
    }

    encapsulation = ENCAPSULATION_MODE_TRANSPORT;
    if (st->st_ah.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL
        || st->st_esp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL
        || st->st_ipcomp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
    {
        encapsulation = ENCAPSULATION_MODE_TUNNEL;
    }

    memset(said, 0, sizeof(said));

    /* If we are tunnelling, set up IP in IP pseudo SA */

    if (kernel_ops->inbound_eroute)
    {
        inner_spi = 256;
        proto = SA_IPIP;
        esatype = ET_IPIP; /* XXX bart: used to be "UNSPEC" */
    }
    else if (encapsulation == ENCAPSULATION_MODE_TUNNEL)
    {
        /* XXX hack alert -- we SHOULD NOT HAVE TO HAVE A DIFFERENT SPI
         * XXX FOR IP-in-IP ENCAPSULATION!
         */

        ipsec_spi_t ipip_spi;

        /* Allocate an SPI for the tunnel.
         * Since our peer will never see this,
         * and it comes from its own number space,
         * it is purely a local implementation wart.
         */
        {
            static ipsec_spi_t last_tunnel_spi = IPSEC_DOI_SPI_OUR_MIN;

            ipip_spi = htonl(++last_tunnel_spi);
            if (inbound)
                st->st_tunnel_in_spi = ipip_spi;
            else
                st->st_tunnel_out_spi = ipip_spi;
        }

        set_text_said(text_said
            , &c->spd.that.host_addr, ipip_spi, SA_IPIP);

        said_next->src = &src.addr;
        said_next->dst = &dst.addr;
        said_next->src_client = &src_client;
        said_next->dst_client = &dst_client;
        said_next->transport_proto = c->spd.this.protocol;
        said_next->spi = ipip_spi;
        said_next->esatype = ET_IPIP;
        said_next->text_said = text_said;
	said_next->sa_lifetime = c->sa_ipsec_life_seconds;

	said_next->outif   = -1;

#ifdef HAVE_LABELED_IPSEC
	said_next->sec_ctx = st->sec_ctx;
#endif

	if(inbound) {
	    /*
	     * set corresponding outbound SA. We can do this on
	     * each SA in the bundle without harm.
	     */
	    said_next->refhim = refhim;
	} else if (!outgoing_ref_set) {
	    /* on outbound, pick up the SAref if not already done */
	    said_next->ref    = refhim;
	    outgoing_ref_set  = TRUE;
	}

	if(inbound) {
	    /*
	     * set corresponding outbound SA. We can do this on
	     * each SA in the bundle without harm.
	     */
	    said_next->refhim = refhim;
	} else if (!outgoing_ref_set) {
	    /* on outbound, pick up the SAref if not already done */
	    said_next->ref    = refhim;
	    outgoing_ref_set  = TRUE;
	}

        if (!kernel_ops->add_sa(said_next, replace)) {
	    DBG(DBG_KLIPS, DBG_log("add_sa tunnel failed"));
            goto fail;
	}

	time((inbound)? &st->st_esp.our_lastused : &st->st_esp.peer_lastused);

	DBG(DBG_KLIPS, DBG_log("added tunnel with ref=%u", said_next->ref));

	/*
	 * SA refs will have been allocated for this SA.
	 * The inner most one is interesting for the outgoing SA,
	 * since we refer to it in the policy that we instantiate.
	 */
	if(new_refhim == IPSEC_SAREF_NULL && !inbound) {
	    DBG(DBG_KLIPS, DBG_log("recorded ref=%u as refhim", said_next->ref));
	    new_refhim = said_next->ref;
	    if(new_refhim == IPSEC_SAREF_NULL) {
		new_refhim = IPSEC_SAREF_NA;
	    }
	}
	if(!incoming_ref_set && inbound) {
	    st->st_ref = said_next->ref;
	    incoming_ref_set=TRUE;
	}
        said_next++;

        inner_spi = ipip_spi;
        proto = SA_IPIP;
        esatype = ET_IPIP;
    }

    /* set up IPCOMP SA, if any */

    if (st->st_ipcomp.present)
    {
        ipsec_spi_t ipcomp_spi = inbound? st->st_ipcomp.our_spi : st->st_ipcomp.attrs.spi;
        unsigned compalg;

        switch (st->st_ipcomp.attrs.transattrs.encrypt)
        {
            case IPCOMP_DEFLATE:
                compalg = SADB_X_CALG_DEFLATE;
                break;

            default:
                loglog(RC_LOG_SERIOUS, "IPCOMP transform %s not implemented"
                    , enum_name(&ipcomp_transformid_names, st->st_ipcomp.attrs.transattrs.encrypt));
                goto fail;
        }

        set_text_said(text_said, &dst.addr, ipcomp_spi, SA_COMP);

        said_next->src = &src.addr;
        said_next->dst = &dst.addr;
        said_next->src_client = &src_client;
        said_next->dst_client = &dst_client;
        said_next->transport_proto = c->spd.this.protocol;
        said_next->spi = ipcomp_spi;
        said_next->esatype = ET_IPCOMP;
        said_next->encalg = compalg;
        said_next->encapsulation = encapsulation;
        said_next->reqid = c->spd.reqid + 2;
        said_next->text_said = text_said;
	said_next->sa_lifetime = c->sa_ipsec_life_seconds;

	said_next->outif   = -1;

#ifdef HAVE_LABELED_IPSEC
        said_next->sec_ctx = st->sec_ctx;
#endif

	if(inbound) {
	    /*
	     * set corresponding outbound SA. We can do this on
	     * each SA in the bundle without harm.
	     */
	    said_next->refhim = refhim;
	} else if (!outgoing_ref_set) {
	    /* on outbound, pick up the SAref if not already done */
	    said_next->ref    = refhim;
	    outgoing_ref_set  = TRUE;
	}

        if (!kernel_ops->add_sa(said_next, replace)) {
	    DBG_log("add_sa ipcomp failed");
            goto fail;
	}

	/*
	 * SA refs will have been allocated for this SA.
	 * The inner most one is interesting for the outgoing SA,
	 * since we refer to it in the policy that we instantiate.
	 */
	if(new_refhim == IPSEC_SAREF_NULL && !inbound) {
	    new_refhim = said_next->ref;
	    if(new_refhim == IPSEC_SAREF_NULL) {
		new_refhim = IPSEC_SAREF_NA;
	    }
	}
	if(!incoming_ref_set && inbound) {
	    st->st_ref = said_next->ref;
	    incoming_ref_set=TRUE;
	}
        said_next++;

        encapsulation = ENCAPSULATION_MODE_TRANSPORT;
    }

    /* set up ESP SA, if any */

    if (st->st_esp.present)
    {
        ipsec_spi_t esp_spi = inbound? st->st_esp.our_spi : st->st_esp.attrs.spi;
        u_char *esp_dst_keymat = inbound? st->st_esp.our_keymat : st->st_esp.peer_keymat;
        const struct esp_info *ei;
        u_int16_t key_len;

        static const struct esp_info esp_info[] = {
            { FALSE, ESP_NULL, AUTH_ALGORITHM_HMAC_MD5,
                0, HMAC_MD5_KEY_LEN,
                SADB_EALG_NULL, SADB_AALG_MD5HMAC },
            { FALSE, ESP_NULL, AUTH_ALGORITHM_HMAC_SHA1,
                0, HMAC_SHA1_KEY_LEN,
                SADB_EALG_NULL, SADB_AALG_SHA1HMAC },

            { FALSE, ESP_DES, AUTH_ALGORITHM_NONE,
                DES_CBC_BLOCK_SIZE, 0,
                SADB_EALG_DESCBC, SADB_AALG_NONE },
            { FALSE, ESP_DES, AUTH_ALGORITHM_HMAC_MD5,
                DES_CBC_BLOCK_SIZE, HMAC_MD5_KEY_LEN,
                SADB_EALG_DESCBC, SADB_AALG_MD5HMAC },
            { FALSE, ESP_DES, AUTH_ALGORITHM_HMAC_SHA1,
                DES_CBC_BLOCK_SIZE,
                HMAC_SHA1_KEY_LEN, SADB_EALG_DESCBC, SADB_AALG_SHA1HMAC },

            { FALSE, ESP_3DES, AUTH_ALGORITHM_NONE,
                DES_CBC_BLOCK_SIZE * 3, 0,
                SADB_EALG_3DESCBC, SADB_AALG_NONE },
            { FALSE, ESP_3DES, AUTH_ALGORITHM_HMAC_MD5,
                DES_CBC_BLOCK_SIZE * 3, HMAC_MD5_KEY_LEN,
                SADB_EALG_3DESCBC, SADB_AALG_MD5HMAC },
            { FALSE, ESP_3DES, AUTH_ALGORITHM_HMAC_SHA1,
                DES_CBC_BLOCK_SIZE * 3, HMAC_SHA1_KEY_LEN,
                SADB_EALG_3DESCBC, SADB_AALG_SHA1HMAC },

            { FALSE, ESP_AES, AUTH_ALGORITHM_NONE,
                AES_CBC_BLOCK_SIZE, 0,
                SADB_X_EALG_AESCBC, SADB_AALG_NONE },
            { FALSE, ESP_AES, AUTH_ALGORITHM_HMAC_MD5,
                AES_CBC_BLOCK_SIZE, HMAC_MD5_KEY_LEN,
                SADB_X_EALG_AESCBC, SADB_AALG_MD5HMAC },
            { FALSE, ESP_AES, AUTH_ALGORITHM_HMAC_SHA1,
                AES_CBC_BLOCK_SIZE, HMAC_SHA1_KEY_LEN,
                SADB_X_EALG_AESCBC, SADB_AALG_SHA1HMAC },
        };
	/* static const int esp_max = elemsof(esp_info); */
	/* int esp_count; */

#ifdef NAT_TRAVERSAL
        u_int8_t natt_type = 0;
        u_int16_t natt_sport = 0, natt_dport = 0;
        ip_address natt_oa;

        if (st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) {
	    if(st->hidden_variables.st_nat_traversal & NAT_T_WITH_PORT_FLOATING) {
		natt_type = ESPINUDP_WITH_NON_ESP;
	    } else {
		natt_type = ESPINUDP_WITH_NON_IKE;
	    }

	    if(inbound) {
		natt_sport = st->st_remoteport;
		natt_dport = st->st_localport;
	    } else {
		natt_sport = st->st_localport;
		natt_dport = st->st_remoteport;
	    }

            natt_oa = st->hidden_variables.st_nat_oa;
        }
#endif

	DBG(DBG_CRYPT
	    , DBG_log("looking for alg with transid: %d keylen: %d auth: %d\n"
		      , st->st_esp.attrs.transattrs.encrypt
		      , st->st_esp.attrs.transattrs.enckeylen
		      , st->st_esp.attrs.transattrs.integ_hash));

        for (ei = esp_info; ; ei++)
        {

	    /* if it is the last key entry, then ask algo */
            if (ei == &esp_info[elemsof(esp_info)])
            {
                /* Check for additional kernel alg */
#ifdef KERNEL_ALG
                if ((ei=kernel_alg_esp_info(st->st_esp.attrs.transattrs.encrypt,
					    st->st_esp.attrs.transattrs.enckeylen,
					    st->st_esp.attrs.transattrs.integ_hash))!=NULL) {
                        break;
                }
#endif

                /* note: enum_show may use a static buffer, so two
                 * calls in one printf would be a mistake.
                 * enum_name does the same job, without a static buffer,
                 * assuming the name will be found.
                 */
                loglog(RC_LOG_SERIOUS, "ESP transform %s(%d) / auth %s not implemented yet"
                    , enum_name(&esp_transformid_names, st->st_esp.attrs.transattrs.encrypt)
		       , st->st_esp.attrs.transattrs.enckeylen
                    , enum_name(&auth_alg_names, st->st_esp.attrs.transattrs.integ_hash));
                goto fail;
            }

	    DBG(DBG_CRYPT
		, DBG_log("checking transid: %d keylen: %d auth: %d\n"
			  , ei->transid, ei->enckeylen, ei->auth));

            if (st->st_esp.attrs.transattrs.encrypt == ei->transid
		&& (st->st_esp.attrs.transattrs.enckeylen ==0 || st->st_esp.attrs.transattrs.enckeylen == ei->enckeylen * BITS_PER_BYTE)
		&& st->st_esp.attrs.transattrs.integ_hash == ei->auth)
                break;
        }

	if (st->st_esp.attrs.transattrs.encrypt != ei->transid
	    && st->st_esp.attrs.transattrs.enckeylen != ei->enckeylen  * BITS_PER_BYTE
	    && st->st_esp.attrs.transattrs.integ_hash != ei->auth) {
	    loglog(RC_LOG_SERIOUS, "failed to find key info for %s/%s"
		   , enum_name(&esp_transformid_names, st->st_esp.attrs.transattrs.encrypt)
		   , enum_name(&auth_alg_names, st->st_esp.attrs.transattrs.integ_hash));
	    goto fail;
	}

        key_len = st->st_esp.attrs.transattrs.enckeylen/BITS_PER_BYTE;
        if (key_len) {
                /* XXX: must change to check valid _range_ key_len */
                if (key_len > ei->enckeylen) {
                        loglog(RC_LOG_SERIOUS, "ESP transform %s passed key_len=%d > %d",
                        enum_name(&esp_transformid_names, st->st_esp.attrs.transattrs.encrypt),
                        (int)key_len, (int)ei->enckeylen);
                        goto fail;
                }
        } else {
                key_len = ei->enckeylen;
        }
        /* Grrrrr.... f*cking 7 bits jurassic algos  */

        /* 168 bits in kernel, need 192 bits for keymat_len */
        if (ei->transid == ESP_3DES && key_len == 21)
                key_len = 24;

        /* 56 bits in kernel, need 64 bits for keymat_len */
        if (ei->transid == ESP_DES && key_len == 7)
                key_len = 8;

        /* divide up keying material */
        /* passert(st->st_esp.keymat_len == ei->enckeylen + ei->authkeylen); */
	if(st->st_esp.keymat_len != key_len + ei->authkeylen)
	    DBG_log("keymat_len=%d key_len=%d authkeylen=%d",
		    st->st_esp.keymat_len, (int)key_len, (int)ei->authkeylen);
        passert(st->st_esp.keymat_len == (key_len + ei->authkeylen));

        set_text_said(text_said, &dst.addr, esp_spi, SA_ESP);

        said_next->src = &src.addr;
        said_next->dst = &dst.addr;
        said_next->src_client = &src_client;
        said_next->dst_client = &dst_client;
        said_next->transport_proto = c->spd.this.protocol;
        said_next->spi = esp_spi;
        said_next->esatype = ET_ESP;
        said_next->replay_window = kernel_ops->replay_window;
        said_next->authalg = ei->authalg;

		if( (said_next->authalg == AUTH_ALGORITHM_HMAC_SHA2_256) && (st->st_connection->sha2_truncbug)) {
			if(kernel_ops->sha2_truncbug_support){
			   DBG_log(" authalg converted for sha2 truncation at 96bits instead of IETF's mandated 128bits");
			   /* We need to tell the kernel to mangle the sha2_256, as instructed by the user */
			   said_next->authalg = AUTH_ALGORITHM_HMAC_SHA2_256_TRUNCBUG;
			} else {
                   loglog(RC_LOG_SERIOUS, "Error: %s stack does not support sha2_truncbug=yes", kernel_ops->kern_name);
		   	goto fail;
			}
		}
        said_next->authkeylen = ei->authkeylen;
        /* said_next->authkey = esp_dst_keymat + ei->enckeylen; */
        said_next->authkey = esp_dst_keymat + key_len;
        said_next->encalg = ei->encryptalg;
        /* said_next->enckeylen = ei->enckeylen; */
        said_next->enckeylen = key_len;
        said_next->enckey = esp_dst_keymat;
        said_next->encapsulation = encapsulation;
        said_next->reqid = c->spd.reqid + 1;

#ifdef HAVE_LABELED_IPSEC
        said_next->sec_ctx = st->sec_ctx;
#endif

#ifdef NAT_TRAVERSAL
        said_next->natt_sport = natt_sport;
        said_next->natt_dport = natt_dport;
        said_next->transid = st->st_esp.attrs.transattrs.encrypt;
        said_next->natt_type = natt_type;
        said_next->natt_oa = &natt_oa;
#endif
	said_next->outif   = -1;
#ifdef KLIPS_MAST
	if(st->st_esp.attrs.encapsulation == ENCAPSULATION_MODE_TRANSPORT && useful_mastno != -1) {
	    said_next->outif = MASTTRANSPORT_OFFSET+useful_mastno;
	}
#endif
	said_next->text_said = text_said;
	said_next->sa_lifetime = c->sa_ipsec_life_seconds;

	DBG(DBG_CRYPT,
	  DBG_dump("esp enckey:",  said_next->enckey,  said_next->enckeylen);
	  DBG_dump("esp authkey:", said_next->authkey, said_next->authkeylen);
	);

	if(inbound) {
	    /*
	     * set corresponding outbound SA. We can do this on
	     * each SA in the bundle without harm.
	     */
	    said_next->refhim = refhim;
	} else if (!outgoing_ref_set) {
	    /* on outbound, pick up the SAref if not already done */
	    said_next->ref    = refhim;
	    outgoing_ref_set  = TRUE;
	}

	if(inbound) {
	    /*
	     * set corresponding outbound SA. We can do this on
	     * each SA in the bundle without harm.
	     */
	    said_next->refhim = refhim;
	} else if (!outgoing_ref_set) {
	    /* on outbound, pick up the SAref if not already done */
	    said_next->ref    = refhim;
	    outgoing_ref_set  = TRUE;
	}

#ifdef HAVE_LIBNSS
       if (!kernel_ops->add_sa(said_next, replace)) {
            memset(said_next->enckey, 0, said_next->enckeylen);
            memset(said_next->authkey, 0, said_next->authkeylen);
#else
        if (!kernel_ops->add_sa(said_next, replace))
#endif
            goto fail;
#ifdef HAVE_LIBNSS
       }
            memset(said_next->enckey, 0, said_next->enckeylen);
            memset(said_next->authkey, 0, said_next->authkeylen);
#endif

	/*
	 * SA refs will have been allocated for this SA.
	 * The inner most one is interesting for the outgoing SA,
	 * since we refer to it in the policy that we instantiate.
	 */
	if(new_refhim == IPSEC_SAREF_NULL && !inbound) {
	    new_refhim = said_next->ref;
	    if(new_refhim == IPSEC_SAREF_NULL) {
		new_refhim = IPSEC_SAREF_NA;
	    }
	}
	if(!incoming_ref_set && inbound) {
	    st->st_ref = said_next->ref;
	    incoming_ref_set=TRUE;
	}
        said_next++;

        encapsulation = ENCAPSULATION_MODE_TRANSPORT;
    }

    /* set up AH SA, if any */

    if (st->st_ah.present)
    {
        ipsec_spi_t ah_spi = inbound? st->st_ah.our_spi : st->st_ah.attrs.spi;
        u_char *ah_dst_keymat = inbound? st->st_ah.our_keymat : st->st_ah.peer_keymat;

        unsigned char authalg;

        switch (st->st_ah.attrs.transattrs.integ_hash)
        {
        case AUTH_ALGORITHM_HMAC_MD5:
            authalg = SADB_AALG_MD5HMAC;
            break;

        case AUTH_ALGORITHM_HMAC_SHA1:
            authalg = SADB_AALG_SHA1HMAC;
            break;

        case AUTH_ALGORITHM_KPDK:
        case AUTH_ALGORITHM_DES_MAC:
        default:
            loglog(RC_LOG_SERIOUS, "%s not implemented yet"
                , enum_show(&auth_alg_names, st->st_ah.attrs.transattrs.integ_hash));
            goto fail;
        }

        set_text_said(text_said, &dst.addr, ah_spi, SA_AH);

        said_next->src = &src.addr;
        said_next->dst = &dst.addr;
        said_next->src_client = &src_client;
        said_next->dst_client = &dst_client;
        said_next->transport_proto = c->spd.this.protocol;
        said_next->spi = ah_spi;
        said_next->esatype = ET_AH;
        said_next->replay_window = kernel_ops->replay_window;
        said_next->authalg = authalg;
        said_next->authkeylen = st->st_ah.keymat_len;
        said_next->authkey = ah_dst_keymat;
        said_next->encapsulation = encapsulation;
        said_next->reqid = c->spd.reqid;
        said_next->text_said = text_said;
	said_next->sa_lifetime = c->sa_ipsec_life_seconds;
	said_next->outif   = -1;

#ifdef HAVE_LABELED_IPSEC
        said_next->sec_ctx = st->sec_ctx;
#endif

	if(inbound) {
	    /*
	     * set corresponding outbound SA. We can do this on
	     * each SA in the bundle without harm.
	     */
	    said_next->refhim = refhim;
	} else if (!outgoing_ref_set) {
	    /* on outbound, pick up the SAref if not already done */
	    said_next->ref    = refhim;
	    outgoing_ref_set  = TRUE;
	}

	if(inbound) {
	    /*
	     * set corresponding outbound SA. We can do this on
	     * each SA in the bundle without harm.
	     */
	    said_next->refhim = refhim;
	} else if (!outgoing_ref_set) {
	    /* on outbound, pick up the SAref if not already done */
	    said_next->ref    = refhim;
	    outgoing_ref_set  = TRUE;
	}

#ifdef HAVE_LIBNSS
       if (!kernel_ops->add_sa(said_next, replace)) {
            memset(said_next->authkey, 0, said_next->authkeylen);
#else
        if (!kernel_ops->add_sa(said_next, replace))
#endif
            goto fail;
#ifdef HAVE_LIBNSS
       }
            memset(said_next->authkey, 0, said_next->authkeylen);
#endif


	/*
	 * SA refs will have been allocated for this SA.
	 * The inner most one is interesting for the outgoing SA,
	 * since we refer to it in the policy that we instantiate.
	 */
	if(new_refhim == IPSEC_SAREF_NULL && !inbound) {
	    new_refhim = said_next->ref;
	    if(new_refhim == IPSEC_SAREF_NULL) {
		new_refhim = IPSEC_SAREF_NA;
	    }
	}
	if(!incoming_ref_set && inbound) {
	    st->st_ref = said_next->ref;
	    incoming_ref_set=TRUE;
	}
        said_next++;

        encapsulation = ENCAPSULATION_MODE_TRANSPORT;
    }

    if (st->st_ah.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL
    || st->st_esp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL
    || st->st_ipcomp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
    {
        encapsulation = ENCAPSULATION_MODE_TUNNEL;
    }

    if (kernel_ops->inbound_eroute ? c->spd.eroute_owner == SOS_NOBODY
        : encapsulation == ENCAPSULATION_MODE_TUNNEL)
    {
        /* If inbound, and policy does not specifie DISABLEARRIVALCHECK,
         * tell KLIPS to enforce the IP addresses appropriate for this tunnel.
         * Note reversed ends.
         * Not much to be done on failure.
         */
        if (inbound && (c->policy & POLICY_DISABLEARRIVALCHECK) == 0)
        {
            struct pfkey_proto_info proto_info[4];
            int i = 0;

            if (st->st_ipcomp.present)
            {
                proto_info[i].proto = IPPROTO_COMP;
                proto_info[i].encapsulation = st->st_ipcomp.attrs.encapsulation;
                proto_info[i].reqid = c->spd.reqid + 2;
                i++;
            }

            if (st->st_esp.present)
            {
                proto_info[i].proto = IPPROTO_ESP;
                proto_info[i].encapsulation = st->st_esp.attrs.encapsulation;
                proto_info[i].reqid = c->spd.reqid + 1;
                i++;
            }

            if (st->st_ah.present)
            {
                proto_info[i].proto = IPPROTO_AH;
                proto_info[i].encapsulation = st->st_ah.attrs.encapsulation;
                proto_info[i].reqid = c->spd.reqid;
                i++;
            }

            proto_info[i].proto = 0;

            if (kernel_ops->inbound_eroute
                && encapsulation == ENCAPSULATION_MODE_TUNNEL)
            {
                proto_info[0].encapsulation = ENCAPSULATION_MODE_TUNNEL;
                for (i = 1; proto_info[i].proto; i++)
                {
                    proto_info[i].encapsulation = ENCAPSULATION_MODE_TRANSPORT;
                }
            }

            /* MCR - should be passed a spd_eroute structure here */
            (void) raw_eroute(&c->spd.that.host_addr   /* this_host */
			      , &c->spd.that.client    /* this_client */
                              , &c->spd.this.host_addr /* that_host */
			      , &c->spd.this.client    /* that_client */
                              , inner_spi              /* spi */
			      , proto                  /* proto */
                              , c->spd.this.protocol   /* transport_proto */
                              , esatype                /* esatype */
                              , proto_info             /* " */
			      , 0                      /* lifetime */
                              , ERO_ADD_INBOUND        /* op */
			      , "add inbound"        /* opname */
#ifdef HAVE_LABELED_IPSEC
			      , st->st_connection->policy_label
#endif
			      );

	if(st->st_ikev2) {
	   struct spd_route *sr = &c->spd;
	   for(sr = sr->next; sr != NULL; sr = sr->next) {

            /* MCR - should be passed a spd_eroute structure here */
            (void) raw_eroute(&sr->that.host_addr   /* this_host */
			      , &sr->that.client    /* this_client */
                              , &sr->this.host_addr /* that_host */
			      , &sr->this.client    /* that_client */
                              , inner_spi              /* spi */
			      , proto                  /* proto */
                              , sr->this.protocol   /* transport_proto */
                              , esatype                /* esatype */
                              , proto_info             /* " */
			      , 0                      /* lifetime */
                              , ERO_ADD_INBOUND        /* op */
			      , "add inbound"        /* opname */
#ifdef HAVE_LABELED_IPSEC
			      , st->st_connection->policy_label
#endif
			      );
	   }
	}

        }
    }

    /* If there are multiple SPIs, group them. */

    if (kernel_ops->grp_sa && said_next > &said[1])
    {
        struct kernel_sa *s;

        /* group SAs, two at a time, inner to outer (backwards in said[])
         * The grouping is by pairs.  So if said[] contains ah esp ipip,
         * the grouping would be ipip:esp, esp:ah.
         */
        for (s = said; s < said_next-1; s++)
        {
            char
                text_said0[SATOT_BUF],
                text_said1[SATOT_BUF];

            /* group s[1] and s[0], in that order */

            set_text_said(text_said0, s[0].dst, s[0].spi, s[0].proto);
            set_text_said(text_said1, s[1].dst, s[1].spi, s[1].proto);

            DBG(DBG_KLIPS, DBG_log("grouping %s (ref=%u) and %s (ref=%u)"
				   , text_said0, s[0].ref
				   , text_said1, s[1].ref));

            s[0].text_said = text_said0;
            s[1].text_said = text_said1;

            if (!kernel_ops->grp_sa(s + 1, s))
                goto fail;
        }
        /* could update said, but it will not be used */
    }

    if(new_refhim != IPSEC_SAREF_NULL) {
	st->st_refhim = new_refhim;
    }

#ifdef DEBUG
    /* if the impaired is set, pretend this fails */
    if(st->st_connection->extra_debugging & IMPAIR_SA_CREATION) {
	DBG_log("Impair SA creation is set, pretending to fail");
	goto fail;
    }
#endif
    return TRUE;

fail:
    {
	DBG_log("setup_half_ipsec_sa() hit fail:");
        /* undo the done SPIs */
        while (said_next-- != said) {
	    if(said_next->proto) {
		(void) del_spi(said_next->spi, said_next->proto
			       , &src.addr, said_next->dst);
	    }
	}
        return FALSE;
    }
}

/* teardown_ipsec_sa is a canibalized version of setup_ipsec_sa */

static bool
teardown_half_ipsec_sa(struct state *st, bool inbound)
{
    /* We need to delete AH, ESP, and IP in IP SPIs.
     * But if there is more than one, they have been grouped
     * so deleting any one will do.  So we just delete the
     * first one found.  It may or may not be the only one.
     */
    struct connection *c = st->st_connection;
    struct spd_route *sr;
    struct {
        unsigned proto;
        struct ipsec_proto_info *info;
    } protos[4];
    int i;
    bool result;

    i = 0;
    if (kernel_ops->inbound_eroute && inbound
        && c->spd.eroute_owner == SOS_NOBODY)
    {
        (void) raw_eroute(&c->spd.that.host_addr, &c->spd.that.client
                          , &c->spd.this.host_addr, &c->spd.this.client
                          , 256
			  , IPSEC_PROTO_ANY
                          , c->spd.this.protocol
                          , ET_UNSPEC
                          , null_proto_info, 0
                          , ERO_DEL_INBOUND, "delete inbound"
#ifdef HAVE_LABELED_IPSEC
			  , c->policy_label
#endif
			  );
    }

    if(st->st_ikev2) {
        for(sr = &c->spd; sr; sr=sr->next) {
            if (kernel_ops->inbound_eroute && inbound
                && sr->eroute_owner == SOS_NOBODY)
                {
                    (void) raw_eroute(&sr->that.host_addr, &sr->that.client
                                      , &sr->this.host_addr, &sr->this.client
                                      , 256
                                      , IPSEC_PROTO_ANY
                                      , sr->this.protocol
                                      , ET_UNSPEC
                                      , null_proto_info, 0
                                      , ERO_DEL_INBOUND, "delete inbound"
#ifdef HAVE_LABELED_IPSEC
                                      , c->policy_label
#endif
                                      );
                }
        }
    }




    if (!kernel_ops->grp_sa)
    {
        if (st->st_ah.present)
        {
            protos[i].info = &st->st_ah;
            protos[i].proto = SA_AH;
            i++;
        }

        if (st->st_esp.present)
        {
            protos[i].info = &st->st_esp;
            protos[i].proto = SA_ESP;
            i++;
        }

        if (st->st_ipcomp.present)
        {
            protos[i].info = &st->st_ipcomp;
            protos[i].proto = SA_COMP;
            i++;
        }
    }
    else if (st->st_ah.present)
    {
        protos[i].info = &st->st_ah;
        protos[i].proto = SA_AH;
        i++;
    }
    else if (st->st_esp.present)
    {
        protos[i].info = &st->st_esp;
        protos[i].proto = SA_ESP;
        i++;
    }
    else
    {
	return TRUE;
    }
    protos[i].proto = 0;

    result = TRUE;
    for (i = 0; protos[i].proto; i++)
    {
        unsigned proto = protos[i].proto;
        ipsec_spi_t spi;
        const ip_address *src, *dst;

        if (inbound)
        {
            spi = protos[i].info->our_spi;
            src = &c->spd.that.host_addr;
            dst = &c->spd.this.host_addr;
        }
        else
        {
            spi = protos[i].info->attrs.spi;
            src = &c->spd.this.host_addr;
            dst = &c->spd.that.host_addr;
        }

        result &= del_spi(spi, proto, src, dst);
    }
    return result;
}

const struct kernel_ops *kernel_ops;

/* keep track of kernel version */
char kversion[256];

void
init_kernel(void)
{
    struct utsname un;
#if defined(NETKEY_SUPPORT) || defined(KLIPS) || defined(KLIPS_MAST)
    struct stat buf;
#endif

    /* get kernel version */
    uname(&un);
    strncpy(kversion, un.release, sizeof(kversion));

    switch(kern_interface) {
    case AUTO_PICK:
#if defined(NETKEY_SUPPORT) || defined(KLIPS) || defined(KLIPS_MAST)
	/* If we detect NETKEY and KLIPS, we can't continue */
	if(stat("/proc/net/pfkey", &buf) == 0 &&
	   stat("/proc/net/pf_key", &buf) == 0) {
	    /* we don't die, we just log and go to sleep */
	    openswan_log("Can not run with both NETKEY and KLIPS in the kernel");
	    openswan_log("Please check your kernel configuration, or specify a stack");
	    openswan_log("using protostack={klips,netkey,mast}");
	    exit_pluto(0);
	}
#endif
	openswan_log("Kernel interface auto-pick");
	/* FALL THROUGH */

#if defined(NETKEY_SUPPORT)
    case USE_NETKEY:
	if (stat("/proc/net/pfkey", &buf) == 0) {
	    kern_interface = USE_NETKEY;
	    openswan_log("Using Linux 2.6 IPsec interface code on %s (experimental code)"
			 , kversion);
	    kernel_ops = &netkey_kernel_ops;
	    break;
	} else
	    openswan_log("No Kernel NETKEY interface detected");
	/* FALL THROUGH */
#endif

#if defined(KLIPS)
    case USE_KLIPS:
	if (stat("/proc/net/pf_key", &buf) == 0) {
	    kern_interface = USE_KLIPS;
	    openswan_log("Using KLIPS IPsec interface code on %s"
			 , kversion);
	    kernel_ops = &klips_kernel_ops;
	    break;
	} else
	    openswan_log("No Kernel KLIPS interface detected");
	/* FALL THROUGH */
#endif

#if defined(KLIPS_MAST)
    case USE_MASTKLIPS:
        if (stat("/proc/sys/net/ipsec/debug_mast", &buf) == 0) {
	    kern_interface = USE_MASTKLIPS;
	    openswan_log("Using KLIPSng (mast) IPsec interface code on %s"
			 , kversion);
	    kernel_ops = &mast_kernel_ops;
	    break;
	} else
	    openswan_log("No Kernel MASTKLIPS interface detected");
	/* FALL THROUGH */
#endif

#if defined(BSD_KAME)
    case USE_BSDKAME:
	kern_interface = USE_BSDKAME;
	openswan_log("Using BSD/KAME IPsec interface code on %s"
			, kversion);
	kernel_ops = &bsdkame_kernel_ops;
	break;
#endif

#if defined(WIN32) && defined(WIN32_NATIVE)
    case USE_WIN32_NATIVE:
	kern_interface = USE_WIN32_NATIVE;
	openswan_log("Using Win2K native IPsec interface code on %s"
		     , kversion);
	kernel_ops = &win2k_kernel_ops;
	break;
#endif

    case NO_KERNEL:
	kern_interface = NO_KERNEL;
	openswan_log("Using 'no_kernel' interface code on %s"
		     , kversion);
	kernel_ops = &noklips_kernel_ops;
	break;

    default:
	if(kern_interface == AUTO_PICK)
		openswan_log("kernel interface auto-pick failed - no suitable kernel stack found");
	else
		openswan_log("kernel interface '%s' not available"
		     , enum_name(&kern_interface_names, kern_interface));
	exit_pluto(5);
    }

    if (kernel_ops->init)
    {
        kernel_ops->init();
    }

    /* register SA types that we can negotiate */
    can_do_IPcomp = FALSE;  /* until we get a response from KLIPS */
    if (kernel_ops->pfkey_register)
    {
	kernel_ops->pfkey_register();
    }

    if (!kernel_ops->policy_lifetime)
    {
        event_schedule(EVENT_SHUNT_SCAN, SHUNT_SCAN_INTERVAL, NULL);
    }
}

void show_kernel_interface()
{
    if(kernel_ops) {
	whack_log(RC_COMMENT, "using kernel interface: %s"
		  , kernel_ops->kern_name);
    }
}

/*
 * see if the attached connection refers to an older state.
 * if it does, then initiate this state with the appropriate outgoing
 * references, such that we won't break any userland applications
 * that are using the conn with REFINFO.
 */
static void look_for_replacement_state(struct state *st)
{
    struct connection *c = st->st_connection;
    struct state *ost = state_with_serialno(c->newest_ipsec_sa);

    DBG(DBG_CONTROL,
	DBG_log("checking if this is a replacement state");
	DBG_log("  st=%p ost=%p st->serialno=#%lu ost->serialno=#%lu "
		, st, ost, st->st_serialno, ost?ost->st_serialno : 0));

    if(ost && ost != st && ost->st_serialno != st->st_serialno) {
	/*
	 * then there is an old state associated, and it is
	 * different then the new one.
	 */
	openswan_log("keeping refhim=%lu during rekey"
		     , (unsigned long)ost->st_refhim);
	st->st_refhim = ost->st_refhim;
    }
}


/* Note: install_inbound_ipsec_sa is only used by the Responder.
 * The Responder will subsequently use install_ipsec_sa for the outbound.
 * The Initiator uses install_ipsec_sa to install both at once.
 */
bool
install_inbound_ipsec_sa(struct state *st)
{
    struct connection *const c = st->st_connection;

    /* If our peer has a fixed-address client, check if we already
     * have a route for that client that conflicts.  We will take this
     * as proof that that route and the connections using it are
     * obsolete and should be eliminated.  Interestingly, this is
     * the only case in which we can tell that a connection is obsolete.
     */
    passert(c->kind == CK_PERMANENT || c->kind == CK_INSTANCE);
    if (c->spd.that.has_client)
    {
        for (;;)
        {
            struct spd_route *esr;
            struct connection *o = route_owner(c, &c->spd, &esr, NULL, NULL);

            if (o == NULL || c==o)
                break;  /* nobody interesting has a route */

            /* note: we ignore the client addresses at this end */
            if (sameaddr(&o->spd.that.host_addr, &c->spd.that.host_addr)
		&& o->interface == c->interface)
                break;  /* existing route is compatible */

#if 0	    /* this stops us removing certain RW routes, and later we fail */
            if (o->kind == CK_TEMPLATE && streq(o->name, c->name))
                break;  /* ??? is this good enough?? */
#endif

            if(kernel_ops->overlap_supported) {
		/* Both are transport mode, allow overlapping.
		 * [bart] not sure if this is actually intended, but am
		 *        leaving it in to make it behave like before */
		if (!LIN(POLICY_TUNNEL, c->policy)
		    && !LIN(POLICY_TUNNEL, o->policy))
		    break;
		/* Both declared that overlapping is OK. */
		if (LIN(POLICY_OVERLAPIP, c->policy)
		    && LIN(POLICY_OVERLAPIP, o->policy))
		    break;
            }

	    loglog(RC_LOG_SERIOUS, "route to peer's client conflicts with \"%s\" %s; releasing old connection to free the route"
		   , o->name, ip_str(&o->spd.that.host_addr));
	    release_connection(o, FALSE);
        }
    }

    DBG(DBG_CONTROL, DBG_log("install_inbound_ipsec_sa() checking if we can route"));
    /* check that we will be able to route and eroute */
    switch (could_route(c))
    {
    case route_easy:
    case route_nearconflict:
	DBG(DBG_CONTROL
	    , DBG_log("   routing is easy, or has resolvable near-conflict"));
	break;

    case route_unnecessary:
	/*
	 * in this situation, we should look and see if there is a state
	 * that our connection references, that we are in fact replacing.
	 */
        break;

    default:
        return FALSE;
    }

    look_for_replacement_state(st);

    /*
     * we now have to set up the outgoing SA first, so that
     * we can refer to it in the incoming SA.
     */
    if(st->st_refhim == IPSEC_SAREF_NULL && !st->st_outbound_done) {

#ifdef HAVE_LABELED_IPSEC
	if(!st->st_connection->loopback) {
#endif

	DBG(DBG_CONTROL, DBG_log("installing outgoing SA now as refhim=%u", st->st_refhim));
	if(!setup_half_ipsec_sa(st, FALSE)) {
	    DBG_log("failed to install outgoing SA: %u", st->st_refhim);
	    return FALSE;
	}
#ifdef HAVE_LABELED_IPSEC
	}
	else {
	DBG(DBG_CONTROL,
	DBG_log("in case of loopback, the state that initiated this quick mode exchange will install outgoing SAs, so skipping this"));
	}
#endif

	st->st_outbound_done = TRUE;
    }
    DBG(DBG_CONTROL, DBG_log("outgoing SA has refhim=%u", st->st_refhim));

    /* (attempt to) actually set up the SAs */

#ifdef HAVE_LABELED_IPSEC
	if(!st->st_connection->loopback) {
#endif

    return setup_half_ipsec_sa(st, TRUE);

#ifdef HAVE_LABELED_IPSEC
	}
	else {
	DBG(DBG_CONTROL, DBG_log("in case of loopback, the state that initiated this quick mode exchange will install incoming SAs, so skipping this"));
	return TRUE;
	}
#endif
}

/* Install a route and then a prospective shunt eroute or an SA group eroute.
 * Assumption: could_route gave a go-ahead.
 * Any SA Group must have already been created.
 * On failure, steps will be unwound.
 */
bool
route_and_eroute(struct connection *c USED_BY_KLIPS
                 , struct spd_route *sr USED_BY_KLIPS
                 , struct state *st USED_BY_KLIPS)
{
    struct spd_route *esr;
    struct spd_route *rosr;
    struct connection *ero, *ro;      /* who, if anyone, owns our eroute? */
    bool eroute_installed = FALSE
        , firewall_notified = FALSE
        , route_installed = FALSE;
#ifdef IPSEC_CONNECTION_LIMIT
    bool new_eroute = FALSE;
#endif

    struct bare_shunt **bspp;

    ro = route_owner(c, sr, &rosr, &ero, &esr);

    DBG(DBG_CONTROLMORE,
        DBG_log("route_and_eroute with c: %s (next: %s) ero:%s esr:{%p} ro:%s rosr:{%p} and state: %lu"
                , c->name
                , (c->policy_next ? c->policy_next->name : "none")
                , ero ? ero->name : "null"
                , esr
                , ro ? ro->name : "null"
                , rosr
                , st ? st->st_serialno : 0));

    /* look along the chain of policies for one with the same name */


#if 0
    /* XXX - mcr this made sense before, and likely will make sense
     * again, so I'l leaving this to remind me what is up */
    if (ero!= NULL && ero->routing == RT_UNROUTED_KEYED)
        ero = NULL;

    for (ero2 = ero; ero2 != NULL; ero2 = ero->policy_next)
        if ((ero2->kind == CK_TEMPLATE || ero2->kind==CK_SECONDARY)
        && streq(ero2->name, c->name))
            break;
#endif

    bspp = (ero == NULL)
        ? bare_shunt_ptr(&sr->this.client, &sr->that.client, sr->this.protocol)
        : NULL;

    /* install the eroute */

    passert(bspp == NULL || ero == NULL);       /* only one non-NULL */

    if (bspp != NULL || ero != NULL)
    {
        /* We're replacing an eroute */

        /* if no state provided, then install a shunt for later */
        if (st == NULL)
            eroute_installed = shunt_eroute(c, sr, RT_ROUTED_PROSPECTIVE
                                            , ERO_REPLACE, "replace");
        else
            eroute_installed = sag_eroute(st, sr, ERO_REPLACE, "replace");

#if 0
        /* XXX - MCR. I previously felt that this was a bogus check */
        if (ero != NULL && ero != c && esr != sr)
        {
            /* By elimination, we must be eclipsing ero.  Check. */
            passert(ero->kind == CK_TEMPLATE && streq(ero->name, c->name));
            passert(LHAS(LELEM(RT_ROUTED_PROSPECTIVE) | LELEM(RT_ROUTED_ECLIPSED)
                , esr->routing));
            passert(samesubnet(&esr->this.client, &sr->this.client)
                && samesubnet(&esr->that.client, &sr->that.client));
        }
#endif
        /* remember to free bspp iff we make it out of here alive */
    }
    else
    {
        /* we're adding an eroute */
#ifdef IPSEC_CONNECTION_LIMIT
	if (num_ipsec_eroute == IPSEC_CONNECTION_LIMIT) {
	    loglog(RC_LOG_SERIOUS
	    	, "Maximum number of IPSec connections reached (%d)"
		, IPSEC_CONNECTION_LIMIT);
	    return FALSE;
	}
	new_eroute = TRUE;
#endif

        /* if no state provided, then install a shunt for later */
        if (st == NULL)
            eroute_installed = shunt_eroute(c, sr, RT_ROUTED_PROSPECTIVE
                                            , ERO_ADD, "add");
        else
            eroute_installed = sag_eroute(st, sr, ERO_ADD, "add");
    }

    /* notify the firewall of a new tunnel */

    if (eroute_installed)
    {
        /* do we have to notify the firewall?  Yes, if we are installing
         * a tunnel eroute and the firewall wasn't notified
         * for a previous tunnel with the same clients.  Any Previous
         * tunnel would have to be for our connection, so the actual
         * test is simple.
         */
        firewall_notified = st == NULL  /* not a tunnel eroute */
            || sr->eroute_owner != SOS_NOBODY   /* already notified */
            || do_command(c, sr, "up", st); /* go ahead and notify */
    }

    /* install the route */

    DBG(DBG_CONTROL,
        DBG_log("route_and_eroute: firewall_notified: %s"
                , firewall_notified ? "true" : "false"));
    if (!firewall_notified)
    {
        /* we're in trouble -- don't do routing */
    }
    else if (ro == NULL)
    {
        /* a new route: no deletion required, but preparation is */
        (void) do_command(c, sr, "prepare", st);    /* just in case; ignore failure */
        route_installed = do_command(c, sr, "route", st);
    }
    else if (routed(sr->routing)
    || routes_agree(ro, c))
    {
        route_installed = TRUE; /* nothing to be done */
    }
    else
    {
        /* Some other connection must own the route
         * and the route must disagree.  But since could_route
         * must have allowed our stealing it, we'll do so.
         *
         * A feature of LINUX allows us to install the new route
         * before deleting the old if the nexthops differ.
         * This reduces the "window of vulnerability" when packets
         * might flow in the clear.
         */
        if (sameaddr(&sr->this.host_nexthop, &esr->this.host_nexthop))
        {
            (void) do_command(ro, sr, "unroute", st);
            route_installed = do_command(c, sr, "route", st);
        }
        else
        {
            route_installed = do_command(c, sr, "route", st);
            (void) do_command(ro, sr, "unroute", st);
        }

        /* record unrouting */
        if (route_installed)
        {
            do {
                passert(!erouted(rosr->routing));
                rosr->routing = RT_UNROUTED;

                /* no need to keep old value */
                ro = route_owner(c, sr, &rosr, NULL, NULL);
            } while (ro != NULL);
        }
    }

    /* all done -- clean up */
    if (route_installed)
    {
        /* Success! */

        if (bspp != NULL)
        {
            free_bare_shunt(bspp);
        }
        else if (ero != NULL && ero != c)
        {
            /* check if ero is an ancestor of c. */
            struct connection *ero2;

            for (ero2 = c; ero2 != NULL && ero2 != c; ero2 = ero2->policy_next)
                ;

            if (ero2 == NULL)
            {
                /* By elimination, we must be eclipsing ero.  Checked above. */
                if (ero->spd.routing != RT_ROUTED_ECLIPSED)
                {
                    ero->spd.routing = RT_ROUTED_ECLIPSED;
                    eclipse_count++;
                }
            }
        }

        if (st == NULL)
        {
            passert(sr->eroute_owner == SOS_NOBODY);
            sr->routing = RT_ROUTED_PROSPECTIVE;
        }
        else
        {
            sr->routing = RT_ROUTED_TUNNEL;

            DBG(DBG_CONTROL,
                char cib[CONN_INST_BUF];
                DBG_log("route_and_eroute: instance \"%s\"%s, setting eroute_owner {spd=%p,sr=%p} to #%ld (was #%ld) (newest_ipsec_sa=#%ld)"
                        , st->st_connection->name
                        , (fmt_conn_instance(st->st_connection, cib), cib)
                        , &st->st_connection->spd, sr
                        , st->st_serialno
                        , sr->eroute_owner
                        , st->st_connection->newest_ipsec_sa));
            sr->eroute_owner = st->st_serialno;
            /* clear host shunts that clash with freshly installed route */
            clear_narrow_holds(&sr->this.client, &sr->that.client, sr->this.protocol);
        }

#ifdef IPSEC_CONNECTION_LIMIT
	if (new_eroute) {
	    num_ipsec_eroute++;
	    loglog(RC_COMMENT
		, "%d IPSec connections are currently being managed"
		, num_ipsec_eroute);
	}
#endif

        return TRUE;
    }
    else
    {
        /* Failure!  Unwind our work. */
        if (firewall_notified && sr->eroute_owner == SOS_NOBODY)
            (void) do_command(c, sr, "down", st);

        if (eroute_installed)
        {
            /* Restore original eroute, if we can.
             * Since there is nothing much to be done if the restoration
             * fails, ignore success or failure.
             */
            if (bspp != NULL)
            {
                /* Restore old bare_shunt.
                 * I don't think that this case is very likely.
                 * Normally a bare shunt would have been assigned
                 * to a connection before we've gotten this far.
                 */
                struct bare_shunt *bs = *bspp;

                (void) raw_eroute(&bs->said.dst /* should be useless */
                    , &bs->ours
                    , &bs->said.dst     /* should be useless */
                    , &bs->his
                    , bs->said.spi      /* network order */
                    , SA_INT            /* proto */
                    , 0                 /* transport_proto */
                    , ET_INT
                    , null_proto_info
                    , SHUNT_PATIENCE
                    , ERO_REPLACE, "restore"
#ifdef HAVE_LABELED_IPSEC
		    , NULL             /* bare shunt are not associated with any connection so no security label*/
#endif
		    );
            }
            else if (ero != NULL)
            {
                /* restore ero's former glory */
                if (esr->eroute_owner == SOS_NOBODY)
                {
                    /* note: normal or eclipse case */
                    (void) shunt_eroute(ero, esr
                                        , esr->routing, ERO_REPLACE, "restore");
                }
                else
                {
                    /* Try to find state that owned eroute.
                     * Don't do anything if it cannot be found.
                     * This case isn't likely since we don't run
                     * the updown script when replacing a SA group
                     * with its successor (for the same conn).
                     */
                    struct state *ost = state_with_serialno(esr->eroute_owner);

                    if (ost != NULL)
                        (void) sag_eroute(ost, esr, ERO_REPLACE, "restore");
                }
            }
            else
            {
                /* there was no previous eroute: delete whatever we installed */
                if (st == NULL)
                    (void) shunt_eroute(c, sr
                                        , sr->routing, ERO_DELETE, "delete");
                else
                    (void) sag_eroute(st, sr
                                      , ERO_DELETE, "delete");
            }
        }

        return FALSE;
    }
}

bool
install_ipsec_sa(struct state *st, bool inbound_also USED_BY_KLIPS)
{
    struct spd_route *sr;
    enum routability rb;

    DBG(DBG_CONTROL, DBG_log("install_ipsec_sa() for #%ld: %s"
                             , st->st_serialno
                             , inbound_also?
                             "inbound and outbound" : "outbound only"));
#ifdef HAVE_LABELED_IPSEC
    if(st->st_connection->loopback && st->st_state == STATE_QUICK_R1) {
	return TRUE;
    }
#endif

    rb = could_route(st->st_connection);
    switch (rb)
    {
    case route_easy:
    case route_unnecessary:
    case route_nearconflict:
        break;

    default:
        return FALSE;
    }

    /* (attempt to) actually set up the SA group */

    /* setup outgoing SA if we haven't already */
    if(!st->st_outbound_done
#ifdef HAVE_LABELED_IPSEC
	&& !st->st_connection->loopback
#endif
	) {
	if(!setup_half_ipsec_sa(st, FALSE)) {
	    return FALSE;
	}
	DBG(DBG_KLIPS, DBG_log("set up outoing SA, ref=%u/%u", st->st_ref, st->st_refhim));
	st->st_outbound_done = TRUE;
    }

    /* now setup inbound SA */
    if(st->st_ref == IPSEC_SAREF_NULL && inbound_also) {
	if(!setup_half_ipsec_sa(st, TRUE)) {
	    return FALSE;
	}
	DBG(DBG_KLIPS, DBG_log("set up incoming SA, ref=%u/%u", st->st_ref, st->st_refhim));
    }

    if(rb == route_unnecessary) {
	return TRUE;
    }


    sr = &st->st_connection->spd;
    if (st->st_connection->remotepeertype == CISCO) {
    sr = sr->next;
    }

    /* for (sr = &st->st_connection->spd; sr != NULL; sr = sr->next) */
    for (; sr != NULL; sr = sr->next)
    {
        DBG(DBG_CONTROL, DBG_log("sr for #%ld: %s"
                                 , st->st_serialno
                                 , enum_name(&routing_story, sr->routing)));

        /*
         * if the eroute owner is not us, then make it us.
         * See test co-terminal-02, pluto-rekey-01, pluto-unit-02/oppo-twice
         */
        pexpect(sr->eroute_owner == SOS_NOBODY
                || sr->routing >= RT_ROUTED_TUNNEL);

        if (sr->eroute_owner != st->st_serialno
            && sr->routing != RT_UNROUTED_KEYED)
        {
            if (!route_and_eroute(st->st_connection, sr, st))
            {
                delete_ipsec_sa(st, FALSE);
                /* XXX go and unroute any SRs that were successfully
                 * routed already.
                 */
                return FALSE;
            }
        }
    }

   if (st->st_connection->remotepeertype == CISCO) {

	sr = st->st_connection->spd.next;
	st->st_connection->spd.eroute_owner = sr->eroute_owner;
	st->st_connection->spd.routing = sr->routing;

	if(!st->st_connection->newest_ipsec_sa) {
		if(!do_command(st->st_connection, &st->st_connection->spd, "updateresolvconf", st)) {
		DBG(DBG_CONTROL, DBG_log("Updating resolv.conf failed, you may need to update it manually"));
		}
	}
   }

    return TRUE;
}

/* delete an IPSEC SA.
 * we may not succeed, but we bull ahead anyway because
 * we cannot do anything better by recognizing failure
 */
void
delete_ipsec_sa(struct state *st USED_BY_KLIPS, bool inbound_only USED_BY_KLIPS)
{
    switch (kern_interface) {
    case USE_MASTKLIPS:
    case USE_KLIPS:
    case USE_NETKEY:
	if (!inbound_only)
	{
	    /* If the state is the eroute owner, we must adjust
	     * the routing for the connection.
	     */
	    struct connection *c = st->st_connection;
	    struct spd_route *sr;

	    passert(st->st_connection);

	    for (sr = &c->spd; sr; sr = sr->next)
	    {
		if (sr->eroute_owner == st->st_serialno
		    && sr->routing == RT_ROUTED_TUNNEL)
		{
		    sr->eroute_owner = SOS_NOBODY;

		    /* Routing should become RT_ROUTED_FAILURE,
		     * but if POLICY_FAIL_NONE, then we just go
		     * right back to RT_ROUTED_PROSPECTIVE as if no
		     * failure happened.
		     */
		    sr->routing = (c->policy & POLICY_FAIL_MASK) == POLICY_FAIL_NONE
			? RT_ROUTED_PROSPECTIVE : RT_ROUTED_FAILURE;

		    if (sr == &c->spd && c->remotepeertype == CISCO) {
			continue;
		    }

		    (void) do_command(c, sr, "down", st);
		    if ((c->policy & POLICY_DONT_REKEY)
			&& c->kind == CK_INSTANCE)
		    {
			/* in this special case, even if the connection
			 * is still alive (due to an ISAKMP SA),
			 * we get rid of routing.
			 * Even though there is still an eroute, the c->routing
			 * setting will convince unroute_connection to delete it.
			 * unroute_connection would be upset if c->routing == RT_ROUTED_TUNNEL
			 */
			unroute_connection(c);
		    }
		    else
		    {
			(void) shunt_eroute(c, sr, sr->routing, ERO_REPLACE, "replace with shunt");
		    }

#ifdef KLIPS_MAST
		    /* in mast mode we must also delete the iptables rule */
		    if (kern_interface == USE_MASTKLIPS)
			    (void) sag_eroute(st, sr, ERO_DELETE, "delete");
#endif
		}
	    }
#ifdef HAVE_LABELED_IPSEC
	    if(!st->st_connection->loopback) {
#endif
	    (void) teardown_half_ipsec_sa(st, FALSE);
#ifdef HAVE_LABELED_IPSEC
	    }
#endif
	}
#ifdef HAVE_LABELED_IPSEC
	if(!st->st_connection->loopback || st->st_state == STATE_QUICK_I2) {
#endif
	(void) teardown_half_ipsec_sa(st, TRUE);
#ifdef HAVE_LABELED_IPSEC
            }
#endif

	if (st->st_connection->remotepeertype == CISCO && st->st_serialno == st->st_connection->newest_ipsec_sa) {
		if(!do_command(st->st_connection, &st->st_connection->spd, "restoreresolvconf", st)) {
		DBG(DBG_CONTROL, DBG_log("Restoring resolv.conf failed, you may need to do it manually"));
		}
	}

	break;
#if defined(WIN32) && defined(WIN32_NATIVE)
    case USE_WIN32_NATIVE:
	DBG(DBG_CONTROL, DBG_log("No support (required?) to delete_ipsec_sa with Win2k"));
	break;
#endif
    case NO_KERNEL:
	DBG(DBG_CONTROL, DBG_log("No support required to delete_ipsec_sa with NoKernel support"));
	break;
    default:
	DBG(DBG_CONTROL, DBG_log("Unknown kernel stack in delete_ipsec_sa"));
	break;
 } /* switch kern_interface */
}

#ifdef NAT_TRAVERSAL
static bool update_nat_t_ipsec_esp_sa (struct state *st, bool inbound)
{
        struct connection *c = st->st_connection;
        char text_said[SATOT_BUF];
        struct kernel_sa sa;
        ip_address
                src = inbound? c->spd.that.host_addr : c->spd.this.host_addr,
                dst = inbound? c->spd.this.host_addr : c->spd.that.host_addr;


        ipsec_spi_t esp_spi = inbound? st->st_esp.our_spi : st->st_esp.attrs.spi;

        u_int16_t
                natt_sport = inbound? c->spd.that.host_port : c->spd.this.host_port,
                natt_dport = inbound? c->spd.this.host_port : c->spd.that.host_port;

        set_text_said(text_said, &dst, esp_spi, SA_ESP);

        memset(&sa, 0, sizeof(sa));
        sa.spi = esp_spi;
        sa.src = &src;
        sa.dst = &dst;
        sa.text_said = text_said;
        sa.authalg = st->st_esp.attrs.transattrs.integ_hash;
        sa.natt_sport = natt_sport;
        sa.natt_dport = natt_dport;
        sa.transid = st->st_esp.attrs.transattrs.encrypt;
#ifdef HAVE_LABELED_IPSEC
	sa.sec_ctx = st->sec_ctx;
#endif

        return kernel_ops->add_sa(&sa, TRUE);

}

bool update_ipsec_sa (struct state *st USED_BY_KLIPS)
{
        if (IS_IPSEC_SA_ESTABLISHED(st->st_state)) {
                if ((st->st_esp.present) && (
                        (!update_nat_t_ipsec_esp_sa (st, TRUE)) ||
                        (!update_nat_t_ipsec_esp_sa (st, FALSE)))) {
                        return FALSE;
                }
        }
        else if (IS_ONLY_INBOUND_IPSEC_SA_ESTABLISHED(st->st_state)) {
                if ((st->st_esp.present) && (!update_nat_t_ipsec_esp_sa (st, FALSE))) {
                        return FALSE;
                }
        }
        else {
                DBG_log("assert failed at %s:%d st_state=%d", __FILE__, __LINE__,
                        st->st_state);
                return FALSE;
        }
        return TRUE;
}
#endif

bool was_eroute_idle(struct state *st, time_t since_when)
{
    if(kernel_ops->eroute_idle) {
	return kernel_ops->eroute_idle(st, since_when);
    }

    /* it is never idle if we can't check */
    return FALSE;
}

/* This wrapper is to make the seam_* files in testing/ easier */
bool kernel_overlap_supported()
{
   return kernel_ops->overlap_supported;
}


const char *kernel_if_name()
{
    return kernel_ops->kern_name;
}

/*
 * get information about a given sa - needs merging with was_eroute_idle
 */
bool
get_sa_info(struct state *st, bool inbound, time_t *ago)
{
    char text_said[SATOT_BUF];
    u_int proto;
    u_int bytes;
    time_t now;
    ipsec_spi_t spi;
    const ip_address *src, *dst;
    struct kernel_sa sa;

    struct connection *c = st->st_connection;

    if (kernel_ops->get_sa == NULL || !st->st_esp.present)
	return FALSE;

    proto = SA_ESP;

    if (inbound)
    {
	src = &c->spd.that.host_addr;
	dst = &c->spd.this.host_addr;
	spi = st->st_esp.our_spi;
    }
    else
    {
	src = &c->spd.this.host_addr;
	dst = &c->spd.that.host_addr;
	spi = st->st_esp.attrs.spi;
    }
    set_text_said(text_said, dst, spi, proto);

    memset(&sa, 0, sizeof(sa));
    sa.spi = spi;
    sa.proto = proto;
    sa.src = src;
    sa.dst = dst;
    sa.text_said = text_said;

    DBG(DBG_KLIPS,
	DBG_log("get %s", text_said)
    )
    if (!kernel_ops->get_sa(&sa, &bytes))
	return FALSE;

    time(&now);

    if (inbound)
    {
	if (bytes > st->st_esp.our_bytes)
	{
	    st->st_esp.our_bytes = bytes;
	    st->st_esp.our_lastused = now;
	}
	*ago = now - st->st_esp.our_lastused;
    }
    else
    {
	if (bytes > st->st_esp.peer_bytes)
	{
	    st->st_esp.peer_bytes = bytes;
	    st->st_esp.peer_lastused = now;
	}
	*ago = now - st->st_esp.peer_lastused;
    }
    return TRUE;
}
/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
