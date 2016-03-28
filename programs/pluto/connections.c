/* information about connections between hosts and clients
 *
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009-2010 Avesh Agarwal <avagarwa@redhat.com>
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
#include "pluto/x509lists.h"
#include "certs.h"
#include "secrets.h"

#include "pluto/defs.h"
#include "ac.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "pluto/log.h"
#include "pluto/connections.h"	/* needs id.h */
#include "pending.h"
#include "foodgroups.h"
#include "packet.h"
#include "pluto/demux.h"	/* needs packet.h */
#include "state.h"
#include "timer.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "pluto/server.h"
#include "kernel.h"	/* needs connections.h */
#include "pluto/keys.h"
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
#include "pluto/libpluto.h"
#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

#include "pluto/virtual.h"

#include "hostpair.h"

struct connection *connections = NULL;

struct connection *unoriented_connections = NULL;

/* find a connection by name.
 * If strict, don't accept a CK_INSTANCE.
 * Move the winner (if any) to the front.
 * If none is found, and strict, a diagnostic is logged to whack.
 */
struct connection *
con_by_name(const char *nm, bool strict)
{
    struct connection *p, *prev;

    for (prev = NULL, p = connections; ; prev = p, p = p->ac_next)
    {
	if (p == NULL)
	{
	    if (strict)
		whack_log(RC_UNKNOWN_NAME
		    , "no connection named \"%s\"", nm);
	    break;
	}
	if (streq(p->name, nm)
	&& (!strict || p->kind != CK_INSTANCE))
	{
	    if (prev != NULL)
	    {
		prev->ac_next = p->ac_next;	/* remove p from list */
		p->ac_next = connections;	/* and stick it on front */
		connections = p;
	    }
	    break;
	}
    }
    return p;
}

void
release_connection(struct connection *c, bool relations)
{
    if (c->kind == CK_INSTANCE)
    {
	/* This does everything we need.
	 * Note that we will be called recursively by delete_connection,
	 * but kind will be CK_GOING_AWAY.
	 */
	delete_connection(c, relations);
    }
    else
    {
	flush_pending_by_connection(c);
	delete_states_by_connection(c, relations);
	unroute_connection(c);
    }
}

/*
 * this routine compares two struct end on two basis.
 *   They are the same if they are not KH_IPHOSTNAME, and have the
 *   same host_addr.
 *   They are the same if they are KH_IPHOSTNAME, and have the same
 *   same *name*.
 *   If one is KH_IPHOSTNAME, and the other is not, then the host_addr
 *   are compared.
 *
 */
bool compare_end_addr_names(struct end *a, struct end *b)
{
    if(a->host_type == KH_IPHOSTNAME
       && b->host_type == KH_IPHOSTNAME) {
        return strcasecmp(a->host_addr_name, b->host_addr_name)==0;
    }

    return sameaddr(&a->host_addr, &b->host_addr);
}

/*
 * update the host pairs attachment, after host_addr changes
 * just remove it from the pair it is in, and put it in another pair.
 *
 * This routine also binds to a new/proper interface using orient.
 */
bool
update_host_pairs(struct connection *c)
{
    if (c->spd.that.host_type != KH_IPHOSTNAME)
	    return TRUE;

    clear_IPhost_pair(c);

    /*
     * unorient, and try again: this may change the interface to the
     * appropriate ADDRESS family too!
     * If orient fails, then tell caller, as they move to another address
     * family.
     */
    c->interface = NULL;
    if(!orient(c, pluto_port500)) {
        return FALSE;
    }

    connect_to_IPhost_pair(c);
    return TRUE;
}


/* Delete a connection */

static void
delete_end(struct connection *c UNUSED, struct spd_route *sr UNUSED, struct end *e)
{
    free_id_content(&e->id);
    pfreeany(e->updown);
    freeanychunk(e->ca);
    release_cert(e->cert);
    free_ietfAttrList(e->groups);
    pfreeany(e->host_addr_name);
}

void
delete_sr(struct connection *c, struct spd_route *sr)
{
    delete_end(c, sr, &sr->this);
    delete_end(c, sr, &sr->that);
}


/*
 * delete_connection -- removes a connection by pointer
 *
 * @c - the connection pointer
 * @relations - whether to delete any instances as well.
 *
 */

void
delete_connection(struct connection *c, bool relations)
{
    struct spd_route *sr;
    struct connection *old_cur_connection
	= cur_connection == c? NULL : cur_connection;
#ifdef DEBUG
    lset_t old_cur_debugging = cur_debugging;
#endif
	union {
		struct alg_info**     ppai;
#ifdef KERNEL_ALG
		struct alg_info_esp** ppai_esp;
#endif
#ifdef IKE_ALG
		struct alg_info_ike** ppai_ike;
#endif
	} palg_info;

    set_cur_connection(c);

    /* Must be careful to avoid circularity:
     * we mark c as going away so it won't get deleted recursively.
     */
    struct state *st = state_with_serialno(c->newest_isakmp_sa);
    unsigned int whack_sock = NULL_FD;
    if(st) {
        whack_sock = st->st_whack_sock;
    }

    passert(c->kind != CK_GOING_AWAY);
    if (c->kind == CK_INSTANCE)
    {
	openswan_log("deleting connection \"%s\" [whackfd=%u] instance with peer %s {isakmp=#%lu/ipsec=#%lu}"
                     , c->name, whack_sock
	     , ip_str(&c->spd.that.host_addr)
	     , c->newest_isakmp_sa, c->newest_ipsec_sa);
	c->kind = CK_GOING_AWAY;
    }
    else
    {
	openswan_log("deleting connection");
    }
    release_connection(c, relations);	/* won't delete c */

    if (c->kind == CK_GROUP)
	delete_group(c);

    /* free up any logging resources */
    perpeer_logfree(c);

    /* find and delete c from connections list */
    list_rm(struct connection, ac_next, c, connections);
    cur_connection = old_cur_connection;

    /* find and delete c from the host pair list */
    clear_host_pairs(c);

    if (c->kind != CK_GOING_AWAY) pfreeany(c->spd.that.virt);

#ifdef DEBUG
    set_debugging(old_cur_debugging);
#endif
    pfreeany(c->name);
#ifdef XAUTH
    pfreeany(c->cisco_dns_info);
    pfreeany(c->cisco_domain_info);
    pfreeany(c->cisco_banner);
#endif
#ifdef HAVE_LABELED_IPSEC
    pfreeany(c->policy_label);
#endif

    sr = &c->spd;
    while(sr) {
	delete_sr(c, sr);
	sr = sr->next;
    }

    free_generalNames(c->requested_ca, TRUE);

    gw_delref(&c->gw_info);
#ifdef KERNEL_ALG
    palg_info.ppai_esp = &c->alg_info_esp;
    alg_info_delref(palg_info.ppai);
#endif
#ifdef IKE_ALG
    palg_info.ppai_ike = &c->alg_info_ike;
    alg_info_delref(palg_info.ppai);
#endif
    pfree(c);
}

int foreach_connection_by_alias(const char *alias
				 , int (*f)(struct connection *c, void *arg)
				 , void *arg)
{
    struct connection *p, *pnext;
    int count = 0;

    for (p = connections; p!=NULL; p = pnext)
    {
	pnext = p->ac_next;

	if (osw_alias_cmp(alias, p->connalias)) {
	    count += (*f)(p, arg);
	}
    }
    return count;
}

static int
delete_connection_wrap(struct connection *c, void *arg)
{
    bool *barg = (bool *)arg;

    delete_connection(c, *barg);
    return 1;
}

/* Delete connections with the specified name */
void
delete_connections_by_name(const char *name, bool strict)
{
    bool f = FALSE;
    struct connection *c = con_by_name(name, strict);

    if(c==NULL) {
	(void)foreach_connection_by_alias(name, delete_connection_wrap, &f);
    } else {
	for (; c != NULL; c = con_by_name(name, FALSE))
	    delete_connection(c, FALSE);
    }
}

void
delete_every_connection(void)
{
    while (connections != NULL)
	delete_connection(connections, TRUE);
}

/* adjust orientations of connections to reflect newly added interfaces */
void
check_orientations(void)
{
    /* try to orient all the unoriented connections */
    {
	struct connection *c = unoriented_connections;

	unoriented_connections = NULL;

	while (c != NULL)
	{
	    struct connection *nxt = c->IPhp_next;

	    bool oriented = orient(c, pluto_port500);
            if(oriented) {
                DBG(DBG_CONTROLMORE
                    , DBG_log("connection %s is now oriented"
                              , c->name));
            }
	    connect_to_IPhost_pair(c);
	    connect_to_IDhost_pair(c);
	    c = nxt;
	}
    }

    /* Check that no oriented connection has become double-oriented.
     * In other words, the far side must not match one of our new interfaces.
     */
    {
	struct iface_port *i;

	for (i = interfaces; i != NULL; i = i->next)
	{
	    if (i->change == IFN_ADD)
	    {
		struct IPhost_pair *hp;

		for (hp = IPhost_pairs; hp != NULL; hp = hp->next)
		{
		    if (sameaddr(&hp->him.addr, &i->ip_addr)
			&& (kern_interface!=NO_KERNEL || hp->him.host_port == pluto_port500))
		    {
			/* bad news: the whole chain of connections
			 * hanging off this host pair has both sides
			 * matching an interface.
			 * We'll get rid of them, using orient and
			 * connect_to_IPhost_pair.  But we'll be lazy
			 * and not ditch the IPhost_pair itself (the
			 * cost of leaving it is slight and cannot
			 * be induced by a foe).
			 */
			struct connection *c = hp->connections;

			hp->connections = NULL;
			while (c != NULL)
			{
			    struct connection *nxt = c->IPhp_next;

			    c->interface = NULL;
			    (void)orient(c, pluto_port500);
			    connect_to_IPhost_pair(c);
			    c = nxt;
			}
		    }
		}
	    }
	}
    }
}

static err_t
default_end(struct end *e, ip_address *dflt_nexthop)
{
    err_t ugh = NULL;
    const struct af_info *afi = aftoinfo(addrtypeof(&e->host_addr));

    if (afi == NULL)
	return "unknown address family in default_end";

    /* default ID to IP (but only if not NO_IP -- WildCard) */
    if (e->id.kind == ID_NONE && !isanyaddr(&e->host_addr))
    {
	e->id.kind = afi->id_addr;
	e->id.ip_addr = e->host_addr;
	e->id.has_wildcards = FALSE;
    }

    /* default nexthop to other side */
    if (isanyaddr(&e->host_nexthop))
	e->host_nexthop = *dflt_nexthop;

    /* default client to subnet containing only self
     * XXX This may mean that the client's address family doesn't match
     * tunnel_addr_family.
     */
    if (!e->has_client)
	ugh = addrtosubnet(&e->host_addr, &e->client);

    if(e->sendcert == 0) {
	e->sendcert = cert_sendifasked;
    }

    return ugh;
}

static void
unshare_connection_end_strings(struct end *e)
{
    /* do "left" */
    unshare_id_content(&e->id);
    e->updown = clone_str(e->updown, "updown");

    share_cert(e->cert);
    if (e->ca.ptr != NULL)
	clonetochunk(e->ca, e->ca.ptr, e->ca.len, "ca string");

#if defined(XAUTH)
    if(e->xauth_name) {
	e->xauth_name = clone_str(e->xauth_name, "xauth name");
    }
#endif

    if(e->host_addr_name) {
	e->host_addr_name = clone_str(e->host_addr_name, "host ip");
    }
}


static void
unshare_connection_strings(struct connection *c)
{
    struct spd_route *sr;

    c->name = clone_str(c->name, "connection name");

#ifdef XAUTH
    c->cisco_dns_info = clone_str(c->cisco_dns_info, "connection cisco_dns_info");
    c->cisco_domain_info = clone_str(c->cisco_domain_info, "connection cisco_domain_info");
    c->cisco_banner = clone_str(c->cisco_banner, "connection cisco_banner");
#endif

    /* duplicate any alias, adding spaces to the beginning and end */
    c->connalias = clone_str(c->connalias, "connection alias");

    /* do "right" */
    for(sr=&c->spd; sr!=NULL; sr=sr->next) {
	unshare_connection_end_strings(&sr->this);
	unshare_connection_end_strings(&sr->that);
    }

    /* increment references to algo's, if any */
    if(c->alg_info_ike) {
#ifdef KERNEL_ALG
	alg_info_addref(IKETOINFO(c->alg_info_ike));
#endif
    }

    if(c->alg_info_esp) {
#ifdef KERNEL_ALG
	alg_info_addref(ESPTOINFO(c->alg_info_esp));
#endif
    }
}


static void
load_end_certificate(const char *filename, struct end *dst)
{
    time_t valid_until;
    cert_t cert;
    err_t ugh = NULL;

    memset(&dst->cert, 0, sizeof(dst->cert));

    /* initialize end certificate */
    dst->cert.type = CERT_NONE;

    if(filename == NULL) {
	return;
    }

    openswan_log("  loading certificate from %s\n", filename);
    dst->cert_filename = clone_str(filename, "certificate filename");

	{
	    bool valid_cert = FALSE;

	    /* load cert from file */
#ifdef HAVE_LIBNSS
	    valid_cert = load_cert_from_nss(FALSE, filename, TRUE,"host cert", &cert);
#else
	    valid_cert = load_host_cert(FALSE, filename, &cert, TRUE);
#endif
	    if(!valid_cert) {
		whack_log(RC_FATAL, "can not load certificate file %s\n"
			  , filename);
		/* clear the ID, we're expecting it via %fromcert */
		dst->id.kind = ID_NONE;
		return;
	    }
	}

    switch (cert.type)
    {
    case CERT_PGP:
	select_pgpcert_id(cert.u.pgp, &dst->id);

	valid_until = cert.u.pgp->until;
	add_pgp_public_key(cert.u.pgp, cert.u.pgp->until, DAL_LOCAL);
	dst->cert.type = cert.type;
	dst->cert.u.pgp = pluto_add_pgpcert(cert.u.pgp);
	break;

    case CERT_X509_SIGNATURE:
	if(dst->id.kind == ID_FROMCERT || dst->id.kind == ID_NONE) {
	    select_x509cert_id(cert.u.x509, &dst->id);
	}

	/* check validity of cert */
	valid_until = cert.u.x509->notAfter;
	ugh = check_validity(cert.u.x509, &valid_until);
	if (ugh != NULL)
	{
	    openswan_log("  %s", ugh);
	    free_x509cert(cert.u.x509);
	}
	else
	{
	    DBG(DBG_CONTROL,
		DBG_log("certificate is valid")
		);
	    add_x509_public_key(&dst->id, cert.u.x509, valid_until, DAL_LOCAL);
	    dst->cert.type = cert.type;
	    dst->cert.u.x509 = add_x509cert(cert.u.x509);

	    /* if no CA is defined, use issuer as default */
	    if (dst->ca.ptr == NULL)
		dst->ca = dst->cert.u.x509->issuer;
	}
	break;
    default:
	break;
    }

}

static bool
extract_end(struct connection *conn
            , struct end *dst, const struct whack_end *src, const char *which)
{
    bool same_ca = FALSE;
    unsigned int family = conn->addr_family;

    /* decode id, if any */
    if (src->id == NULL)
    {
	dst->id.kind = ID_NONE;
    }
    else
    {
	err_t ugh = atoid(src->id, &dst->id, TRUE);

	if (ugh != NULL)
	{
	    loglog(RC_BADID, "bad %s --id: %s (ignored)", which, ugh);
	    dst->id = empty_id;	/* ignore bad one */
	}
    }

    dst->ca = empty_chunk;

    /* decode CA distinguished name, if any */
    if (src->ca != NULL)
    {
	if streq(src->ca, "%same")
	    same_ca = TRUE;
	else if (!streq(src->ca, "%any"))
	{
	    err_t ugh;

	    dst->ca.ptr = temporary_cyclic_buffer();
	    dst->ca.len = IDTOA_BUF;
	    ugh = atodn(src->ca, &dst->ca);
	    if (ugh != NULL)
	    {
		openswan_log("bad CA string '%s': %s (ignored)", src->ca, ugh);
		dst->ca = empty_chunk;
	    }
	}
    }

    if(src->sendcert == cert_forcedtype) {
	/* certificate is a blob */
	dst->cert.forced = TRUE;
	dst->cert.type = src->certtype;
#ifdef HAVE_LIBNSS
	load_cert_from_nss(TRUE, src->cert, TRUE, "forced cert", &dst->cert);
#else
	load_cert(TRUE, src->cert, TRUE, "forced cert", &dst->cert);
#endif
    } else {
	/* load local end certificate and extract ID, if any */
	load_end_certificate(src->cert, dst);
    }

    /* does id has wildcards? */
    dst->id.has_wildcards = id_count_wildcards(&dst->id) > 0;

    /* decode group attributes, if any */
    decode_groups(src->groups, &dst->groups);

    /* the rest is simple copying of corresponding fields */
    dst->host_type = src->host_type;

    if(src->host_type == KH_ANY && family != 0) {
        anyaddr(family, &dst->host_addr);
    } else {
        dst->host_addr = src->host_addr;
    }
    dst->host_addr_name = src->host_addr_name;
    dst->host_nexthop = src->host_nexthop;
    dst->host_srcip = src->host_srcip;
    dst->client = src->client;

#ifdef HAVE_SIN_LEN
    /* XXX need to fix this for v6 */
    dst->client.addr.u.v4.sin_len  = sizeof(struct sockaddr_in);
    dst->host_addr.u.v4.sin_len    = sizeof(struct sockaddr_in);
    dst->host_nexthop.u.v4.sin_len = sizeof(struct sockaddr_in);
    dst->host_srcip.u.v4.sin_len   = sizeof(struct sockaddr_in);
#endif

#ifdef MODECFG
    dst->modecfg_server = src->modecfg_server;
    dst->modecfg_client = src->modecfg_client;
#endif
#ifdef XAUTH
    dst->xauth_server = src->xauth_server;
    dst->xauth_client = src->xauth_client;
    dst->xauth_name = src->xauth_name;
#endif
    dst->protocol = src->protocol;
    dst->port = src->port;
    dst->has_port_wildcard = src->has_port_wildcard;
    dst->key_from_DNS_on_demand = src->key_from_DNS_on_demand;
    dst->has_client = src->has_client;
    dst->has_client_wildcard = src->has_client_wildcard;
    dst->updown = src->updown;
    dst->host_port = IKE_UDP_PORT;
    if(src->host_port != IKE_UDP_PORT) {
	dst->host_port = src->host_port;
	dst->host_port_specific = TRUE;
    }

    dst->sendcert =  src->sendcert;

    /* save the originally provided hint */
    dst->saved_hint_addr = dst->host_addr;

    /* see if we should try to resolve the DNS name */
    /* dst->host_addr may already have a hint, do not destroy it! */
    if(dst->host_type == KH_IPHOSTNAME
       && dst->host_addr_name!=NULL && strlen(dst->host_addr_name) > 0) {
        dst->host_address_list.addresses_available = FALSE;
        kick_adns_connection_lookup(conn, dst, TRUE);
    } else {
        dst->host_address_list.addresses_available = TRUE;
    }

    return same_ca;
}

void
setup_client_ports(struct spd_route *sr)
{
    if(!sr->this.has_port_wildcard) {
	setportof(htons(sr->this.port), &sr->this.client.addr);
    }
    if(!sr->that.has_port_wildcard) {
	setportof(htons(sr->that.port), &sr->that.client.addr);
    }
}

static bool
check_connection_end(const struct whack_end *this, const struct whack_end *that
, const struct whack_message *wm)
{
    if ((this->host_type == KH_IPADDR || this->host_type == KH_IFACE)
	&& wm->addr_family != 0
	&& (wm->addr_family != addrtypeof(&this->host_addr)
	    || wm->addr_family != addrtypeof(&this->host_nexthop)))
    {
	/* this should have been diagnosed by whack, so we need not be clear
	 * !!! overloaded use of RC_CLASH
	 */
	loglog(RC_CLASH, "address family inconsistency in this connection=%s host=%s/nexthop=%s"
	       , (wm->addr_family)     ? aftoinfo(wm->addr_family)->name                 : "NULL"
	       , (&this->host_addr)    ? aftoinfo(addrtypeof(&this->host_addr))->name    : "NULL"
	       , (&this->host_nexthop) ? aftoinfo(addrtypeof(&this->host_nexthop))->name : "NULL");
	return FALSE;
    }

    if (this->host_type == KH_IPADDR && that->host_type == KH_IPADDR
	&& subnettypeof(&this->client) != subnettypeof(&that->client))
    {
	/* this should have been diagnosed by whack, so we need not be clear
	 * !!! overloaded use of RC_CLASH
	 */
	loglog(RC_CLASH, "address family inconsistency in this/that connection");
	return FALSE;
    }

    /* MAKE this more sane in the face of unresolved IP addresses */
    if (that->host_type != KH_IPHOSTNAME
        && KH_ISWILDCARD(that->host_type))
    {
	if (!NEVER_NEGOTIATE(wm->policy))
	{
	    /* check that all main mode RW IKE policies agree because we must
	     * implement them before the correct connection is known.
	     * We cannot enforce this for other non-RW connections because
	     * differentiation is possible when a command specifies which
	     * to initiate.
	     * aggressive mode IKE policies do not have to agree amongst
	     * themselves as the ID is known from the outset.
	     */
	    const struct connection *c = NULL;

	    c = find_host_pair_connections(__FUNCTION__
                                           , ANY_MATCH
					   , NULL
					   , this->host_port
                                           , KH_ANY
					   , (const ip_address *)NULL
					   , that->host_port);

	    for (; c != NULL; c = c->IPhp_next)
	    {
		if (c->policy & POLICY_AGGRESSIVE)
			continue;

                /* if IKEv1 is now allowed, then there is no problem */
		if (c->policy & POLICY_IKEV1_DISABLE)
			continue;
#if 1
		if (!NEVER_NEGOTIATE(c->policy)
                    && ((c->policy ^ wm->policy) & (POLICY_PSK | POLICY_RSASIG)))
                    {
                        loglog(RC_CLASH
                               , "authentication method disagrees with \"%s\", which is also for an unspecified peer"
                               , c->name);
                        return FALSE;
                    }
#endif
	    }
	}
    }

#if 0
    /*
     * Virtual IP is also valid with rightsubnet=vnet:%priv or with
     * rightprotoport=17/%any
     */
    if ((this->virt) && (!isanyaddr(&this->host_addr) || this->has_client)) {
	loglog(RC_CLASH,
	    "virtual IP must only be used with %%any and without client");
	return FALSE;
    }
#endif

    return TRUE;	/* happy */
}

struct connection *
find_connection_by_reqid(uint32_t reqid)
{
    struct connection *c;

    reqid &= ~3;
    for (c = connections; c != NULL; c = c->ac_next)
    {
	if (c->spd.reqid == reqid)
	    return c;
    }

    return NULL;
}

static uint32_t
gen_reqid(void)
{
    uint32_t start;
    static uint32_t reqid = IPSEC_MANUAL_REQID_MAX & ~3;

    start = reqid;
    do {
	reqid += 4;
	if (reqid == 0)
	    reqid = (IPSEC_MANUAL_REQID_MAX & ~3) + 4;
	if (!find_connection_by_reqid(reqid))
	    return reqid;
    } while (reqid != start);

    exit_log("unable to allocate reqid");
    return 0; /* never reached, here to make compiler happy */
}

void
add_connection(const struct whack_message *wm)
{
    struct alg_info_ike *alg_info_ike;
    const char *ugh;

    int family = wm->addr_family;

    alg_info_ike = NULL;

    if (con_by_name(wm->name, FALSE) != NULL)
    {
	loglog(RC_DUPNAME, "attempt to redefine connection \"%s\"", wm->name);
    }
#if 0
    /*
     * A valid proposal done by others to which we need to respond is something like
     *  port 80 only, which is assymetric, eg leftprotoport=6/80 rightprotoport=6/%any
     * So this check is disabled, but it has not been verified this assumption is not
     *  assumed elsewhere.  -- Paul
     */
    else if (wm->right.protocol != wm->left.protocol)
    {
	/* this should haven been diagnosed by whack
	 * !!! overloaded use of RC_CLASH
	 */
	loglog(RC_CLASH, "the protocol must be the same for leftport and rightport");
    }
#endif
    else if(wm->ike != NULL
	    && ((alg_info_ike = alg_info_ike_create_from_str(wm->ike, &ugh))==NULL
		|| alg_info_ike->alg_info_cnt==0)) {
	if (alg_info_ike!= NULL && alg_info_ike->alg_info_cnt==0) {
	    loglog(RC_NOALGO
		   , "got 0 transforms for ike=\"%s\""
		   , wm->ike);
	    return;
	}

	loglog(RC_NOALGO
	       , "esp string error: %s"
	       , ugh? ugh : "Unknown");
	return;
    }
    else if ((wm->ike == NULL || alg_info_ike != NULL)
	     && check_connection_end(&wm->right, &wm->left, wm)
	     && check_connection_end(&wm->left, &wm->right, wm))
    {
	bool same_rightca, same_leftca;
	struct connection *c = alloc_thing(struct connection, "struct connection");

	/* set this up so that we can log which end is which after orient */
	c->spd.this.left = TRUE;
	c->spd.that.left = FALSE;

	same_rightca = same_leftca = FALSE;
	c->name = wm->name;
	c->connalias = wm->connalias;

#ifdef XAUTH_USEPAM
	c->pamh = NULL;
#endif

#ifdef XAUTH
	c->cisco_dns_info = NULL;
	c->cisco_domain_info = NULL;
	c->cisco_banner = NULL;
#endif

	c->policy = wm->policy;

	DBG(DBG_CONTROL,
	    DBG_log("Added new connection %s with policy %s"
		    , c->name
		    , prettypolicy(c->policy)));

	if ((c->policy & POLICY_COMPRESS) && !can_do_IPcomp)
	    loglog(RC_COMMENT
		, "ignoring --compress in \"%s\" because KLIPS is not configured to do IPCOMP"
		, c->name);

	c->alg_info_esp = NULL;
#ifdef KERNEL_ALG
	if (wm->esp)
	{
		DBG(DBG_CONTROL, DBG_log("from whack: got --esp=%s", wm->esp ? wm->esp: "NULL"));

		if( (c->policy & POLICY_AUTHENTICATE)
		    && (c->policy & POLICY_ENCRYPT)) {
		    loglog(RC_NOALGO, "Can only do AH, or ESP, not AH+ESP\n");
		    pfree(c);
		    return;
		}
		if( !(c->policy & POLICY_AUTHENTICATE)
		    && !(c->policy & POLICY_ENCRYPT)) {
		    loglog(RC_NOALGO, "Must do at AH or ESP, not neither.\n");
		    pfree(c);
		    return;
		}

		if(c->policy & POLICY_ENCRYPT) {
		    c->alg_info_esp = alg_info_esp_create_from_str(wm->esp? wm->esp : "", &ugh, FALSE);
		}

		if(c->policy & POLICY_AUTHENTICATE) {
		    c->alg_info_esp = alg_info_ah_create_from_str(wm->esp? wm->esp : "", &ugh, FALSE);
		}

		DBG(DBG_CRYPT|DBG_CONTROL,
			static char buf[256]="<NULL>";
			if (c->alg_info_esp)
				alg_info_snprint(buf, sizeof(buf),
						 (struct alg_info *)c->alg_info_esp, TRUE);
			DBG_log("esp string values: %s", buf);
		);
		if (c->alg_info_esp) {
			if (c->alg_info_esp->alg_info_cnt==0) {
				loglog(RC_NOALGO
					, "got 0 transforms for esp=\"%s\""
					, wm->esp);
				pfree(c);
				return;
			}
		} else {
			loglog(RC_NOALGO
				, "esp string error: %s"
				, ugh? ugh : "Unknown");
			pfree(c);
			return;
		}
	}
#endif

	c->alg_info_ike = NULL;
#ifdef IKE_ALG
	if (wm->ike)
	{
	    c->alg_info_ike = alg_info_ike;

	    DBG(DBG_CRYPT|DBG_CONTROL,
		char buf[256];
		alg_info_snprint(buf, sizeof(buf),
				 (struct alg_info *)c->alg_info_ike, TRUE);
		DBG_log("ike (phase1) algorihtm values: %s", buf);
		);
	    if (c->alg_info_ike) {
		if (c->alg_info_ike->alg_info_cnt==0) {
		    loglog(RC_NOALGO
			   , "got 0 transforms for ike=\"%s\""
			   , wm->ike);
		    pfree(c);
		    return;
		}
	    } else {
		loglog(RC_NOALGO
		       , "ike string error: %s"
		       , ugh? ugh : "Unknown");
		pfree(c);
		return;
	    }
	}
#endif
	c->sa_ike_life_seconds = wm->sa_ike_life_seconds;
	c->sa_ipsec_life_seconds = wm->sa_ipsec_life_seconds;
	c->sa_rekey_margin = wm->sa_rekey_margin;
	c->sa_rekey_fuzz = wm->sa_rekey_fuzz;
	c->sa_keying_tries = wm->sa_keying_tries;

	if (c->sa_rekey_margin >= c->sa_ipsec_life_seconds) {
		time_t new_rkm;

		new_rkm = c->sa_ipsec_life_seconds / 2;

		openswan_log("conn: %s, rekeymargin (%lus) > salifetime (%lus); "
				"reducing rekeymargin to %lu seconds", c->name,
				c->sa_rekey_margin, c->sa_ipsec_life_seconds,
				new_rkm);

		c->sa_rekey_margin = new_rkm;
	}

	/* RFC 3706 DPD */
        c->dpd_delay = wm->dpd_delay;
        c->dpd_timeout = wm->dpd_timeout;
        c->dpd_action = wm->dpd_action;

        /* Cisco interop: remote peer type */
        c->remotepeertype=wm->remotepeertype;

	c->sha2_truncbug=wm->sha2_truncbug;

        /* Network Manager support */
#ifdef HAVE_NM
	c->nmconfigured=wm->nmconfigured;
#endif

#ifdef HAVE_LABELED_IPSEC
	c->loopback  = wm->loopback;
	c->labeled_ipsec = wm->labeled_ipsec;
	c->policy_label = NULL;
	if(wm->policy_label) {
	c->policy_label = clone_str(wm->policy_label, "security label");
	}
	DBG(DBG_CONTROL, DBG_log("loopback=%d labeled_ipsec=%d, policy_label=%s", c->loopback, c->labeled_ipsec, c->policy_label));
#endif

	c->metric = wm->metric;
	c->connmtu = wm->connmtu;

	c->forceencaps = wm->forceencaps;

        if(family == 0) {
	  if(addrtypeof(&c->spd.this.host_addr) != 0) {
    	    family = addrtypeof(&c->spd.this.host_addr);
          }
	  if(addrtypeof(&c->spd.that.host_addr) != 0) {
    	    family = addrtypeof(&c->spd.that.host_addr);
          }
        }

	c->addr_family = family;
	c->tunnel_addr_family = wm->tunnel_addr_family;

	c->requested_ca = NULL;

        same_leftca  = extract_end(c, &c->spd.this, &wm->left, "left");
        same_rightca = extract_end(c, &c->spd.that, &wm->right, "right");

	if (c->spd.this.xauth_server || c->spd.that.xauth_server)
	{
	    c->policy |= POLICY_XAUTH;
	}

	if (same_rightca)
	    c->spd.that.ca = c->spd.this.ca;
	else if (same_leftca)
	    c->spd.this.ca = c->spd.that.ca;

#ifdef MODECFG
#ifdef MODECFG_DNSWINS
	c->modecfg_dns1 = wm->modecfg_dns1;
	c->modecfg_dns2 = wm->modecfg_dns2;
	c->modecfg_wins1 = wm->modecfg_wins1;
	c->modecfg_wins2 = wm->modecfg_wins2;
#endif
#endif

	default_end(&c->spd.this, &c->spd.that.host_addr);
	default_end(&c->spd.that, &c->spd.this.host_addr);

	/* force any wildcard host IP address, any wildcard subnet
	 * or any wildcard ID to that end
	 */
	if (isanyaddr(&c->spd.this.host_addr) || c->spd.this.has_client_wildcard
            || c->spd.this.has_port_wildcard || c->spd.this.id.has_wildcards)
	{
	    struct end t = c->spd.this;

	    c->spd.this = c->spd.that;
	    c->spd.that = t;
	}

	c->spd.next = NULL;
	c->spd.reqid = gen_reqid();

	/* set internal fields */
	c->instance_serial = 0;
	c->ac_next = connections;
	connections = c;
	c->interface = NULL;
	c->spd.routing = RT_UNROUTED;
	c->newest_isakmp_sa = SOS_NOBODY;
	c->newest_ipsec_sa = SOS_NOBODY;
	c->spd.eroute_owner = SOS_NOBODY;

	/* force all oppo connections to have a client */
	if (c->policy & POLICY_OPPO) {
	    c->spd.that.has_client = TRUE;
	    c->spd.that.client.maskbits=0;
	}

	if (c->policy & POLICY_GROUP)
	{
	    c->kind = CK_GROUP;
	    add_group(c);
	}
	else if (c->spd.that.has_client_wildcard)
	{
	    DBG(DBG_CONTROL, DBG_log("based upon client_wildcard policy, the connection is a template."));
	    c->kind = CK_TEMPLATE;
	}
	else if (c->spd.that.has_port_wildcard)
	{
	    DBG(DBG_CONTROL, DBG_log("based upon port_wildcard policy, the connection is a template."));
	    c->kind = CK_TEMPLATE;
	}
	else if ((c->policy & POLICY_SHUNT_MASK) == 0  && c->spd.that.id.has_wildcards )
	{
	    DBG(DBG_CONTROL, DBG_log("based upon ID_wildcard policy, the connection is a template."));
	    c->kind = CK_TEMPLATE;
	}
	else if ((wm->left.virt != NULL) || (wm->right.virt != NULL))
	{
	   /* If we have a subnet=vnet: needing instantiation so we can accept multiple subnets from the remote peer */
	    c->kind = CK_TEMPLATE;
	}
	else
	{
	    c->kind = CK_PERMANENT;
	}



	set_policy_prio(c);	/* must be after kind is set */

#ifdef DEBUG
	c->extra_debugging = wm->debugging;
#endif

	c->gw_info = NULL;

	passert(!(wm->left.virt && wm->right.virt));
	if (wm->left.virt || wm->right.virt) {
	    /*
	     * This now happens with wildcards on non-instantiations,
	     * such as rightsubnet=vnet:%priv or rightprotoport=17/%any
	     * passert(isanyaddr(&c->spd.that.host_addr));
	     */
	    c->spd.that.virt = create_virtual(c,
		wm->left.virt ? wm->left.virt : wm->right.virt);
	    if (c->spd.that.virt)
		c->spd.that.has_client = TRUE;
	}

	unshare_connection_strings(c);

	(void)orient(c, pluto_port500);
	connect_to_IPhost_pair(c);
        connect_to_IDhost_pair(c);

	/* log all about this connection */
	openswan_log("adding connection: \"%s\"", c->name);
	DBG(DBG_CONTROL,
	    char topo[CONN_BUF_LEN];

	    (void) format_connection(topo, sizeof(topo), c, &c->spd);

	    DBG_log("%s", topo);
	);

#ifdef HAVE_LABELED_IPSEC
	if(c->loopback
	   && portof(&c->spd.this.client.addr)!=portof(&c->spd.that.client.addr) ) {
	   struct spd_route *tmp_spd;
	   u_int16_t tmp_this_port, tmp_that_port;

	   tmp_spd = clone_thing(c->spd, "loopback asymmetrical policies");
	   tmp_spd->this.id.name.ptr = NULL;
	   tmp_spd->this.id.name.len = 0;
	   tmp_spd->that.id.name.ptr = NULL;
	   tmp_spd->that.id.name.len = 0;
	   tmp_spd->this.host_addr_name = NULL;
	   tmp_spd->that.host_addr_name = NULL;
	   tmp_spd->this.updown = clone_str(tmp_spd->this.updown, "updown");
	   tmp_spd->that.updown = clone_str(tmp_spd->that.updown, "updown");
	   tmp_spd->this.cert_filename = NULL;
	   tmp_spd->that.cert_filename = NULL;
	   tmp_spd->this.cert.type = 0;
	   tmp_spd->that.cert.type = 0;
	   tmp_spd->this.ca.ptr = NULL;
	   tmp_spd->that.ca.ptr = NULL;
	   tmp_spd->this.groups = NULL;
	   tmp_spd->that.groups = NULL;
	   tmp_spd->this.virt = NULL;
	   tmp_spd->that.virt = NULL;
	   tmp_spd->next = NULL;
	   c->spd.next=tmp_spd;

	   tmp_this_port= portof(&tmp_spd->this.client.addr);
	   tmp_that_port= portof(&tmp_spd->that.client.addr);
	   setportof(tmp_this_port, &tmp_spd->that.client.addr);
	   setportof(tmp_that_port, &tmp_spd->this.client.addr);
	}
#endif

#if 0
	    /* Make sure that address families can be correctly inferred
	     * from printed ends.
	     */
	    passert(c->addr_family == addrtypeof(&c->spd.this.host_addr));
	    passert(c->addr_family == addrtypeof(&c->spd.this.host_nexthop));
	    passert((c->spd.this.has_client? c->tunnel_addr_family : c->addr_family) == subnettypeof(&c->spd.this.client));


	    passert(c->addr_family == addrtypeof(&c->spd.that.host_addr));
	    passert(c->addr_family == addrtypeof(&c->spd.that.host_nexthop));
	    passert((c->spd.that.has_client? c->tunnel_addr_family : c->addr_family)
		    == subnettypeof(&c->spd.that.client));
#endif

	DBG(DBG_CONTROL,
	    DBG_log("ike_life: %lus; ipsec_life: %lus; rekey_margin: %lus;"
		" rekey_fuzz: %lu%%; keyingtries: %lu; policy: %s"
		, (unsigned long) c->sa_ike_life_seconds
		, (unsigned long) c->sa_ipsec_life_seconds
		, (unsigned long) c->sa_rekey_margin
		, (unsigned long) c->sa_rekey_fuzz
		, (unsigned long) c->sa_keying_tries
		, prettypolicy(c->policy));
	);
    } else {
	loglog(RC_FATAL, "attempt to load incomplete connection");
    }

}

/* Derive a template connection from a group connection and target.
 * Similar to instantiate().  Happens at whack --listen.
 * Returns name of new connection.  May be NULL.
 * Caller is responsible for pfreeing.
 */
char *
add_group_instance(struct connection *group, const ip_subnet *target)
{
    char namebuf[100]
	, targetbuf[SUBNETTOT_BUF];
    struct connection *t;
    char *name = NULL;

    passert(group->kind == CK_GROUP);
    passert(oriented(*group));

    /* manufacture a unique name for this template */
    subnettot(target, 0, targetbuf, sizeof(targetbuf));
    snprintf(namebuf, sizeof(namebuf), "%s#%s", group->name, targetbuf);

    if (con_by_name(namebuf, FALSE) != NULL)
    {
	loglog(RC_DUPNAME, "group name + target yields duplicate name \"%s\""
	    , namebuf);
    }
    else
    {
	t = clone_thing(*group, "group instance");
	t->name = namebuf;
	unshare_connection_strings(t);
	name = clone_str(t->name, "group instance name");
	t->spd.that.client = *target;
	t->policy &= ~(POLICY_GROUP | POLICY_GROUTED);
	t->kind = isanyaddr(&t->spd.that.host_addr) && !NEVER_NEGOTIATE(t->policy)
	    ? CK_TEMPLATE : CK_INSTANCE;

	/* reset log file info */
	t->log_file_name = NULL;
	t->log_file = NULL;
	t->log_file_err = FALSE;

	t->spd.reqid = gen_reqid();

	if (t->spd.that.virt) {
	        DBG_log("virtual_ip not supported in group instance");
		t->spd.that.virt = NULL;
	}

	/* add to connections list */
	t->ac_next = connections;
	connections = t;

	/* same host_pair as parent: stick after parent on list */
	group->IPhp_next = t;

	/* route if group is routed */
	if (group->policy & POLICY_GROUTED)
	{
	    if (!trap_connection(t))
		whack_log(RC_ROUTE, "could not route");
	}
    }
    return name;
}

/* an old target has disappeared for a group: delete instance */
void
remove_group_instance(const struct connection *group USED_BY_DEBUG
, const char *name)
{
    passert(group->kind == CK_GROUP);
    passert(oriented(*group));

    delete_connections_by_name(name, FALSE);
}

/* Common part of instantiating a Road Warrior or Opportunistic connection.
 * his_id can be used to carry over an ID discovered in Phase 1.
 * It must not disagree with the one in c, but if that is unspecified,
 * the new connection will use his_id.
 * If his_id is NULL, and c.that.id is uninstantiated (ID_NONE), the
 * new connection will continue to have an uninstantiated that.id.
 * Note: instantiation does not affect port numbers.
 *
 * Note that instantiate can only deal with a single SPD/eroute.
 */
static struct connection *
instantiate(struct connection *c, const ip_address *him
	    , const struct id *his_id)
{
    struct connection *d;
#ifdef DEBUG
    int wildcards;
#endif

    passert(c->kind == CK_TEMPLATE);
    passert(c->spd.next == NULL);

    c->instance_serial++;
    d = clone_thing(*c, "temporary connection");
    if (his_id != NULL)
    {
	passert(match_id(his_id, &d->spd.that.id, &wildcards));
	d->spd.that.id = *his_id;
	d->spd.that.id.has_wildcards = FALSE;
    }
    unshare_connection_strings(d);
    unshare_ietfAttrList(&d->spd.this.groups);
    unshare_ietfAttrList(&d->spd.that.groups);

    d->kind = CK_INSTANCE;

    passert(oriented(*d));
    d->spd.that.host_addr = *him;
    setportof(htons(c->spd.that.port), &d->spd.that.host_addr);
    default_end(&d->spd.that, &d->spd.this.host_addr);

    /* We cannot guess what our next_hop should be, but if it was
     * explicitly specified as 0.0.0.0, we set it to be him.
     * (whack will not allow nexthop to be elided in RW case.)
     */
    default_end(&d->spd.this, &d->spd.that.host_addr);
    d->spd.next = NULL;
    d->spd.reqid = gen_reqid();

    /* set internal fields */
    d->ac_next = connections;
    connections = d;
    d->spd.routing = RT_UNROUTED;
    d->newest_isakmp_sa = SOS_NOBODY;
    d->newest_ipsec_sa = SOS_NOBODY;
    d->spd.eroute_owner = SOS_NOBODY;

    /* reset log file info */
    d->log_file_name = NULL;
    d->log_file = NULL;
    d->log_file_err = FALSE;

    connect_to_IPhost_pair(d);

    /* but do not connect to ID host pair: parent should get all links */
    d->IDhost_pair = NULL;

    return d;
}

struct connection *
rw_instantiate(struct connection *c
               , const ip_address *him
               , const ip_subnet *his_net
               , const struct id *his_id)
{
    struct connection *d = instantiate(c, him, his_id);

    if (d && his_net && is_virtual_connection(c)) {
	d->spd.that.client = *his_net;
	/* d->spd.that.virt = NULL; */
	if (subnetishost(his_net) && addrinsubnet(him, his_net))
	    d->spd.that.has_client = FALSE;
    }

    if (d->policy & POLICY_OPPO)
    {
	/* This must be before we know the client addresses.
	 * Fill in one that is impossible.  This prevents anyone else from
	 * trying to use this connection to get to a particular client
	 */
	d->spd.that.client = *aftoinfo(subnettypeof(&d->spd.that.client))->none;
    }
    DBG(DBG_CONTROL
	, DBG_log("instantiated \"%s\" for %s" , d->name, ip_str(him)));
    return d;
}

#if 0
/*
 * IKEv2 instantiation
 * We needed to instantiate because we are updating our traffic selectors and subnets
 * taken frmo oppo_instantiate
 */
struct connection *
ikev2_ts_instantiate(struct connection *c
, const ip_address *our_client
, const u_int16_t our_port
, const ip_address *peer_client
, const u_int16_t peer_port
, const u_int8_t protocol)
{
    struct connection *d = instantiate(c, him, his_id);

    DBG(DBG_CONTROL,
	DBG_log("ikev2_ts instantiate d=%s from c=%s with c->routing %s, d->routing %s"
		, d->name, c->name
		, enum_name(&routing_story, c->spd.routing)
		, enum_name(&routing_story, d->spd.routing)));
    DBG(DBG_CONTROL,
	char instbuf[512];
	DBG_log("new ikev2_ts instance: %s"
		, (format_connection(instbuf, sizeof(instbuf), d, &d->spd), instbuf)));

    passert(d->spd.next == NULL);

    /* fill in our client side */
    if (d->spd.this.has_client)
    {
	/* there was a client in the abstract connection
	 * so we demand that the required client is within that subnet.
	 */
	passert(addrinsubnet(our_client, &d->spd.this.client));
	happy(addrtosubnet(our_client, &d->spd.this.client));
    }
    else
    {
	/* there was no client in the abstract connection
	 * so we demand that the required client be the host
	 */
	passert(sameaddr(our_client, &d->spd.this.host_addr));
    }

    /*
     * fill in peer's client side.
     * If the client is the peer, excise the client from the connection.
     */
    passert(addrinsubnet(peer_client, &d->spd.that.client));
    happy(addrtosubnet(peer_client, &d->spd.that.client));

    if (sameaddr(peer_client, &d->spd.that.host_addr))
	d->spd.that.has_client = FALSE;

    passert(d->gw_info == NULL);
    gw_addref(gw);
    d->gw_info = gw;

#if 0
    /* Remember if the template is routed:
     * if so, this instance applies for initiation
     * even if it is created for responding.
     */
    if (routed(c->spd.routing))
	d->instance_initiation_ok = TRUE;
#endif

    DBG(DBG_CONTROL,
	char topo[CONN_BUF_LEN];

	(void) format_connection(topo, sizeof(topo), d, &d->spd);
	DBG_log("instantiated \"%s\": %s", d->name, topo);
    );
    return d;
}
#endif

struct connection *
oppo_instantiate(struct connection *c
		 , const ip_address *him
		 , const struct id *his_id
		 , struct gw_info *gw
		 , const ip_address *our_client USED_BY_DEBUG
		 , const ip_address *peer_client)
{
    struct connection *d = instantiate(c, him, his_id);

    DBG(DBG_CONTROL,
	DBG_log("oppo instantiate d=%s from c=%s with c->routing %s, d->routing %s"
		, d->name, c->name
		, enum_name(&routing_story, c->spd.routing)
		, enum_name(&routing_story, d->spd.routing)));
    DBG(DBG_CONTROL,
	char instbuf[512];
	DBG_log("new oppo instance: %s"
		, (format_connection(instbuf, sizeof(instbuf), d, &d->spd), instbuf)));

    passert(d->spd.next == NULL);

    /* fill in our client side */
    if (d->spd.this.has_client)
    {
	/* there was a client in the abstract connection
	 * so we demand that the required client is within that subnet.
	 */
	passert(addrinsubnet(our_client, &d->spd.this.client));
	happy(addrtosubnet(our_client, &d->spd.this.client));
	/* opportunistic connections do not use port selectors */
	setportof(0, &d->spd.this.client.addr);
    }
    else
    {
	/* there was no client in the abstract connection
	 * so we demand that the required client be the host
	 */
	passert(sameaddr(our_client, &d->spd.this.host_addr));
    }

    /*
     * fill in peer's client side.
     * If the client is the peer, excise the client from the connection.
     */
    passert(d->policy & POLICY_OPPO);
    passert(addrinsubnet(peer_client, &d->spd.that.client));
    happy(addrtosubnet(peer_client, &d->spd.that.client));

    /* opportunistic connections do not use port selectors */
    setportof(0, &d->spd.that.client.addr);

    if (sameaddr(peer_client, &d->spd.that.host_addr))
	d->spd.that.has_client = FALSE;

    passert(d->gw_info == NULL);
    gw_addref(gw);
    d->gw_info = gw;

    /* Adjust routing if something is eclipsing c.
     * It must be a %hold for us (hard to passert this).
     * If there was another instance eclipsing, we'd be using it.
     */
    if (c->spd.routing == RT_ROUTED_ECLIPSED)
	d->spd.routing = RT_ROUTED_PROSPECTIVE;

    /* Remember if the template is routed:
     * if so, this instance applies for initiation
     * even if it is created for responding.
     */
    if (routed(c->spd.routing))
	d->instance_initiation_ok = TRUE;

    DBG(DBG_CONTROL,
	char topo[CONN_BUF_LEN];

	(void) format_connection(topo, sizeof(topo), d, &d->spd);
	DBG_log("instantiated \"%s\": %s", d->name, topo);
    );
    return d;
}

/* priority formatting */
void
fmt_policy_prio(policy_prio_t pp, char buf[POLICY_PRIO_BUF])
{
    if (pp == BOTTOM_PRIO)
	snprintf(buf, POLICY_PRIO_BUF, "0");
    else
	snprintf(buf, POLICY_PRIO_BUF, "%lu,%lu"
	    , pp>>16, (pp & ~(~(policy_prio_t)0 << 16)) >> 8);
}

/* Format any information needed to identify an instance of a connection.
 * Fills any needed information into buf which MUST be big enough.
 * Road Warrior: peer's IP address
 * Opportunistic: [" " myclient "==="] " ..." peer ["===" hisclient] '\0'
 */
static size_t
fmt_client(const ip_subnet *client, const ip_address *gw, const char *prefix, char buf[ADDRTOT_BUF])
{
    if (subnetisaddr(client, gw))
    {
	buf[0] = '\0';	/* compact denotation for "self" */
    }
    else
    {
	char *ap;

	strcpy(buf, prefix);
	ap = buf + strlen(prefix);
	if (subnetisnone(client))
	    strcpy(ap, "?");	/* unknown */
	else
	    subnettot(client, 0, ap, SUBNETTOT_BUF);
    }
    return strlen(buf);
}

char *
fmt_conn_instance(const struct connection *c, char buf[CONN_INST_BUF])
{
    char *p = buf;

    *p = '\0';

    if (c->kind == CK_INSTANCE)
    {
	if (c->instance_serial != 0)
	{
	    snprintf(p, CONN_INST_BUF, "[%lu]", c->instance_serial);
	    p += strlen(p);
	}

	if (c->policy & POLICY_OPPO)
	{
	    size_t w = fmt_client(&c->spd.this.client, &c->spd.this.host_addr, " ", p);

	    p += w;

	    strcpy(p, w == 0? " ..." : "=== ...");
	    p += strlen(p);

	    addrtot(&c->spd.that.host_addr, 0, p, ADDRTOT_BUF);
	    p += strlen(p);

	    (void) fmt_client(&c->spd.that.client, &c->spd.that.host_addr, "===", p);
	}
	else
	{
	    *p++ = ' ';
	    addrtot(&c->spd.that.host_addr, 0, p, ADDRTOT_BUF);
	}
    }

    return buf;
}

/* Find an existing connection for a trapped outbound packet.
 * This is attempted before we bother with gateway discovery.
 *   + this connection is routed or instance_of_routed_template
 *     (i.e. approved for on-demand)
 *   + this subnet contains our_client (or we are our_client)
 *   + that subnet contains peer_client (or peer is peer_client)
 *   + don't care about Phase 1 IDs (we don't know)
 * Note: result may still need to be instantiated.
 * The winner has the highest policy priority.
 *
 * If there are several with that priority, we give preference to
 * the first one that is an instance.
 *
 * See also build_outgoing_opportunistic_connection.
 */
struct connection *
find_connection_for_clients(struct spd_route **srp,
			    const ip_address *our_client,
			    const ip_address *peer_client,
			    int transport_proto)
{
    struct connection *c = connections, *best = NULL;
    policy_prio_t best_prio = BOTTOM_PRIO;
    struct spd_route *sr;
    struct spd_route *best_sr;
    int our_port  = ntohs(portof(our_client));
    int peer_port = ntohs(portof(peer_client));

    best_sr = NULL;

    passert(!isanyaddr(our_client) && !isanyaddr(peer_client));

    DBG(DBG_CONTROL,
	char ocb[ADDRTOT_BUF];
	char pcb[ADDRTOT_BUF];

	addrtot(our_client, 0, ocb, sizeof(ocb));
	addrtot(peer_client, 0, pcb, sizeof(pcb));
	DBG_log("find_connection: "
		"looking for policy for connection: %s:%d/%d -> %s:%d/%d"
		, ocb, transport_proto, our_port, pcb, transport_proto, peer_port));


    for (c = connections; c != NULL; c = c->ac_next)
    {
	if (c->kind == CK_GROUP)
	    continue;

	for (sr = &c->spd; best!=c && sr; sr = sr->next)
	{
	    if ((routed(sr->routing) || c->instance_initiation_ok)
	    && addrinsubnet(our_client, &sr->this.client)
 	    && addrinsubnet(peer_client, &sr->that.client)
 	    && (!sr->this.protocol || transport_proto == sr->this.protocol)
 	    && (!sr->this.port || our_port == sr->this.port)
 	    && (!sr->that.port || peer_port == sr->that.port))
	    {

 		policy_prio_t prio = 8 * (c->prio + (c->kind == CK_INSTANCE))
 				   + 2 * (sr->this.port == our_port)
 				   + 2 * (sr->that.port == peer_port)
 				   +     (sr->this.protocol == transport_proto);

		DBG(DBG_CONTROLMORE,
		{
		    char cib[CONN_INST_BUF];
		    char c_ocb[SUBNETTOT_BUF];
		    char c_pcb[SUBNETTOT_BUF];

		    subnettot(&c->spd.this.client, 0, c_ocb, sizeof(c_ocb));
		    subnettot(&c->spd.that.client, 0, c_pcb, sizeof(c_pcb));
 		    DBG_log("find_connection: "
 			    "conn \"%s\"%s has compatible peers: %s -> %s [pri: %ld]"
			    , c->name
			    , (fmt_conn_instance(c, cib), cib)
			    , c_ocb, c_pcb, prio);
		}
		);

		if (best == NULL)
		{
		    best = c;
		    best_sr = sr;
		    best_prio = prio;
		}

		DBG(DBG_CONTROLMORE,
		{
		    char cib[CONN_INST_BUF];
		    char cib2[CONN_INST_BUF];
		    DBG_log("find_connection: comparing best \"%s\"%s [pri:%ld]{%p} (child %s) to \"%s\"%s [pri:%ld]{%p} (child %s)"
			    , best->name
			    , (fmt_conn_instance(best, cib), cib)
			    , best_prio
			    , best
			    , (best->policy_next ? best->policy_next->name : "none")
			    , c->name
			    , (fmt_conn_instance(c, cib2), cib2)
			    , prio
			    , c
			    , (c->policy_next ? c->policy_next->name : "none"));
		}
		);

		if (prio > best_prio)
		{
		    best = c;
		    best_sr = sr;
		    best_prio = prio;
		}
	    }
	}
    }

    if (best!= NULL && NEVER_NEGOTIATE(best->policy)) {
	best = NULL;
    }

    if (srp != NULL && best != NULL)
	*srp = best_sr;

#ifdef DEBUG
    if (DBGP(DBG_CONTROL))
    {
	if (best)
	{
	    char cib[CONN_INST_BUF];
	    DBG_log("find_connection: concluding with \"%s\"%s [pri:%ld]{%p} kind=%s"
		    , best->name
		    , (fmt_conn_instance(best, cib), cib)
		    , best_prio
		    , best
		    , enum_name(&connection_kind_names, best->kind));
	} else {
	    DBG_log("find_connection: concluding with empty");
	}
    }
#endif /* DEBUG */

    return best;
}

/* Find and instantiate a connection for an outgoing Opportunistic connection.
 * We've already discovered its gateway.
 * We look for a the connection such that:
 *   + this is one of our interfaces
 *   + this subnet contains our_client (or we are our_client)
 *     (we will specialize the client).  We prefer the smallest such subnet.
 *   + that subnet contains peer_clent (we will specialize the client).
 *     We prefer the smallest such subnet.
 *   + is opportunistic
 *   + that peer is NO_IP
 *   + don't care about Phase 1 IDs (probably should be default)
 * We could look for a connection that already had the desired peer
 * (rather than NO_IP) specified, but it doesn't seem worth the
 * bother.
 *
 * We look for the routed policy applying to the narrowest subnets.
 * We only succeed if we find such a policy AND it is satisfactory.
 *
 * The body of the inner loop is a lot like that in
 * find_connection_for_clients.  In this case, we know the gateways
 * that we need to instantiate an opportunistic connection.
 */
struct connection *
build_outgoing_opportunistic_connection(struct gw_info *gw
					,const ip_address *our_client
					,const ip_address *peer_client)
{
    struct iface_port *p;
    struct connection *best = NULL;
    struct spd_route *sr, *bestsr;
    char ocb[ADDRTOT_BUF], pcb[ADDRTOT_BUF];

    addrtot(our_client, 0, ocb, sizeof(ocb));
    addrtot(peer_client, 0, pcb, sizeof(pcb));

    passert(!isanyaddr(our_client) && !isanyaddr(peer_client));

    /* We don't know his ID yet, so gw id must be an ipaddr */
    passert(gw->key != NULL);
    passert(id_is_ipaddr(&gw->gw_id));

    /* for each of our addresses... */
    for (p = interfaces; p != NULL; p = p->next)
    {
	/* go through those connections with our address and NO_IP as hosts
	 * We cannot know what port the peer would use, so we assume
	 * that it is pluto_port (makes debugging easier).
	 */
	struct connection *c = find_host_pair_connections(__FUNCTION__, ANY_MATCH, &p->ip_addr
							  , pluto_port500
                                                          , KH_ANY
							  , (ip_address *)NULL
							  , pluto_port500);

	for (; c != NULL; c = c->IPhp_next)
	{
	    DBG(DBG_OPPO,
		DBG_log("checking %s", c->name));
	    if (c->kind == CK_GROUP)
	    {
		continue;
	    }

	    for (sr = &c->spd; best!=c && sr; sr = sr->next)
	    {
		if (routed(sr->routing)
		&& addrinsubnet(our_client, &sr->this.client)
		&& addrinsubnet(peer_client, &sr->that.client))
		{
		    if (best == NULL)
		    {
			best = c;
			break;
		    }

		    DBG(DBG_OPPO,
			DBG_log("comparing best %s to %s"
				, best->name, c->name));

		    for (bestsr = &best->spd; best!=c && bestsr; bestsr=bestsr->next)
		    {
			if (!subnetinsubnet(&bestsr->this.client, &sr->this.client)
			|| (samesubnet(&bestsr->this.client, &sr->this.client)
			     && !subnetinsubnet(&bestsr->that.client
						, &sr->that.client)))
			{
			    best = c;
			}
		    }
		}
	    }
	}
    }

    if (best == NULL
    || NEVER_NEGOTIATE(best->policy)
    || (best->policy & POLICY_OPPO) == LEMPTY
    || best->kind != CK_TEMPLATE)
	return NULL;
    else
	return oppo_instantiate(best, &gw->gw_id.ip_addr, NULL, gw
			      , our_client, peer_client);
}

/* Find the connection to connection c's peer's client with the
 * largest value of .routing.  All other things being equal,
 * preference is given to c.  If none is routed, return NULL.
 *
 * If erop is non-null, set *erop to a connection sharing both
 * our client subnet and peer's client subnet with the largest value
 * of .routing.  If none is erouted, set *erop to NULL.
 *
 * The return value is used to find other connections sharing a route.
 * *erop is used to find other connections sharing an eroute.
 */
struct connection *
route_owner(struct connection *c
	    , const struct spd_route *cur_spd
	    , struct spd_route **srp
	    , struct connection **erop
	    , struct spd_route **esrp)
{
    struct connection *d
	, *best_ro = c
	, *best_ero = c;
    struct spd_route *srd, *src;
    struct spd_route *best_sr, *best_esr;
    enum routing_t best_routing, best_erouting;

    passert(oriented(*c));
    best_sr  = NULL;
    best_esr = NULL;
    best_routing = cur_spd->routing;
    best_erouting = best_routing;

    for (d = connections; d != NULL; d = d->ac_next)
    {

#ifdef KLIPS_MAST
	/* in mast mode we must also delete the iptables rule */
	if (kern_interface == USE_MASTKLIPS)
	    if (compatible_overlapping_connections(c, d))
		continue;
#endif

	for (srd = &d->spd; srd; srd = srd->next)
	{
	    if (srd->routing == RT_UNROUTED)
		continue;

	    for (src = &c->spd; src; src=src->next)
	    {
		if (src==srd)
		    continue;

		if (!samesubnet(&src->that.client, &srd->that.client))
		    continue;
		if (src->that.protocol != srd->that.protocol)
		    continue;
		if (src->that.port != srd->that.port)
		    continue;

		/* with old eroutes/routing, we could not do this. This
		 * allows a host with two IP's to talk to 1 oter host
		 * with both IP's using two different tunnels.
		 */
		if (!sameaddr(&src->this.host_addr, &srd->this.host_addr))
			continue;

		passert(oriented(*d));
		if (srd->routing > best_routing)
		{
		    best_ro = d;
		    best_sr = srd;
		    best_routing = srd->routing;
		}

		if (!samesubnet(&src->this.client, &srd->this.client))
		    continue;
		if (src->this.protocol != srd->this.protocol)
		    continue;
		if (src->this.port != srd->this.port)
		    continue;
		if (srd->routing > best_erouting)
		{
		    best_ero = d;
		    best_esr = srd;
		    best_erouting = srd->routing;
		}
	    }
	}
    }

    DBG(DBG_CONTROL,
	{
	    char cib[CONN_INST_BUF];
	    err_t m = builddiag("route owner of \"%s\"%s %s:"
		, c->name
		, (fmt_conn_instance(c, cib), cib)
		, enum_name(&routing_story, cur_spd->routing));

	    if (!routed(best_routing))
		m = builddiag("%s NULL", m);
	    else if (best_ro == c)
		m = builddiag("%s self", m);
	    else
		m = builddiag("%s \"%s\"%s %s", m
		    , best_ro->name
		    , (fmt_conn_instance(best_ro, cib), cib)
		    , enum_name(&routing_story, best_routing));

	    if (erop != NULL)
	    {
		m = builddiag("%s; eroute owner:", m);
		if (!erouted(best_ero->spd.routing))
		    m = builddiag("%s NULL", m);
		else if (best_ero == c)
		    m = builddiag("%s self", m);
		else
		    m = builddiag("%s \"%s\"%s %s", m
			, best_ero->name
			, (fmt_conn_instance(best_ero, cib), cib)
			, enum_name(&routing_story, best_ero->spd.routing));
	    }

	    DBG_log("%s", m);
	});

    if (erop != NULL)
	*erop = erouted(best_erouting)? best_ero : NULL;

    if (srp != NULL )
    {
	*srp = best_sr;
	if (esrp != NULL )
	    *esrp = best_esr;
    }

    return routed(best_routing)? best_ro : NULL;
}

static struct connection *
find_match_by_policy(struct connection *c, lset_t policy_set, lset_t policy_clear,
                     const char *policy_set_buf, const char *policy_clear_buf,
                     struct connection **pPolicy_hint)
{
    struct connection *c_without_version_policy = NULL;

    if (policy_set != LEMPTY || policy_clear != LEMPTY) {
	/*
	 * if we have requirements for the policy, choose the first matching
	 * connection.
	 */
	DBG(DBG_CONTROLMORE,
		DBG_log("searching for connection with policy = %s/%s"
                        , policy_set_buf, policy_clear_buf));

	for (; c != NULL; c = c->IPhp_next) {
            lset_t policy_without_ikeversion = (c->policy & (~POLICY_IKEV1_DISABLE)) | POLICY_IKEV2_ALLOW;

	    DBG(DBG_CONTROLMORE,
		DBG_log("found policy = %s (%s)"
			, bitnamesof(sa_policy_bit_names, c->policy)
			, c->name));

	    if(NEVER_NEGOTIATE(c->policy)) continue;

            /* XAUTH must match true/false exactly */
	    if ((policy_set & POLICY_XAUTH) != (c->policy & POLICY_XAUTH)) continue;

	    if ((c->policy & policy_set) == policy_set
                && (c->policy & policy_clear) == 0) {
		break;
            }

            /* this is a bit of comparison specific to IKEv1/IKEv2, because we need to
             * lead a bread trail to indicate if we could have found something, had
             * the policy ignored IKE version info
             */
            if((policy_without_ikeversion & policy_set)==policy_set
               && (policy_without_ikeversion & policy_clear)==0) {
                c_without_version_policy = c;
            }

            DBG(DBG_CONTROL,
                DBG_log("connection %s (policy=%s) does not match desired policy %s (~ %s) [withoutversion: %s]"
                        , c->name
                        , bitnamesof(sa_policy_bit_names, c->policy)
                        , policy_set_buf, policy_clear_buf
                        , c_without_version_policy ? c_without_version_policy->name : "none"));
	}

    }

    if(c==NULL && c_without_version_policy) {
        DBG(DBG_CONTROL,
            DBG_log("connection %s (policy=%s) would have matched, but ike version policy was wrong"
                    , c_without_version_policy->name
                    , bitnamesof(sa_policy_bit_names, c_without_version_policy->policy)));
        if(pPolicy_hint) {
            *pPolicy_hint = c_without_version_policy;
        }
    }

    return c;
}

/* Find some connection with this pair of hosts.
 * We don't know enough to chose amongst those available.
 * ??? no longer usefully different from find_host_pair_connections
 */
struct connection *
find_host_connection2(const char *func, bool exact
                      , const ip_address *me, u_int16_t my_port
                      , enum keyword_host histype
                      , const ip_address *him, u_int16_t his_port
                      , lset_t policy_set, lset_t policy_clear
                      , lset_t *pPolicy_IkeVersion)
{
    struct connection *c;
    struct connection *cWithoutIkePolicy = NULL;
    struct connection *cWithoutIkePolicy_any = NULL;
    char policy_set_buf[128];
    char policy_clear_buf[128];
    zero(policy_set_buf);
    zero(policy_clear_buf);

    bitnamesofb(sa_policy_bit_names, policy_set, policy_set_buf, sizeof(policy_set_buf));
    strcpy(policy_clear_buf, "-");
    if(policy_clear) {
        bitnamesofb(sa_policy_bit_names, policy_clear, policy_clear_buf, sizeof(policy_clear_buf));
    }


    DBG(DBG_CONTROLMORE,
        char mebuf[ADDRTOT_BUF];
        char himbuf[ADDRTOT_BUF];
	DBG_log("find_host_connection2 called from %s, me=%s:%d him=%s:%d policy=%s/%s", func
		, (addrtot(me,  0, mebuf,  sizeof(mebuf)),mebuf),   my_port
		, him ?  (addrtot(him, 0, himbuf, sizeof(himbuf)),himbuf) : "%any"
		, his_port , policy_set_buf, policy_clear_buf));
    c = find_host_pair_connections(__FUNCTION__, exact, me, my_port, histype, him, his_port);

    c = find_match_by_policy(c, policy_set, policy_clear, policy_set_buf, policy_clear_buf, &cWithoutIkePolicy);

    if(c == NULL) {
        /* look again with right=%any */
        c = find_host_pair_connections(__FUNCTION__, ANY_MATCH, me, my_port, KH_ANY, NULL, pluto_port500);

        c = find_match_by_policy(c, policy_set, policy_clear, policy_set_buf, policy_clear_buf, &cWithoutIkePolicy_any);
    }

    DBG(DBG_CONTROLMORE,
	DBG_log("find_host_connection2 returns %s (ike=%s/%s)"
                , c ? c->name : "empty"
                , cWithoutIkePolicy     ? cWithoutIkePolicy->name     : "none"
                , cWithoutIkePolicy_any ? cWithoutIkePolicy_any->name : "none"));

    if(c == NULL && pPolicy_IkeVersion != NULL) {
        if(cWithoutIkePolicy) {
            if(policy_clear & POLICY_IKEV1_DISABLE
               && cWithoutIkePolicy->policy & POLICY_IKEV1_DISABLE) {
                *pPolicy_IkeVersion |= POLICY_IKEV1_DISABLE;
            }
            if(policy_set & POLICY_IKEV2_ALLOW
               && (cWithoutIkePolicy->policy & POLICY_IKEV2_ALLOW) == 0) {
                *pPolicy_IkeVersion |= POLICY_IKEV2_ALLOW;
            }
        }
        if(cWithoutIkePolicy_any) {
            if(policy_clear & POLICY_IKEV1_DISABLE
               && cWithoutIkePolicy_any->policy & POLICY_IKEV1_DISABLE) {
                *pPolicy_IkeVersion |= POLICY_IKEV1_DISABLE;
            }
            if(policy_set & POLICY_IKEV2_ALLOW
               && (cWithoutIkePolicy_any->policy & POLICY_IKEV2_ALLOW) == 0) {
                *pPolicy_IkeVersion |= POLICY_IKEV2_ALLOW;
            }
        }
    }

    return c;
}

/*
 * extracts the peer's ca from the chained list of public keys
 */
static chunk_t
get_peer_ca(const struct id *peer_id)
{
    struct pubkey_list *p;

    for (p = pluto_pubkeys; p != NULL; p = p->next)
    {
       struct pubkey *key = p->key;

       if (key->alg == PUBKEY_ALG_RSA && same_id(peer_id, &key->id))
       {
           return key->issuer;
       }
    }
    return empty_chunk;
}



/* given an up-until-now satisfactory connection, find the best connection
 * now that we just got the Phase 1 Id Payload from the peer.
 *
 * Comments in the code describe the (tricky!) matching criteria.
 * Although this routine could handle the initiator case,
 * it isn't currently called in this case.
 * If it were, it could "upgrade" an Opportunistic Connection
 * to a Road Warrior Connection if a suitable Peer ID were found.
 *
 * In RFC 2409 "The Internet Key Exchange (IKE)",
 * in 5.1 "IKE Phase 1 Authenticated With Signatures", describing Main
 * Mode:
 *
 *         Initiator                          Responder
 *        -----------                        -----------
 *         HDR, SA                     -->
 *                                     <--    HDR, SA
 *         HDR, KE, Ni                 -->
 *                                     <--    HDR, KE, Nr
 *         HDR*, IDii, [ CERT, ] SIG_I -->
 *                                     <--    HDR*, IDir, [ CERT, ] SIG_R
 *
 * In 5.4 "Phase 1 Authenticated With a Pre-Shared Key":
 *
 *               HDR, SA             -->
 *                                   <--    HDR, SA
 *               HDR, KE, Ni         -->
 *                                   <--    HDR, KE, Nr
 *               HDR*, IDii, HASH_I  -->
 *                                   <--    HDR*, IDir, HASH_R
 *
 * refine_host_connection could be called in two case:
 *
 * - the Responder receives the IDii payload:
 *   + [PSK] after using PSK to decode this message
 *   + before sending its IDir payload
 *   + before using its ID in HASH_R computation
 *   + [DSig] before using its private key to sign SIG_R
 *   + before using the Initiator's ID in HASH_I calculation
 *   + [DSig] before using the Initiator's public key to check SIG_I
 *
 * - the Initiator receives the IDir payload:
 *   + [PSK] after using PSK to encode previous message and decode this message
 *   + after sending its IDii payload
 *   + after using its ID in HASH_I computation
 *   + [DSig] after using its private key to sign SIG_I
 *   + before using the Responder's ID to compute HASH_R
 *   + [DSig] before using Responder's public key to check SIG_R
 *
 * refine_host_connection can choose a different connection, as long as
 * nothing already used is changed.
 *
 * In the Initiator case, the particular connection might have been
 * specified by whatever provoked Pluto to initiate.  For example:
 *	whack --initiate connection-name
 * The advantages of switching connections when we're the Initiator seem
 * less important than the disadvantages, so after FreeS/WAN 1.9, we
 * don't do this.
 */
struct connection *
refine_host_connection(const struct state *st, const struct id *peer_id
, bool initiator, bool aggrmode)
{
    struct connection *c = st->st_connection;
    u_int16_t auth = st->st_oakley.auth;
    struct connection *d;
    struct connection *best_found = NULL;
    lset_t auth_policy;
    lset_t p1mode_policy = aggrmode ? POLICY_AGGRESSIVE : LEMPTY;
    const struct RSA_private_key *my_RSA_pri = NULL;
    bool wcpip;	/* wildcard Peer IP? */
    int wildcards, best_wildcards;
    int our_pathlen, best_our_pathlen, peer_pathlen, best_peer_pathlen;
    chunk_t peer_ca;
    const chunk_t *psk;

    psk = NULL;

    our_pathlen = peer_pathlen = 0;
    best_our_pathlen  = 0;
    best_peer_pathlen = 0;
    wildcards = best_wildcards = 0;

    /* zero it, so because we will test it later, to see if we found
     * something, and the get_peer_ca code is uncertain. */
    zero(&peer_ca);

    DBG(DBG_CONTROLMORE
	 , DBG_log("refine_connection: starting with %s"
		   , c->name));

    peer_ca = get_peer_ca(peer_id);

    if (same_id(&c->spd.that.id, peer_id)
	&& (peer_ca.ptr != NULL)
	&& trusted_ca(peer_ca, c->spd.that.ca, &peer_pathlen)
	&& peer_pathlen == 0
	&& match_requested_ca(c->requested_ca, c->spd.this.ca, &our_pathlen)
	&& our_pathlen == 0
	) {

	DBG(DBG_CONTROLMORE
	    , DBG_log("refine_connection: happy with starting point: %s"
		      , c->name));

	return c;	/* peer ID matches current connection -- look no further */
    }

#if defined(XAUTH)
    auth = xauth_calcbaseauth(auth);
#endif
    switch (auth)
    {
    case OAKLEY_PRESHARED_KEY:
	auth_policy = POLICY_PSK;
	psk = get_preshared_secret(c);
	/* It should be virtually impossible to fail to find PSK:
	 * we just used it to decode the current message!
	 */
	if (psk == NULL)
	    return NULL;	/* cannot determine PSK! */
	break;

    case OAKLEY_RSA_SIG:
	auth_policy = POLICY_RSASIG;
	if (initiator)
	{
	    /* at this point, we've committed to our RSA private key:
	     * we used it in our previous message.
	     */
	    my_RSA_pri = get_RSA_private_key(c);
	    if (my_RSA_pri == NULL)
		return NULL;	/* cannot determine my RSA private key! */
	}
	break;

    default:
	bad_case(auth);
    }

    /* The current connection won't do: search for one that will.
     * First search for one with the same pair of hosts.
     * If that fails, search for a suitable Road Warrior or Opportunistic
     * connection (i.e. wildcard peer IP).
     * We need to match:
     * - peer_id (slightly complicated by instantiation)
     * - if PSK auth, the key must not change (we used it to decode message)
     * - policy-as-used must be acceptable to new connection
     * - if initiator, also:
     *   + our ID must not change (we sent it in previous message)
     *   + our RSA key must not change (we used in in previous message)
     */
    passert(c != NULL);
    d = c->IPhost_pair->connections;
    for (wcpip = FALSE; ; wcpip = TRUE)
    {
	for (; d != NULL; d = d->IPhp_next)
	{
	    bool match1 = match_id(peer_id, &d->spd.that.id, &wildcards);
	    bool match2 = trusted_ca(peer_ca, d->spd.that.ca, &peer_pathlen);
	    bool match3 = match_requested_ca(c->requested_ca, d->spd.this.ca, &our_pathlen);
	    bool match = match1 && match2 && match3;

	    DBG(DBG_CONTROLMORE
		, DBG_log("refine_connection: checking %s against %s, best=%s with match=%d(id=%d/ca=%d/reqca=%d)"
			  , c->name, d->name, best_found ? best_found->name : "(none)"
			  , match, match1, match2, match3));

	    /* ignore group connections */
	    if (d->policy & POLICY_GROUP)
		continue;

	    /* check if peer_id matches, exactly or after instantiation */
	    if (!match)
		continue;

	    /* if initiator, our ID must match exactly */
	    if (initiator && !same_id(&c->spd.this.id, &d->spd.this.id))
		continue;

	    /* authentication used must fit policy of this connection */
	    if ((d->policy & auth_policy) == LEMPTY)
		continue;	/* our auth isn't OK for this connection */

	    if ((d->policy & POLICY_AGGRESSIVE) ^ p1mode_policy)
		continue;   /* disallow phase1 main/aggressive mode mismatch */

#ifdef XAUTH
	    if (d->spd.this.xauth_server != c->spd.this.xauth_server)
		continue;	/* disallow xauth/no xauth mismatch */

	    if (d->spd.this.xauth_client != c->spd.this.xauth_client)
		continue;	/* disallow xauth/no xauth mismatch */
#endif

	    DBG(DBG_CONTROLMORE
		, DBG_log("refine_connection: checked %s against %s, now for see if best"
			  , c->name, d->name));

	    switch (auth)
	    {
	    case OAKLEY_PRESHARED_KEY:
		/* secret must match the one we already used */
		{
		    const chunk_t *dpsk = get_preshared_secret(d);

		    if (dpsk == NULL)
			continue;	/* no secret */

		    if (aggrmode) {
			/*
			 * we can change PSK mid startup in agressive mode
			 */
		    	break;
		    }

		    if (psk != dpsk)
			if (psk->len != dpsk->len
			|| memcmp(psk->ptr, dpsk->ptr, psk->len) != 0)
			    continue;	/* different secret */
		}
		break;

	    case OAKLEY_RSA_SIG:
		/* We must at least be able to find our private key.
		 * If we initiated, it must match the one we
		 * used in the SIG_I payload that we sent previously.
		 */
		{
		    const struct RSA_private_key *pri
			= get_RSA_private_key(d);

		    if (pri == NULL || (initiator && (
			!same_RSA_public_key(&my_RSA_pri->pub, &pri->pub))))
			    continue;
		}
		break;

	    default:
		bad_case(auth);
	    }

	    /* d has passed all the tests.
	     * We'll go with it if the Peer ID was an exact match.
	     */
	    if (match && wildcards == 0 && peer_pathlen == 0 && our_pathlen == 0)
		return d;

	    /* We'll remember it as best_found in case an exact
	     * match doesn't come along.
	     */
	    if (best_found == NULL || wildcards < best_wildcards
	    || ((wildcards == best_wildcards && peer_pathlen < best_peer_pathlen)
		|| (peer_pathlen == best_peer_pathlen && our_pathlen < best_our_pathlen)))
	    {
		DBG(DBG_CONTROLMORE
		    , DBG_log("refine_connection: picking new best %s (wild=%d, peer_pathlen=%d/our=%d)"
			       , d->name
			       , wildcards, peer_pathlen, our_pathlen));
		best_found = d;
		best_wildcards = wildcards;
		best_peer_pathlen = peer_pathlen;
		best_our_pathlen = our_pathlen;
	    }
	}
	if (wcpip)
	    return best_found;	/* been around twice already */

	/* Starting second time around.
	 * We're willing to settle for a connection that needs Peer IP
	 * instantiated: Road Warrior or Opportunistic.
	 * Look on list of connections for host pair with wildcard Peer IP
	 */
	d = find_host_pair_connections(__FUNCTION__, ANY_MATCH, &c->spd.this.host_addr
				       , c->spd.this.host_port
                                       , KH_ANY
				       , (ip_address *)NULL
				       , c->spd.that.host_port);
    }
}

/**
 * With virtual addressing, we must not allow someone to use an already
 * used (by another id) addr/net.
 */
static bool
is_virtual_net_used(struct connection *c, const ip_subnet *peer_net, const struct id *peer_id)
{
    struct connection *d;
    char cbuf[CONN_INST_BUF];

    for (d = connections; d != NULL; d = d->ac_next)
    {
	switch (d->kind) {
	    case CK_PERMANENT:
	    case CK_TEMPLATE:
	    case CK_INSTANCE:
		if ((subnetinsubnet(peer_net,&d->spd.that.client) ||
		     subnetinsubnet(&d->spd.that.client,peer_net)) &&
		     !same_id(&d->spd.that.id, peer_id))
		{
		    char buf[IDTOA_BUF];
		    char client[SUBNETTOT_BUF];
		    const char *cname;
		    const char *doesnot = " does not";
		    const char *esses = "";

		    subnettot(peer_net, 0, client, sizeof(client));
		    idtoa(&d->spd.that.id, buf, sizeof(buf));

		    openswan_log("Virtual IP %s overlaps with connection %s\"%s\" (kind=%s) '%s'"
				 , client
				 , d->name, fmt_conn_instance(d, cbuf)
				 , enum_name(&connection_kind_names, d->kind)
				 , buf);

		    if(!kernel_overlap_supported()) {
			openswan_log("Kernel method '%s' does not support overlapping IP ranges"
				     , kernel_if_name());
			return TRUE;

		    } else if(LIN(POLICY_OVERLAPIP, c->policy)
			      && LIN(POLICY_OVERLAPIP, d->policy)) {
			openswan_log("overlap is okay by mutual consent");

			/* look for another overlap to report on */
			break;

		    } else if(LIN(POLICY_OVERLAPIP, c->policy)
			      && !LIN(POLICY_OVERLAPIP, d->policy)) {
			/* redundant */
			cname = d->name;
			fmt_conn_instance(d, cbuf);
		    } else if(!LIN(POLICY_OVERLAPIP, c->policy)
			      && LIN(POLICY_OVERLAPIP, d->policy)) {
			cname = c->name;
			fmt_conn_instance(c, cbuf);
		    } else {
			cbuf[0]='\0';
			doesnot="";
			esses="s";
			cname="neither";
		    }

		    openswan_log("overlap is forbidden (%s%s%s agree%s to overlap)"
				 , cname
				 , cbuf
				 , doesnot
				 , esses);

		    idtoa(peer_id, buf, sizeof(buf));
		    openswan_log("Your ID is '%s'", buf);

		    return TRUE; /* already used by another one */
		}
		break;
	    case CK_GOING_AWAY:
	    default:
		break;
	}
    }
    return FALSE; /* you can safely use it */
}

/* find_client_connection: given a connection suitable for ISAKMP
 * (i.e. the hosts match), find a one suitable for IPSEC
 * (i.e. with matching clients).
 *
 * If we don't find an exact match (not even our current connection),
 * we try for one that still needs instantiation.  Try Road Warrior
 * abstract connections and the Opportunistic abstract connections.
 * This requires inverse instantiation: abstraction.
 *
 * After failing to find an exact match, we abstract the peer
 * to be NO_IP (the wildcard value).  This enables matches with
 * Road Warrior and Opportunistic abstract connections.
 *
 * After failing that search, we also abstract the Phase 1 peer ID
 * if possible.  If the peer's ID was the peer's IP address, we make
 * it NO_ID; instantiation will make it the peer's IP address again.
 *
 * If searching for a Road Warrior abstract connection fails,
 * and conditions are suitable, we search for the best Opportunistic
 * abstract connection.
 *
 * Note: in the end, both Phase 1 IDs must be preserved, after any
 * instantiation.  They are the IDs that have been authenticated.
 */

#define PATH_WEIGHT	1
#define WILD_WEIGHT	(MAX_CA_PATH_LEN+1)
#define PRIO_WEIGHT	(MAX_WILDCARDS+1)*WILD_WEIGHT

/* fc_try: a helper function for find_client_connection */
static struct connection *
fc_try(const struct connection *c
       , struct IPhost_pair *hp
       , const struct id *peer_id UNUSED
       , const struct end *our_end
       , const struct end *peer_end)
{
    struct connection *d;
    struct connection *best = NULL;
    policy_prio_t best_prio = BOTTOM_PRIO;
    int wildcards, pathlen;
    err_t virtualwhy = NULL;
    char s1[ENDCLIENTTOT_BUF],d1[ENDCLIENTTOT_BUF];
    const bool peer_net_is_host = subnetisaddr(&peer_end->client, &c->spd.that.host_addr) ||
        (c->spd.that.host_type == KH_ANY && c->spd.that.has_client == FALSE);

    endclienttot(our_end,  s1, sizeof(s1));
    endclienttot(peer_end, d1, sizeof(d1));

    for (d = hp->connections; d != NULL; d = d->IPhp_next)
    {
	struct spd_route *sr;

	if (d->policy & POLICY_GROUP)
	    continue;

	if (!(same_id(&c->spd.this.id, &d->spd.this.id)
	      && match_id(&c->spd.that.id, &d->spd.that.id, &wildcards)
	      && trusted_ca(c->spd.that.ca, d->spd.that.ca, &pathlen)))
	    continue;

    	/* compare protocol and ports */
	if (d->spd.this.protocol != our_end->protocol
	    ||  (d->spd.this.port && d->spd.this.port != our_end->port)
	    ||  d->spd.that.protocol != peer_end->protocol
            || (d->spd.that.port != peer_end->port && !d->spd.that.has_port_wildcard))
	    continue;

	/* non-Opportunistic case:
	 * our_client must match.
	 *
	 * So must peer_client, but the testing is complicated
	 * by the fact that the peer might be a wildcard
	 * and if so, the default value of that.client
	 * won't match the default peer_net.  The appropriate test:
	 *
	 * If d has a peer client, it must match peer_net.
	 * If d has no peer client, peer_net must just have peer itself.
	 */

	for (sr = &d->spd; best != d && sr != NULL; sr = sr->next)
	{
	    policy_prio_t prio;
#ifdef DEBUG
	    char s3[ENDCLIENTTOT_BUF],d3[ENDCLIENTTOT_BUF];

	    if (DBGP(DBG_CONTROLMORE))
	    {
                endclienttot(&sr->this, s3, sizeof(s3));
                endclienttot(&sr->that, d3, sizeof(d3));
		DBG_log("  fc_try trying "
			"%s:%s -> %s%s vs %s:%s -> %s%s"
			, c->name, s1, d1
			, is_virtual_connection(c) ? "(virt)" : ""
			, d->name, s3, d3
			, is_virtual_sr(sr) ? "(virt)" : "");
	    }
#endif /* DEBUG */

	    if (!samesubnet(&sr->this.client, &our_end->client)) {
		DBG(DBG_CONTROLMORE
		     , DBG_log("   our client(%s) not in our_net (%s)"
			       , s3, s1));

		continue;
	    }

	    if (sr->that.has_client)
	    {
		if (sr->that.has_client_wildcard) {
		    if (!subnetinsubnet(&peer_end->client, &sr->that.client))
			continue;
		} else {
		    if ((!samesubnet(&sr->that.client, &peer_end->client))
			&& (!is_virtual_sr(sr))
			) {
			DBG(DBG_CONTROLMORE
			     , DBG_log("   their client(%s) not in same peer_net (%s)"
				       , d3, d1));
			continue;
		    }

                    /* XXX */
		    virtualwhy=is_virtual_net_allowed(d, &peer_end->client, &sr->that.host_addr);

		    if ((is_virtual_sr(sr)) &&
			( (virtualwhy != NULL) ||
			  (is_virtual_net_used(d, &peer_end->client, peer_id?peer_id:&sr->that.id)) )) {
			DBG(DBG_CONTROLMORE
			     , DBG_log("   virtual net not allowed"));
			continue;
		    }
		}
	    }
	    else
	    {
		if (!peer_net_is_host)
		    continue;
	    }

	    /* We've run the gauntlet -- success:
	     * We've got an exact match of subnets.
	     * The connection is feasible, but we continue looking for the best.
	     * The highest priority wins, implementing eroute-like rule.
	     * - a routed connection is preferrred
	     * - given that, the smallest number of ID wildcards are preferred
	     * - given that, the shortest CA pathlength is preferred
	     */
	    prio = PRIO_WEIGHT * routed(sr->routing)
		 + WILD_WEIGHT * (MAX_WILDCARDS - wildcards)
		 + PATH_WEIGHT * (MAX_CA_PATH_LEN - pathlen)
		 + 1;
	    if (prio > best_prio)
	    {
		best = d;
		best_prio = prio;
	    }
	}
    }

    if (best != NULL && NEVER_NEGOTIATE(best->policy))
	best = NULL;

    DBG(DBG_CONTROLMORE,
	DBG_log("  fc_try concluding with %s [%ld]"
		, (best ? best->name : "none"), best_prio)
    )

    if(best == NULL) {
	if(virtualwhy != NULL) {
	    openswan_log("peer proposal was reject in a virtual connection policy because:");
	    openswan_log("  %s", virtualwhy);
	}
    }

    return best;
}

static struct connection *
fc_try_oppo(const struct connection *c
, struct IPhost_pair *hp
, const ip_subnet *our_net
, const ip_subnet *peer_net
, const u_int8_t our_protocol
, const u_int16_t our_port
, const u_int8_t peer_protocol
, const u_int16_t peer_port)
{
    struct connection *d;
    struct connection *best = NULL;
    policy_prio_t best_prio = BOTTOM_PRIO;
    int wildcards, pathlen;

    for (d = hp->connections; d != NULL; d = d->IPhp_next)
    {
	struct spd_route *sr;
	policy_prio_t prio;

	if (d->policy & POLICY_GROUP)
	    continue;

	if (!(same_id(&c->spd.this.id, &d->spd.this.id)
	      && match_id(&c->spd.that.id, &d->spd.that.id, &wildcards)
	      && trusted_ca(c->spd.that.ca, d->spd.that.ca, &pathlen)))
	    continue;

	/* compare protocol and ports */
	if (d->spd.this.protocol != our_protocol
	    ||  (d->spd.this.port && d->spd.this.port != our_port)
	    ||  d->spd.that.protocol != peer_protocol
            || (d->spd.that.port != peer_port && !d->spd.that.has_port_wildcard))
	    continue;

	/* Opportunistic case:
	 * our_net must be inside d->spd.this.client
	 * and peer_net must be inside d->spd.that.client
	 * Note: this IPhost_pair chain also has shunt
	 * eroute conns (clear, drop), but they won't
	 * be marked as opportunistic.
	 */
	for (sr = &d->spd; sr != NULL; sr = sr->next)
	{
#ifdef DEBUG
	    if (DBGP(DBG_CONTROLMORE))
	    {
		char s1[SUBNETTOT_BUF],d1[SUBNETTOT_BUF];
		char s3[SUBNETTOT_BUF],d3[SUBNETTOT_BUF];

		subnettot(our_net,  0, s1, sizeof(s1));
		subnettot(peer_net, 0, d1, sizeof(d1));
		subnettot(&sr->this.client,  0, s3, sizeof(s3));
		subnettot(&sr->that.client,  0, d3, sizeof(d3));
		DBG_log("  fc_try_oppo trying %s:%s -> %s vs %s:%s -> %s"
			, c->name, s1, d1, d->name, s3, d3);
	    }
#endif /* DEBUG */

	    if (!subnetinsubnet(our_net, &sr->this.client)
	    || !subnetinsubnet(peer_net, &sr->that.client))
		continue;

	    /* The connection is feasible, but we continue looking for the best.
	     * The highest priority wins, implementing eroute-like rule.
	     * - our smallest client subnet is preferred (longest mask)
	     * - given that, his smallest client subnet is preferred
	     * - given that, a routed connection is preferrred
	     * - given that, the smallest number of ID wildcards are preferred
	     * - given that, the shortest CA pathlength is preferred
	     */
	    prio = PRIO_WEIGHT * (d->prio + routed(sr->routing))
	    	 + WILD_WEIGHT * (MAX_WILDCARDS - wildcards)
		 + PATH_WEIGHT * (MAX_CA_PATH_LEN - pathlen);
	    if (prio > best_prio)
	    {
		best = d;
		best_prio = prio;
	    }
	}
    }

    /* if the best wasn't opportunistic, we fail: it must be a shunt */
    if (best != NULL
    && (NEVER_NEGOTIATE(best->policy)
	|| (best->policy & POLICY_OPPO) == LEMPTY))
    {
	best = NULL;
    }

    DBG(DBG_CONTROLMORE,
	DBG_log("  fc_try_oppo concluding with %s [%ld]"
		, (best ? best->name : "none"), best_prio)
    )
    return best;

}

struct connection *
find_client_connection(struct connection *c
                       , const struct end *our_end
                       , const struct end *peer_end)
{
    struct connection *d;
    struct spd_route *sr;

#ifdef DEBUG
    if (DBGP(DBG_CONTROLMORE))
    {
	char s1[ENDCLIENTTOT_BUF],d1[ENDCLIENTTOT_BUF];

	endclienttot(our_end,  s1, sizeof(s1));
	endclienttot(peer_end, d1, sizeof(d1));

	DBG_log("find_client_connection starting with %s"
	    , (c ? c->name : "(none)"));
	DBG_log("  looking for %s -> %s"
	    , s1, d1);
    }
#endif /* DEBUG */

    /* give priority to current connection
     * but even greater priority to a routed concrete connection
     */
    {
	struct connection *unrouted = NULL;
	int srnum = -1;

	for (sr = &c->spd; unrouted == NULL && sr != NULL; sr = sr->next)
	{
	    srnum++;

#ifdef DEBUG
	    if (DBGP(DBG_CONTROLMORE))
	    {
		char s2[SUBNETTOT_BUF],d2[SUBNETTOT_BUF];

		subnettot(&sr->this.client, 0, s2, sizeof(s2));
		subnettot(&sr->that.client, 0, d2, sizeof(d2));
		DBG_log("  concrete checking against sr#%d %s -> %s"
			, srnum, s2, d2);
	    }
#endif /* DEBUG */

	    if (samesubnet(&sr->this.client,    &our_end->client)
		&& samesubnet(&sr->that.client, &peer_end->client)
		&& (sr->this.protocol == our_end->protocol)
		&& (!sr->this.port || (sr->this.port == our_end->port))
		&& (sr->that.protocol == peer_end->protocol)
		&& (!sr->that.port || (sr->that.port == peer_end->port)))
	    {
		passert(oriented(*c));
		if (routed(sr->routing))
		    return c;

		unrouted = c;
	    }
	}

	/* exact match? */
	d = fc_try(c, c->IPhost_pair, NULL, our_end, peer_end);

	DBG(DBG_CONTROLMORE,
	    DBG_log("  fc_try %s gives %s"
		    , c->name
		    , (d ? d->name : "none"))
	)

	if (d == NULL)
	    d = unrouted;
    }

    if (d == NULL)
    {
	/* look for an abstract connection to match */
	struct spd_route *sra;
	struct IPhost_pair *hp = NULL;

	for (sra = &c->spd; hp==NULL && sra != NULL; sra = sra->next)
	{
	    hp = find_host_pair(/*exact*/FALSE, &sra->this.host_addr
				, sra->this.host_port
                                , KH_ANY                  /* XXX maybe some other types too */
				, NULL
				, sra->that.host_port);
#ifdef DEBUG
	    if (DBGP(DBG_CONTROLMORE))
	    {
		char s2[ENDCLIENTTOT_BUF],d2[ENDCLIENTTOT_BUF];

		endclienttot(&sra->this, s2, sizeof(s2));
		endclienttot(&sra->that, d2, sizeof(d2));

		DBG_log("  checking hostpair %s -> %s is %s"
			, s2, d2
			, (hp ? "found" : "not found"));
	    }
#endif /* DEBUG */
	}

	if (hp != NULL)
	{
	    /* RW match with actual peer_id or abstract peer_id? */
	    d = fc_try(c, hp, NULL, our_end, peer_end);

	    if (d == NULL
	    && subnetishost(&our_end->client)
	    && subnetishost(&peer_end->client))
	    {
		/* Opportunistic match?
		 * Always use abstract peer_id.
		 * Note that later instantiation will result in the same peer_id.
		 */
		d = fc_try_oppo(c, hp, &our_end->client, &peer_end->client
                                , our_end->protocol, our_end->port, peer_end->protocol, peer_end->port);
	    }
	}
    }

    DBG(DBG_CONTROLMORE,
	DBG_log("  concluding with d = %s"
		, (d ? d->name : "none"))
    )
    return d;
}

int
connection_compare(const struct connection *ca
, const struct connection *cb)
{
    int ret;

    /* DBG_log("comparing %s to %s", ca->name, cb->name);  */

    ret = strcasecmp(ca->name, cb->name);
    if (ret != 0)
	return ret;

    ret = ca->kind - cb->kind;	/* note: enum connection_kind behaves like int */
    if (ret != 0)
	return ret;

    /* same name, and same type */
    switch (ca->kind)
    {
    case CK_INSTANCE:
	return ca->instance_serial < cb->instance_serial ? -1
	    : ca->instance_serial > cb->instance_serial ? 1
	    : 0;

    default:
	return ca->prio < cb->prio ? -1
	    : ca->prio > cb->prio ? 1
	    : 0;
    }
}

static int
connection_compare_qsort(const void *a, const void *b)
{
    return connection_compare(*(const struct connection *const *)a
			    , *(const struct connection *const *)b);
}

static void
show_one_sr(struct connection *c
	    , struct spd_route *sr
	    , int num UNUSED
	    , char *instance)
{
    char topo[CONN_BUF_LEN];
    char srcip[ADDRTOT_BUF], dstip[ADDRTOT_BUF];
    char thissemi[3+sizeof("myup=")];
    char thatsemi[3+sizeof("hisup=")];
#ifdef XAUTH
    char thisxauthsemi[XAUTH_USERNAME_LEN+sizeof("myxauthuser=")];
    char thatxauthsemi[XAUTH_USERNAME_LEN+sizeof("hisxauthuser=")];
#endif
    char thiscertsemi[3+sizeof("mycert=")+PATH_MAX];
    char thatcertsemi[3+sizeof("hiscert=")+PATH_MAX];
    char *thisup, *thatup;

    (void) format_connection(topo, sizeof(topo), c, sr);
    whack_log(RC_COMMENT, "\"%s\"%s: %s; %s; eroute owner: #%lu"
	      , c->name, instance, topo
	      , enum_name(&routing_story, sr->routing)
	      , sr->eroute_owner);
    if(addrbytesptr(&c->spd.this.host_srcip, NULL) == 0
       || isanyaddr(&c->spd.this.host_srcip)) {
	strcpy(srcip, "unset");
    } else {
	addrtot(&sr->this.host_srcip, 0, srcip, sizeof(srcip));
    }
    if(addrbytesptr(&c->spd.that.host_srcip, NULL) == 0
       || isanyaddr(&c->spd.that.host_srcip)) {
	strcpy(dstip, "unset");
    } else {
	addrtot(&sr->that.host_srcip, 0, dstip, sizeof(dstip));
    }

    thissemi[0]='\0';
    thisup=thissemi;
    if(sr->this.updown) {
	thissemi[0]=';';
	thissemi[1]=' ';
	thissemi[2]='\0';
	strcat(thissemi, "myup=");
	thisup=sr->this.updown;
    }

    thatsemi[0]='\0';
    thatup=thatsemi;
    if(sr->that.updown) {
	thatsemi[0]=';';
	thatsemi[1]=' ';
	thatsemi[2]='\0';
	strcat(thatsemi, "hisup=");
	thatup=sr->that.updown;
    }

    thiscertsemi[0]='\0';
    if(sr->this.cert_filename) {
	snprintf(thiscertsemi, sizeof(thiscertsemi)-1
		 , "; mycert=%s"
		 , sr->this.cert_filename);
    }

    thatcertsemi[0]='\0';
    if(sr->that.cert_filename) {
	snprintf(thatcertsemi, sizeof(thatcertsemi)-1
		 , "; hiscert=%s"
		 , sr->that.cert_filename);
    }

    whack_log(RC_COMMENT, "\"%s\"%s:     myip=%s; hisip=%s%s%s%s%s%s%s;"
	      , c->name, instance, srcip, dstip
	      , thissemi, thisup
	      , thatsemi, thatup
	      , thiscertsemi
	      , thatcertsemi);

#ifdef XAUTH
    if(sr->this.xauth_name || sr->that.xauth_name) {
	thisxauthsemi[0]='\0';
	if(sr->this.xauth_name) {
	    snprintf(thisxauthsemi, sizeof(thisxauthsemi)-1
		     , "myxauthuser=%s; "
		     , sr->this.xauth_name);
	}

	thatxauthsemi[0]='\0';
	if(sr->that.xauth_name) {
	    snprintf(thatxauthsemi, sizeof(thatxauthsemi)-1
		     , "hisxauthuser=%s; "
		     , sr->that.xauth_name);
	}
	whack_log(RC_COMMENT, "\"%s\"%s:     xauth info: %s%s"
		  , c->name, instance
		  , thisxauthsemi
		  , thatxauthsemi);
    }
#endif
}

char *fmt_connection_inst_name(struct connection *c
                               , char *instname
                               , unsigned int instname_len)
{
    instname[0] = '\0';
    if (c->kind == CK_INSTANCE && c->instance_serial != 0)
	snprintf(instname, instname_len, "[%lu]", c->instance_serial);

    return instname;
}

void
show_one_connection(struct connection *c, logfunc logger)
{
    const char *ifn;
    char instance[1 + 10 + 1];
    char prio[POLICY_PRIO_BUF];

    ifn = oriented(*c)? c->interface->ip_dev->id_rname : "";
    fmt_connection_inst_name(c, instance, sizeof(instance));

    /* show topology */
    {
	struct spd_route *sr = &c->spd;
	int num=0;

	while (sr != NULL)
	{
	    show_one_sr(c, sr, num, instance);
	    sr = sr->next;
	    num++;
	}
    }

    /* show CAs */
    if (c->spd.this.ca.ptr != NULL || c->spd.that.ca.ptr != NULL)
    {
	char this_ca[IDTOA_BUF], that_ca[IDTOA_BUF];

	dntoa_or_null(this_ca, IDTOA_BUF, c->spd.this.ca, "%any");
	dntoa_or_null(that_ca, IDTOA_BUF, c->spd.that.ca, "%any");

	logger(RC_COMMENT
		  , "\"%s\"%s:   CAs: '%s'...'%s'"
		  , c->name
		  , instance
		  , this_ca
		  , that_ca);
    }

    logger(RC_COMMENT
	      , "\"%s\"%s:   ike_life: %lus; ipsec_life: %lus;"
	      " rekey_margin: %lus; rekey_fuzz: %lu%%; keyingtries: %lu%s%s "
	      , c->name
	      , instance
	      , (unsigned long) c->sa_ike_life_seconds
	      , (unsigned long) c->sa_ipsec_life_seconds
	      , (unsigned long) c->sa_rekey_margin
	      , (unsigned long) c->sa_rekey_fuzz
	      , (unsigned long) c->sa_keying_tries
	      , (c->sha2_truncbug) ? "; sha2_truncbug: yes" : ""
	      , (c->forceencaps) ? "; force_encaps: yes" : ""
	     );

    if (c->policy_next)
    {
	logger(RC_COMMENT
		  , "\"%s\"%s:   policy_next: %s"
		  , c->name, instance, c->policy_next->name);
    }

    /* Note: we display key_from_DNS_on_demand as if policy [lr]KOD */
    fmt_policy_prio(c->prio, prio);
    logger(RC_COMMENT
	      , "\"%s\"%s:   policy: %s%s%s; prio: %s; interface: %s; kind=%s"
	      , c->name
	      , instance
	      , prettypolicy(c->policy)
	      , c->spd.this.key_from_DNS_on_demand? "+lKOD" : ""
	      , c->spd.that.key_from_DNS_on_demand? "+rKOD" : ""
	      , prio
	      , ifn
              , enum_name(&connection_kind_names, c->kind));

    if(c->connmtu > 0 || c->metric > 0) {
	logger(RC_COMMENT
		  , "\"%s\"%s:   network params: metric:%lu; mtu:%lu; "
		  , c->name
		  , instance
		  , (unsigned long)c->metric
		  , (unsigned long)c->connmtu);
    }

    /* slightly complicated stuff to avoid extra crap */
    if(c->dpd_timeout > 0 || DBGP(DBG_DPD)) {
	logger(RC_COMMENT
		  , "\"%s\"%s:   dpd: %s; delay:%lu; timeout:%lu;  "
		  , c->name
		  , instance
		  , enum_name(&dpd_action_names, c->dpd_action)
		  , (unsigned long)c->dpd_delay
		  , (unsigned long)c->dpd_timeout);
    }

    if(c->extra_debugging) {
	logger(RC_COMMENT, "\"%s\"%s:   debug: %s"
		  , c->name
		  , instance
		  , bitnamesof(debug_bit_names
			       , c->extra_debugging));
    }

    logger(RC_COMMENT
	      , "\"%s\"%s:   newest ISAKMP SA: #%ld; newest IPsec SA: #%ld; eroute owner: #%ld;"
	      , c->name
	      , instance
	      , c->newest_isakmp_sa
              , c->newest_ipsec_sa, c->spd.eroute_owner);

    if(c->connalias) {
	logger(RC_COMMENT
		  , "\"%s\"%s:   aliases: %s\n"
		  , c->name
		  , instance
		  , c->connalias);
    }

#ifdef IKE_ALG
    ike_alg_show_connection(c, instance);
#endif
#ifdef KERNEL_ALG
    kernel_alg_show_connection(c, instance);
#endif
}

void
show_connections_status(logfunc logger)
{
    int count, i;
    struct connection *c;
    struct connection **array;

    if(logger == NULL) {
        logger = whack_log;
    }

    /* make an array of connections, and sort it */
    count=0;
    for (c = connections; c != NULL; c = c->ac_next)
    {
	count++;
    }
    if(count == 0)
	/* abort early to avoid a malloc(0) that uclibc does not like */
	return;

    array = alloc_bytes(sizeof(struct connection *)*count, "connection array");

    count=0;
    for (c = connections; c != NULL; c = c->ac_next)
    {
	array[count++]=c;
    }

    /* sort it! */
    qsort(array, count, sizeof(struct connection *), connection_compare_qsort);

    for (i=0; i<count; i++)
    {
	show_one_connection(array[i], logger);
    }
    pfree(array);
}

/* Delete a connection if it is an instance and it is no longer in use.
 * We must be careful to avoid circularity:
 * we don't touch it if it is CK_GOING_AWAY.
 */
void
connection_discard(struct connection *c)
{
    if (c->kind == CK_INSTANCE)
    {
	if(in_pending_use(c)) {
	    return;
	}

	if (!states_use_connection(c))
	    delete_connection(c, FALSE);
    }
}


/* A template connection's eroute can be eclipsed by
 * either a %hold or an eroute for an instance iff
 * the template is a /32 -> /32.  This requires some special casing.
 */

long eclipse_count = 0;

struct connection *
eclipsed(struct connection *c, struct spd_route **esrp)
{
    struct connection *ue;
    struct spd_route *sr1 = &c->spd;

    ue = NULL;

    /* This while is never true as ue is NULL.
     * The flow will never go inside while.
     * This function will return NULL.
     */
    while (sr1 != NULL && ue != NULL)
    {
	for (ue = connections; ue != NULL; ue = ue->ac_next)
	{
	    struct spd_route *srue = &ue->spd;

	    while (srue != NULL
	    && srue->routing == RT_ROUTED_ECLIPSED
	    && !(samesubnet(&sr1->this.client, &srue->this.client)
		 && samesubnet(&sr1->that.client, &srue->that.client)))
	    {
		srue = srue->next;
	    }
	    if (srue != NULL && srue->routing==RT_ROUTED_ECLIPSED)
	    {
		*esrp = srue;
		break;
	    }
	}
    }
    return ue;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
