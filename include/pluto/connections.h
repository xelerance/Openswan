/* information about connections between hosts and clients
 * Copyright (C) 1998-2015  D. Hugh Redelmeier
 * Copyright (C) 2004-2015  Michael Richardson <mcr@sandelman.ca>
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

#ifndef _CONNECTIONS_H

/* There are two kinds of connections:
 * - ISAKMP connections, between hosts (for IKE communication)
 * - IPsec connections, between clients (for secure IP communication)
 *
 * An ISAKMP connection looks like:
 *   host<--->host
 *
 * An IPsec connection looks like:
 *   client-subnet<-->host<->nexthop<--->nexthop<->host<-->client-subnet
 *
 * For the connection to be relevant to this instance of Pluto,
 * exactly one of the hosts must be a public interface of our machine
 * known to this instance.
 *
 * The client subnet might simply be the host -- this is a
 * representation of "host mode".
 *
 * Each nexthop defaults to the neighbouring host's IP address.
 * The nexthop is a property of the pair of hosts, not each
 * individually.  It is only needed for IPsec because of the
 * way IPsec is mixed into the kernel routing logic.  Furthermore,
 * only this end's nexthop is actually used.  Eventually, nexthop
 * will be unnecessary.
 *
 * Other information represented:
 * - each connection has a name: a chunk of uninterpreted text
 *   that is unique for each connection.
 * - security requirements (currently just the "policy" flags from
 *   the whack command to initiate the connection, but eventually
 *   much more.  Different for ISAKMP and IPsec connections.
 * - rekeying parameters:
 *   + time an SA may live
 *   + time before SA death that a rekeying should be attempted
 *     (only by the initiator)
 *   + number of times to attempt rekeying
 * - With the current KLIPS, we must route packets for a client
 *   subnet through the ipsec interface (ipsec0).  Only one
 *   gateway can get traffic for a specific (client) subnet.
 *   Furthermore, if the routing isn't in place, packets will
 *   be sent in the clear.
 *   "routing" indicates whether the routing has been done for
 *   this connection.  Note that several connections may claim
 *   the same routing, as long as they agree about where the
 *   packets are to be sent.
 * - With the current KLIPS, only one outbound IPsec SA bundle can be
 *   used for a particular client.  This is due to a limitation
 *   of using only routing for selection.  So only one IPsec state (SA)
 *   may "own" the eroute.  "eroute_owner" is the serial number of
 *   this state, SOS_NOBODY if there is none.  "routing" indicates
 *   what kind of erouting has been done for this connection, if any.
 *
 * Details on routing is in constants.h
 *
 * Operations on Connections:
 *
 * - add a new connection (with all details) [whack command]
 * - delete a connection (by name) [whack command]
 * - initiate a connection (by name) [whack command]
 * - find a connection (by IP addresses of hosts)
 *   [response to peer request; finding ISAKMP connection for IPsec connection]
 *
 * Some connections are templates, missing the address of the peer
 * (represented by INADDR_ANY).  These are always arranged so that the
 * missing end is "that" (there can only be one missing end).  These can
 * be instantiated (turned into real connections) by Pluto in one of two
 * different ways: Road Warrior Instantiation or Opportunistic
 * Instantiation.  A template connection is marked for Opportunistic
 * Instantiation by specifying the peer client as 0.0.0.0/32 (or the IPV6
 * equivalent).  Otherwise, it is suitable for Road Warrior Instantiation.
 *
 * Instantiation creates a new temporary connection, with the missing
 * details filled in.  The resulting template lasts only as long as there
 * is a state that uses it.
 */

/* connection policy priority: how important this policy is
 * - used to implement eroute-like precedence (augmented by a small
 *   bonus for a routed connection).
 * - a whole number
 * - larger is more important
 * - three subcomponents.  In order of decreasing significance:
 *   + length of source subnet mask (8 bits)
 *   + length of destination subnet mask (8 bits)
 *   + bias (8 bit)
 * - a bias of 1 is added to allow prio BOTTOM_PRIO to be less than all
 *   normal priorities
 * - other bias values are created on the fly to give mild preference
 *   to certaion conditions (eg. routedness)
 * - priority is inherited -- an instance of a policy has the same priority
 *   as the original policy, even though its subnets might be smaller.
 * - display format: n,m
 */
typedef uint32_t policy_prio_t;
#define BOTTOM_PRIO   ((policy_prio_t)0)	/* smaller than any real prio */
#define set_policy_prio(c) { (c)->prio = \
	((policy_prio_t)(c)->spd.this.client.maskbits << 16) \
	| ((policy_prio_t)(c)->spd.that.client.maskbits << 8) \
	| (policy_prio_t)1; }
#define POLICY_PRIO_BUF	(3+1+3+1+10) 
extern void fmt_policy_prio(policy_prio_t pp, char buf[POLICY_PRIO_BUF]);

/* Note that we include this even if not X509, because we do not want the
 * structures to change lots.
 */
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "pluto/defs.h"
#include "pluto/log.h"

struct virtual_t;

#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif

struct ietfAttr;	/* forward declaration of ietfAttr defined in ac.h */
struct IPhost_pair;    /* opaque type */
struct IDhost_pair;    /* opaque type */

struct dns_end_list {
    bool             addresses_available;
    struct addrinfo *address_list;  /* the list of all results returned */
    struct addrinfo *next_address;  /* next one to try */
};

/*
 * An end describes one side of the connection.
 *
 * There is some unfortunate and unwanted connection between the outer (end-point)
 * of the connection (which is contained in host_type, host_addr, host_port, and keys/certs)
 * and the inside part of the connection
 * (which is represented by client, has_client, has_port_wildcard, port and protocol)
 * Future work will split these, moving things around up to spd_route, as there can
 * in general be multiple outer addresses, and also multiple inner (traffic-selectors),
 * and they are not necessarily related.
 *
 * The outer host_type and host_addr may be passed to
 *
 *    const char *end_type_name(struct keyword_host host_type, ip_address *host_addr
 *                              , char  *outbuf, size_t outbuf_len)
 *
 * to create a string representation.
 *
 */
struct end {
    struct id id;
    bool      left;

    enum keyword_host host_type;
    char  *host_addr_name;       /* string version from whack */
    ip_address
	host_addr,
	host_nexthop,
	host_srcip;
    ip_address saved_hint_addr;  /* the address we got from the cfg file if IPHOSTNAME */
    struct dns_end_list host_address_list;

    bool key_from_DNS_on_demand;
    /* this section is about what's inside the SA */
    ip_subnet client;           /* consider replacing this with p2id from ikev1_quick.c */
    bool has_client;
    bool has_client_wildcard;
    bool has_port_wildcard;
    bool client_is_self;        /* true if the end point is the same as host */
    struct virtual_t *virt;
    char *updown;
    u_int16_t host_port;	/* where the IKE port is */
    bool      host_port_specific; /* if TRUE, then IKE ports are tested for*/
    u_int16_t port;		/* port number, if per-port keying. */
    u_int8_t protocol;          /* transport-protocol number, if per-X keying.*/

    enum certpolicy sendcert;   /* whether or not to send the certificate */
    char   *cert_filename;       /* where we got the certificate */
    cert_t  cert;		/* end certificate */

    chunk_t ca;			/* CA distinguished name */

    struct pubkey *key1, *key2;  /* references to the public key to be used to authenticate this connection */

    struct ietfAttrList *groups;/* access control groups */

/*#ifdef XAUTH*/
    bool xauth_server;
    bool xauth_client;
    char *xauth_name;
    char *xauth_password;
/*#ifdef MODECFG */
    bool modecfg_server;        /* Give local addresses to tunnel's end */
    bool modecfg_client;        /* request address for local end */
/*#endif*/
/*#endif*/
};

struct spd_route {
    struct spd_route *next;
    struct end this;
    struct end that;
    so_serial_t eroute_owner;
    enum routing_t routing;	/* level of routing in place */
    uint32_t reqid;
};

/*
 * Not that variables that relate to features that might in fact be disabled, or compiled
 * out remain in this structure so that the system can intelligently notice misconfigurations.
 * This also reduces much of the testing complexity of maintain the options.
 */

/* so that NULL labelled policy will be more obvious */
#define NULL_POLICY NULL

struct connection {
    char *name;
    char *connalias;
    lset_t policy;
    struct db_sa *ike_policies;
    time_t sa_ike_life_seconds;
    time_t sa_ipsec_life_seconds;
    time_t sa_rekey_margin;
    unsigned long sa_rekey_fuzz;
    unsigned long sa_keying_tries;

    /* RFC 3706 DPD */
    time_t          dpd_delay;              /* time between checks */
    time_t          dpd_timeout;            /* time after which we are dead */
    enum dpd_action dpd_action;             /* what to do when we die */

    /*Cisco interop: remote peer type*/
    enum keyword_remotepeertype remotepeertype;

    /* sha2 truncation bug work around */
    bool sha2_truncbug;

    /* Network Manager support */
    bool nmconfigured;

    /* labeled ipsec support */
    bool loopback;                          /* indicates that XXX */
    bool labeled_ipsec;
    char *policy_label;

    bool               forceencaps;         /* always use NAT-T encap */

    char              *log_file_name;       /* name of log file */
    FILE              *log_file;            /* possibly open FILE */
    CIRCLEQ_ENTRY(connection) log_link;     /* linked list of open conns {} */
    bool               log_file_err;        /* only bitch once */

    struct spd_route spd;

    unsigned int first_msgid;		/* what is the first msgid of this conn [0|1] */

    /* internal fields: */

    unsigned long instance_serial;
    policy_prio_t prio;
    bool instance_initiation_ok;	/* this is an instance of a policy that mandates initiate */
    enum connection_kind kind;
    bool                   ip_oriented; /* true iff oriented by IP address */
    const struct iface_port *interface;	/* filled in iff oriented */

    bool initiated;
    bool failed_ikev2;                  /* tried ikev2, but failed */

    bool proposal_can_retry;		/* we will retry if current proposal fails */
    unsigned int proposal_index;	/* incremented on retry */

    /* state object serial number: weak pointers */
    so_serial_t	prospective_parent_sa;  /* state we are still negotiating */
    so_serial_t newest_isakmp_sa;       /* state that is negotiated/up */
    so_serial_t newest_ipsec_sa;        /* child SA state (should be array!) */

    lset_t extra_debugging;

    /* note: if the client is the gateway, the following must be equal */
    sa_family_t end_addr_family;	/* between gateways */
    sa_family_t tunnel_addr_family;	/* between clients */

    struct connection *policy_next; /* if multiple policies,
				       next one to apply */

    struct gw_info *gw_info;
    struct alg_info_esp *alg_info_esp;
    struct alg_info_ike *alg_info_ike;

    struct IPhost_pair *IPhost_pair;   /* opaque from connections.c/hostpair.c */
    struct IDhost_pair *IDhost_pair;   /* opaque from connections.c/hostpair.c */
    struct connection *IPhp_next;	/* host pair list link */
    struct connection *IDhp_next;	/* host pair list link */

    struct connection *ac_next;	/* all connections list link */

    generalName_t *ikev1_requested_ca_names;  /* ikev1 collected certificate requests */
    generalName_t *ikev2_requested_ca_hashes; /* concatenated SHA1 hashes acceptable CA keys */
#ifdef XAUTH_USEPAM
    pam_handle_t  *pamh;		/*  PAM handle for that connection  */
#endif
#ifdef XAUTH
# ifdef MODECFG
    ip_address modecfg_dns1;
    ip_address modecfg_dns2;
    ip_address modecfg_wins1;
    ip_address modecfg_wins2;
# endif
    char *cisco_dns_info;
    char *cisco_domain_info;
    char *cisco_banner;
#endif /* XAUTH */
    u_int8_t metric;              /* metric for tunnel routes */
    u_int16_t connmtu;              /* mtu for tunnel routes */
#ifdef HAVE_STATSD
    u_int32_t statsval;			/* track what we have told statsd */
#endif
};

#define oriented(c) ((c).interface != NULL)
extern bool orient(struct connection *c, unsigned int pluto_port);

extern struct iface_port *pick_matching_interfacebyfamily(struct iface_port *iflist,
                                                          int pluto_port,
                                                          int family, struct spd_route *sr);

extern bool same_peer_ids(const struct connection *c
    , const struct connection *d, const struct id *his_id);
extern bool compare_end_addr_names(struct end *a, struct end *b);

/* Format the topology of a connection end, leaving out defaults.
 * Largest left end looks like: client === host : port [ host_id ] --- hop
 * Note: if that==NULL, skip nexthop
 */
#define END_BUF	(SUBNETTOT_BUF + ADDRTOT_BUF + IDTOA_BUF + ADDRTOT_BUF + 10)
extern size_t format_end(char *buf, size_t buf_len
    , const struct end *this, const struct end *that
    , bool is_left, lset_t policy);

struct whack_message;	/* forward declaration of tag whack_msg */
extern void add_connection(const struct whack_message *wm);
extern void initiate_connection(const char *name
				, int whackfd
				, lset_t moredebug
				, enum crypto_importance importance);
extern void restart_connections_by_peer(struct connection *c);

struct xfrm_user_sec_ctx_ike; /* forward declaration */

extern int initiate_ondemand(const ip_address *our_client
                              , const ip_address *peer_client
                              , int transport_proto
                              , bool held
                              , int whackfd
                              , struct xfrm_user_sec_ctx_ike *uctx
                              , err_t why);
extern void terminate_connection(const char *nm);
extern void release_connection(struct connection *c, bool relations);
extern void delete_connection(struct connection *c, bool relations, bool force);
extern void delete_connections_by_name(const char *name, bool strict);
extern void delete_every_connection(void);
extern void delete_sr(struct connection *c, struct spd_route *sr);
extern char *add_group_instance(struct connection *group, const ip_subnet *target);
extern void remove_group_instance(const struct connection *group, const char *name);
extern void release_dead_interfaces(void);
extern void check_orientations(void);
extern struct connection *route_owner(struct connection *c
				      , const struct spd_route *cur_spd
				      , struct spd_route **srp
				      , struct connection **erop
				      , struct spd_route **esrp);
extern struct connection *shunt_owner(const ip_subnet *ours
    , const ip_subnet *his);

extern bool uniqueIDs;	/* --uniqueids? */
extern void ISAKMP_SA_established(struct connection *c, so_serial_t serial);

#define his_id_was_instantiated(c) ((c)->kind == CK_INSTANCE \
    && (id_is_ipaddr(&(c)->spd.that.id)? \
    sameaddr(&(c)->spd.that.id.ip_addr, &(c)->spd.that.host_addr) : TRUE))

struct state;	/* forward declaration of tag (defined in state.h) */
extern struct connection
*con_by_name(const char *nm, bool strict);

#define find_host_connection(exact, me, my_port, histype, him, his_port, policy_set, policy_clear, pPolicy_hint) find_host_connection2(__FUNCTION__, exact, me, my_port, histype, him, his_port, policy_set, policy_clear, pPolicy_hint)
extern struct connection *find_host_connection2(const char *func
                                                , bool exact
                                                , const ip_address *me
                                                , u_int16_t my_port
                                                , enum keyword_host histype
                                                , const ip_address *him
                                                , u_int16_t his_port
                                                , lset_t policy_set, lset_t policy_clear, lset_t *pPolicy_hint);
extern struct connection *refine_host_connection(const struct state *st
                                                 , const struct id *id
                                                 , bool initiator, bool aggrmode);
extern struct connection *find_client_connection(struct connection *c
                                                 , const struct end *our_end
                                                 , const struct end *peer_end);
extern struct connection *find_connection_by_reqid(uint32_t reqid);

extern struct connection *
find_connection_for_clients(struct spd_route **srp
			    , const ip_address *our_client
			    , const ip_address *peer_client
 			    , int transport_proto);


/* instantiating routines
 * Note: connection_discard() is in state.h because all its work
 * is looking through state objects.
 */
struct gw_info;	/* forward declaration of tag (defined in dnskey.h) */
struct alg_info;	/* forward declaration of tag (defined in alg_info.h) */
extern struct connection *rw_instantiate(struct connection *c
					 , const ip_address *him
					 , const ip_subnet *his_net
					 , const struct id *his_id);

extern struct cnnection *ikev2_ts_instantiate(struct connection *c
					, const ip_address *our_client
					, const u_int16_t our_port
					, const ip_address *peer_client
					, const u_int16_t peer_port
					, const u_int8_t protocol);

extern struct connection *oppo_instantiate(struct connection *c
					   , const ip_address *him
					   , const struct id *his_id
					   , struct gw_info *gw
					   , const ip_address *our_client
					   , const ip_address *peer_client);

extern struct connection
  *build_outgoing_opportunistic_connection(struct gw_info *gw
					   , const ip_address *our_client
					   , const ip_address *peer_client);

/* worst case: "[" serial "] " myclient "=== ..." peer "===" hisclient '\0' */
#define CONN_INST_BUF \
    (2 + 10 + 1 + SUBNETTOT_BUF + 7 + ADDRTOT_BUF + 3 + SUBNETTOT_BUF + 1)

extern char *fmt_conn_instance(const struct connection *c
			       , char buf[CONN_INST_BUF]);

/* operations on "pending", the structure representing Quick Mode
 * negotiations delayed until a Keying Channel has been negotiated.
 */

struct pending;	/* forward declaration (opaque outside connections.c) */

extern int add_pending(int whack_sock
    , struct state *isakmp_sa
    , struct connection *c
    , lset_t policy
    , unsigned long try
    , so_serial_t replacing
    , struct xfrm_user_sec_ctx_ike * uctx
    );

extern void release_pending_whacks(struct state *st, err_t story);
extern void unpend(struct state *st);
extern int update_pending(struct state *os, struct state *ns);
extern void flush_pending_by_state(struct state *st);
extern void connection_discard(struct connection *c);

/* A template connection's eroute can be eclipsed by
 * either a %hold or an eroute for an instance iff
 * the template is a /32 -> /32.  This requires some special casing.
 */
#define eclipsable(sr) (subnetishost(&(sr)->this.client) && subnetishost(&(sr)->that.client))
extern long eclipse_count;
extern struct connection *eclipsed(struct connection *c, struct spd_route **);


/* print connection status */

extern void show_one_connection(struct connection *c, logfunc logger);
extern char *fmt_connection_inst_name(struct connection *c
                                      , char *instname
                                      , unsigned int instname_len);
extern void show_connections_status(logfunc logger);
extern int  connection_compare(const struct connection *ca
			       , const struct connection *cb);
#ifdef NAT_TRAVERSAL
extern void
update_host_pair(const char *why, struct connection *c,
       const ip_address *myaddr, u_int16_t myport ,
       const ip_address *hisaddr, u_int16_t hisport);
#endif /* NAT_TRAVERSAL */

/* export to pending.c */
extern void host_pair_enqueue_pending(const struct connection *c
			       , struct pending *p
			       , struct pending **pnext);
struct pending **host_pair_first_pending(const struct connection *c);

#ifdef DYNAMICDNS
void connection_check_ddns(void);
#endif

extern bool kick_adns_connection(struct connection *c, err_t ugh);
void connection_check_phase2(void);
void init_connections(void);

#define CONN_BUF_LEN	(2 * (END_BUF - 1) + 4)
extern size_t format_connection(char *buf, size_t buf_len
				, const struct connection *c
				, struct spd_route *sr);


extern void setup_client_ports(struct spd_route *sr);

extern int foreach_connection_by_alias(const char *alias
				       , int (*f)(struct connection *c, void *arg)
				       , void *arg);


extern struct connection *unoriented_connections;

extern bool update_host_pairs(struct connection *c);

#ifdef HAVE_LIBNSS
extern void load_authcerts_from_nss(const char *type, u_char auth_flags);
#endif

#define _CONNECTIONS_H
#endif /* _CONNECTIONS_H */

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
