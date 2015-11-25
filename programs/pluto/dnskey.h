/* Find public key in DNS
 * Copyright (C) 2000-2002  D. Hugh Redelmeier.
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

#ifndef _DNSKEY_H_

#include <resolv.h>
#include "adns.h"	/* needs <resolv.h> */
#include "id.h"

/* forward reference */
struct connection;

extern int
    adns_qfd,	/* file descriptor for sending queries to adns */
    adns_afd;	/* file descriptor for receiving answers from adns */
extern const char *pluto_adns_option;	/* path from --pluto_adns */
extern void init_adns(void);
extern void stop_adns(void);
extern void handle_adns_answer(void);

extern bool unsent_ADNS_queries;
extern bool adns_any_in_flight(void);        /* for unit testing */
extern void send_unsent_ADNS_queries(void);

/* (common prefix of) stuff remembered between async query and answer.
 * Filled in by start_adns_query.
 * Freed by call to release_adns_continuation.
 */

struct adns_continuation;	/* forward declaration (not far!) */

typedef void (*cont_fn_t)(struct adns_continuation *cr, err_t ugh);

struct adns_continuation {
    unsigned long qtid;	/* query transaction id number */
    int type;	        /* T_TXT or T_KEY, selecting rr type of interest */
    cont_fn_t cont_fn;	/* function to carry on suspended work */
    struct id id;	/* subject of query */
    bool sgw_specified;
    struct id sgw_id;	/* peer, if constrained */
    lset_t debugging;	/* only used #ifdef DEBUG, but don't want layout to change */
    struct gw_info *gateways_from_dns;	/* answer, if looking for our TXT rrs */
#ifdef USE_KEYRR
    struct pubkey_list *keys_from_dns;	/* answer, if looking for KEY rrs */
#endif
  //struct addrinfo *addresses_from_dns;  /* answer, if looking for A/AAAA rrs */
    struct adns_continuation *previous, *next;
    struct pubkey *last_info;  /* the last structure we accumulated */
    struct adns_query query;
  struct addrinfo *ipanswers;  /* the result of the async getaddrinfo() call
                                * this is a fresh malloc, and does not need to be copied
                                */
};

extern err_t start_adns_query(const struct id *id	/* domain to query */
    , const struct id *sgw_id	/* if non-null, any accepted gw_info must match */
    , int type	/* T_TXT or T_KEY, selecting rr type of interest */
    , cont_fn_t cont_fn	/* continuation function */
    , struct adns_continuation *cr);

extern err_t start_adns_hostname(sa_family_t addr_family
                                 , const char *hostname
                                 , cont_fn_t cont_fn
                                 , struct adns_continuation *cr);



/* Gateway info gleaned from reverse DNS of client */
struct gw_info {
    unsigned refcnt;	/* reference counted! */
    unsigned pref;	/* preference: lower is better */
#define NO_TIME ((time_t) -2)	/* time_t value meaning "not_yet" */
    struct id client_id;	/* id of client of peer */
    struct id gw_id;	/* id of peer (if id_is_ipaddr, .ip_addr is address) */
    bool gw_key_present;
    struct pubkey *key;
    struct gw_info *next;
};

extern void gw_addref(struct gw_info *gw)
    , gw_delref(struct gw_info **gwp);

extern void reset_adns_restart_count(void);

extern bool kick_adns_connection_lookup(struct connection *c, struct end *end, bool newlookup);
extern void dump_addr_info(struct addrinfo *ans);
extern struct addrinfo *sort_addr_info(struct addrinfo *ai);


struct iphostname_continuation {
  struct adns_continuation ac;	/* common prefix */
  struct connection        *c;
};
extern void iphostname_continuation(struct adns_continuation *cr, err_t ugh);




#define _DNSKEY_H_
#endif /* _DNSKEY_H_ */

