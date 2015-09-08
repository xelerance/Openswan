/* information about connections between hosts and clients
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003-2015  Michael Richardson <mcr@xelerance.com>
 */

struct IPhost_pair {
    struct {
      ip_address        addr;
      enum keyword_host host_type;              /* if above is interesting */
      u_int16_t         host_port;	        /* IKE port */
      bool              host_port_specific;	/* if above is interesting */
    } me, him;
    struct connection *connections;	/* connections with this pair */
    struct pending *pending;	/* awaiting Keying Channel */
    struct IPhost_pair *next;
};
extern struct IPhost_pair *IPhost_pairs;


struct IDhost_pair {
    struct id           me_who, him_who;
    struct connection  *connections;	/* connections with this pair */
    struct IDhost_pair *next;           /* maybe HASH later */
};
extern struct IDhost_pair *IDhost_pairs;

extern void connect_to_IPhost_pair(struct connection *c);
extern void connect_to_IDhost_pair(struct connection *c);
extern void connect_to_host_pair(struct connection *c);
#define EXACT_MATCH TRUE
#define ANY_MATCH   FALSE
extern struct connection *find_host_pair_connections(const char *func, bool exact
						     , const ip_address *myaddr
						     , u_int16_t myport
                                                     , enum keyword_host histype
						     , const ip_address *hisaddr
						     , u_int16_t hisport);

extern struct IPhost_pair *find_host_pair(bool exact, const ip_address *myaddr
					, u_int16_t myport
                                        , enum keyword_host histype
					, const ip_address *hisaddr
					, u_int16_t hisport);

extern struct IDhost_pair *find_ID_host_pair(bool exact
                                             , const struct end me
                                             , const struct end him);

#define list_rm(etype, enext, e, ehead) { \
	etype **ep; \
	for (ep = &(ehead); *ep != (e); ep = &(*ep)->enext) \
	    passert(*ep != NULL);    /* we must not come up empty-handed */ \
	*ep = (e)->enext; \
    }

extern void remove_IPhost_pair(struct IPhost_pair *hp);
extern void hostpair_list(void);

extern struct connection *connections;
/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
