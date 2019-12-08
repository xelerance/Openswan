#ifndef __seam_dnskey_c__
#define __seam_dnskey_c__
#include "dnskey.h"

void gw_addref(struct gw_info *gw) {}
void gw_delref(struct gw_info **gwp) {}

#ifndef OMIT_PENDING_USE
bool in_pending_use(struct connection *c) { return FALSE; }
#endif
bool kick_adns_connection_lookup(struct connection *c UNUSED
                                 , struct end *end UNUSED, bool restart UNUSED) {
  end->host_address_list.addresses_available = TRUE;
  return FALSE;
}

err_t start_adns_query(const struct id *id	/* domain to query */
		       , const struct id *sgw_id	/* if non-null, any accepted gw_info must match */
		       , int type	/* T_TXT or T_KEY, selecting rr type of interest */
		       , cont_fn_t cont_fn
		       , struct adns_continuation *cr) {
    return NULL;   /* no error */
    /* SHOULD call continuation immediately with "NOT FOUND" */
}

/* dnskey.c SEAM */
void reset_adns_restart_count(void) {}



#endif
