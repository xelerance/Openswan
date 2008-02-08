char *progname;
#include "x509.h"
#include "ac.h"

void flush_pending_by_connection(struct connection *c) {}
void unroute_connection(struct connection *c) {}
bool trap_connection(struct connection *c) { return TRUE; }
void perpeer_logfree(struct connection *c) {}
#ifndef  NO_X509_SEAM
void release_cert(cert_t cert) {}
void add_pgp_public_key(pgpcert_t *cert , time_t until, enum dns_auth_level dns_auth_level) {}
pgpcert_t*pluto_add_pgpcert(pgpcert_t *cert) { return NULL; }
void add_x509_public_key(struct id *keyid, x509cert_t *cert , time_t until
			 , enum dns_auth_level dns_auth_level) {}
x509cert_t*add_x509cert(x509cert_t *cert) { return NULL; }

/* ac.c SEAM */
void decode_groups(char *groups, ietfAttrList_t **listp) {}
void load_acerts(void) {}
void list_acerts(bool utc) {}
void list_groups(bool utc) {}
void free_ietfAttrList(ietfAttrList_t* list) {}
#endif

#include "dnskey.h"
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

/* server.c SEAM */
void find_ifaces(void) {}

#ifndef  NO_X509_SEAM
/* x509.c SEAM */
void load_crls(void) {}
void list_certs(bool utc) {}
void list_authcerts(const char *caption, u_char auth_flags, bool utc) {}
void list_crls(bool utc, bool strict) {}
#endif

/* timer.c SEAM */
void timer_list(void) {}

/* initiate.c SEAM */
void initiate_connection(const char *name, int whackfd
			 , lset_t moredebug
			 , enum crypto_importance importance) {}
void initiate_ondemand(const ip_address *our_client
		       , const ip_address *peer_client
		       , int transport_proto UNUSED
		       , bool held
		       , int whackfd
		       , err_t why) {}
void show_status(void) {}







struct iface_port  *interfaces = NULL;	/* public interfaces */
struct connection *cur_connection = NULL;
enum kernel_interface kern_interface = NO_KERNEL;
bool can_do_IPcomp=TRUE;
bool nat_traversal_enabled=TRUE;
int whack_log_fd = 1;
bool listening = TRUE;
bool strict_crl_policy = FALSE;

#include "efencedef.h"

#include "readwhackmsg.h"

