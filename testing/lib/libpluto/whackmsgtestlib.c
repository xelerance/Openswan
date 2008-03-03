char *progname;
<<<<<<< HEAD:testing/lib/libpluto/whackmsgtestlib.c
#include "x509.h"
#include "ac.h"
=======

/* LINK seams */
void exit_log(const char *msg, ...)
{
    abort();
}

void exit_tool(int status)
{
    exit(status);
}

void exit_pluto(int status)
{
    exit(status);
}

void whack_log(int rc, const char *msg, ...)
{
    va_list args;

    va_start(args, msg);
    fprintf(stderr, "RC=%u ", rc);
    vfprintf(stderr, msg, args);
    va_end(args);
}
>>>>>>> 47e1291:testing/lib/libpluto/whackmsgtestlib.c

void flush_pending_by_connection(struct connection *c) {}
void unroute_connection(struct connection *c) {}
bool trap_connection(struct connection *c) { return TRUE; }
void perpeer_logfree(struct connection *c) {}
<<<<<<< HEAD:testing/lib/libpluto/whackmsgtestlib.c
=======
void add_pgp_public_key(pgpcert_t *cert , time_t until, enum dns_auth_level dns_auth_level) {}
pgpcert_t*pluto_add_pgpcert(pgpcert_t *cert) { return NULL; }
void add_x509_public_key(x509cert_t *cert , time_t until
			 , enum dns_auth_level dns_auth_level) {}
x509cert_t*add_x509cert(x509cert_t *cert) { return NULL; }

void free_sa(struct db_sa *f) {}

/* ac.c SEAM */
void decode_groups(char *groups, ietfAttrList_t **listp) {}
void load_acerts(void) {}
void list_acerts(bool utc) {}
void list_groups(bool utc) {}

void gw_addref(struct gw_info *gw) {}
void gw_delref(struct gw_info **gwp) {}

bool in_pending_use(struct connection *c) { return FALSE; }

err_t add_public_key(const struct id *id
		     , enum dns_auth_level dns_auth_level
		     , enum pubkey_alg alg
		     , const chunk_t *key
		     , struct pubkey_list **head) { return NULL; /* no error */ }


void transfer_to_public_keys(struct gw_info *gateways_from_dns
			     , struct pubkey_list **keys) {}
>>>>>>> 47e1291:testing/lib/libpluto/whackmsgtestlib.c

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
<<<<<<< HEAD:testing/lib/libpluto/whackmsgtestlib.c
int whack_log_fd = 1;
=======
int whack_log_fd = NULL_FD;
struct pubkey_list *pluto_pubkeys = NULL;	/* keys from ipsec.conf */
>>>>>>> 47e1291:testing/lib/libpluto/whackmsgtestlib.c
bool listening = TRUE;
bool strict_crl_policy = FALSE;
bool force_busy = FALSE;

<<<<<<< HEAD:testing/lib/libpluto/whackmsgtestlib.c
#include "efencedef.h"

#include "readwhackmsg.h"
=======
/* efence defines */
extern int EF_DISABLE_BANNER;
extern int EF_ALIGNMENT;
extern int EF_PROTECT_BELOW;
extern int EF_PROTECT_FREE;
extern int EF_ALLOW_MALLOC_0;
extern int EF_FREE_WIPES;
>>>>>>> 47e1291:testing/lib/libpluto/whackmsgtestlib.c

