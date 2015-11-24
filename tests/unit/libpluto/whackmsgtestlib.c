const char *progname;
#include "x509.h"
#include "ac.h"

struct pcap_pkthdr;
typedef void (*recv_pcap)(u_char *user, const struct pcap_pkthdr *h, const u_char *);
const struct osw_conf_options *oco;

void flush_pending_by_connection(struct connection *c) {}
void unroute_connection(struct connection *c) {}
bool trap_connection(struct connection *c) { return TRUE; }
void perpeer_logfree(struct connection *c) {}

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

/* initiate.c SEAM */
void initiate_connection(const char *name, int whackfd
			 , lset_t moredebug
			 , enum crypto_importance importance) {}

int initiate_ondemand(const ip_address *our_client
                              , const ip_address *peer_client
                              , int transport_proto
                              , bool held
                              , int whackfd
                              , struct xfrm_user_sec_ctx_ike *uctx
                              , err_t why) {}

void show_status(void) {}







struct iface_port  *interfaces = NULL;	/* public interfaces */
struct connection *cur_connection = NULL;
enum kernel_interface kern_interface = NO_KERNEL;
bool can_do_IPcomp=TRUE;
u_int16_t pluto_port500  = IKE_UDP_PORT;	/* Pluto's port */
u_int16_t pluto_port4500 = NAT_IKE_UDP_PORT;	/* Pluto's port NAT */

int whack_log_fd = 1;
bool listening = TRUE;
bool strict_crl_policy = FALSE;
bool force_busy = FALSE;

#include "efencedef.h"

#include "readwhackmsg.h"

