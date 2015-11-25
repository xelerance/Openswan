const char *progname;
#include "pluto/connections.h"
#include "x509.h"
#include "ac.h"

struct pcap_pkthdr;
typedef void (*recv_pcap)(u_char *user, const struct pcap_pkthdr *h, const u_char *);
const struct osw_conf_options *oco;

void unroute_connection(struct connection *c) {}
bool trap_connection(struct connection *c) { return TRUE; }
void perpeer_logfree(struct connection *c) {}

/* server.c SEAM */
void find_ifaces(void) {}

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

