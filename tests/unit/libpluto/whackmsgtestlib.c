const char *progname;
#include "pluto/connections.h"
#include "x509.h"
#include "ac.h"

struct pcap_pkthdr;
typedef void (*recv_pcap)(u_char *user, const struct pcap_pkthdr *h, const u_char *);
const struct osw_conf_options *oco;

void perpeer_logfree(struct connection *c) {}

/* server.c SEAM */
void find_ifaces(void) {}

void show_status(void) {}







struct iface_port  *interfaces = NULL;	/* public interfaces */
struct connection *cur_connection = NULL;
enum kernel_interface kern_interface = NO_KERNEL;

int whack_log_fd = 1;
bool listening = TRUE;
bool strict_crl_policy = FALSE;
bool force_busy = FALSE;

#include "efencedef.h"

#include "readwhackmsg.h"

