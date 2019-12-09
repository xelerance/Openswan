#define INCLUDE_IKEV1_PROCESSING
#define OMIT_MAIN_MODE
#define NAT_TRAVERSAL
#define SEAM_CRYPTO
#include "../lp12-parentR2/parentR2_head.c"
#include "seam_pending.c"
#include "seam_crypt.c"
#include "seam_ikev1.c"
#include "seam_ikev1_aggr.c"
#include "seam_dpd.c"
#include "seam_ikev1_phase2.c"
#include "seam_ikev1_crypto.c"
#include "seam_gi_sha1.c"
#include "seam_finish.c"
#include "seam_unpend.c"
#include "seam_command.c"
#include "seam_kernel.c"
#include "seam_x509.c"
#include "seam_rsasig.c"
#include "seam_rsa_check.c"
#include "seam_host_jamesjohnson.c"

#include "nat_traversal.h"

#define TESTNAME "parentN2"

bool no_cr_send = TRUE;

static void init_local_interface(void)
{
    nat_traversal_support_non_ike = TRUE;
    nat_traversal_support_port_floating = TRUE;
    nat_traversal_enabled = TRUE;
    init_jamesjohnson_interface();
}

static void init_fake_secrets(void)
{
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/jj.secrets"
			       , NULL, NULL);
}

static void init_loaded(void)
{   /* nothing */ }


#define PCAP_INPUT_COUNT 2

#include "seam_parentR2.c"

recv_pcap recv_inputs[PCAP_INPUT_COUNT]={
    recv_pcap_packet1ikev1,
    recv_pcap_packet2ikev1,
};

#include "../lp12-parentR2/parentR2_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
