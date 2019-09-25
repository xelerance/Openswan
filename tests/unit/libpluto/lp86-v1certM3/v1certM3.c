#define INCLUDE_IKEV1_PROCESSING
#define OMIT_MAIN_MODE
#define NAPT_ENABLED 1
#define NAT_TRAVERSAL
#define SEAM_CRYPTO
#include "../lp10-parentI2/parentI2_head.c"
#include "seam_kernel.c"
#include "seam_gi_sha1.c"
#include "seam_finish.c"
#include "seam_crypt.c"
#include "seam_ikev1_crypto.c"
#include "seam_pending.c"
#include "seam_rsasig.c"
#include "seam_dpd.c"
#include "seam_ikev1_phase2.c"
#include "seam_unpend.c"
#include "seam_command.c"
#include "seam_rsa_check.c"
#include "seam_host_carol.c"
#include "seam_sendI1.c"

#include "nat_traversal.h"

#define TESTNAME "v1certM3"

bool no_cr_send = 0;
long crl_check_interval = 0;

static void init_local_interface(void)
{
    nat_traversal_support_non_ike = TRUE;
    nat_traversal_support_port_floating = TRUE;
    nat_traversal_enabled = TRUE;
    init_carol_interface(TRUE);
}

static void init_fake_secrets(void)
{
    prompt_pass_t pass;
    memset(&pass, 0, sizeof(pass));

    osw_init_ipsecdir(SAMPLEDIR "carol");
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , SAMPLEDIR "carol.secrets"
			       , &pass, NULL);
}

static void init_loaded(void) {}

#include "seam_ikev1tc3.c"

#define PCAP_INPUT_COUNT 2
recv_pcap recv_inputs[PCAP_INPUT_COUNT]={
    recv_pcap_packet,
    recv_pcap_packet,
};


#include "../lp10-parentI2/parentI2_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
