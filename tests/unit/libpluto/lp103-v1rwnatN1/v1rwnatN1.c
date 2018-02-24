#define NAT_TRAVERSAL
#define INCLUDE_IKEV1_PROCESSING
/* repeats existing test case */
#include "../lp08-parentR1/parentR1_head.c"
#include "seam_host_sun.c"
#include "seam_x509.c"
#include "seam_gi_sha1.c"
#include "seam_finish.c"
#include "seam_ikev1_phase2.c"
#include "seam_ikev1_crypto.c"
#include "seam_natt_vid.c"
#include "seam_rsa_check.c"
#include "seam_dpd.c"
#include "seam_command.c"
#include "seam_unpend.c"
#include "seam_keys.c"
#include "seam_rsasig.c"

#define TESTNAME "v1rwnatN1"

bool no_cr_send = 0;
#define MORE_DEBUGGING DBG_PARSING

static void init_local_interface(void)
{
    nat_traversal_support_non_ike = TRUE;
    nat_traversal_support_port_floating = TRUE;
    nat_traversal_enabled = TRUE;
    init_sun_interface(TRUE);
}

static void init_fake_secrets(void)
{
    prompt_pass_t pass;
    memset(&pass, 0, sizeof(pass));

    osw_init_ipsecdir(SAMPLEDIR "sun");
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , SAMPLEDIR "sun.secrets"
			       , &pass, NULL);
}
#include "../lp08-parentR1/parentR1_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
