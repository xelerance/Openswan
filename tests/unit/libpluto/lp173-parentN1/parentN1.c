#define NAT_TRAVERSAL
#define INCLUDE_IKEV1_PROCESSING
/* repeats existing test case */
#include "../lp08-parentR1/parentR1_head.c"
#include "seam_x509.c"
#include "seam_host_jamesjohnson.c"
#include "seam_ikev1_phase2.c"
#include "seam_ikev1_crypto.c"
#include "seam_natt_vid.c"
#include "seam_rsasig.c"
#include "seam_rsa_check.c"
#include "seam_dpd.c"
#include "seam_command.c"
#include "seam_unpend.c"
#include "seam_gi_sha1.c"
#include "seam_finish.c"

#define TESTNAME "parentN1"

#define MORE_DEBUGGING DBG_PARSING

static void init_local_interface(void)
{
    struct osw_conf_options *oco = osw_init_options();

    oco->no_cr_send = FALSE;
    oco->crl_check_interval = 0;
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
#include "../lp08-parentR1/parentR1_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
