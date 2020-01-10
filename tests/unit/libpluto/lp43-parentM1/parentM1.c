#define OMIT_MAIN_MODE 1
#define NAT_TRAVERSAL

#include "../lp02-parentI1/parentI1_head.c"
#include "seam_gi_sha1.c"
#include "seam_gi_sha1_group14.c"
#include "seam_finish.c"
#include "seam_ikev2_sendI1.c"
#include "seam_demux.c"
#include "seam_x509.c"
#include "seam_pending.c"
#include "seam_whack.c"
#include "seam_initiate.c"
#include "seam_dnskey.c"
#include "seam_ikev1_phase2.c"
#include "seam_ikev1_crypto.c"
#include "seam_natt_vid.c"
#include "seam_rsa_check.c"
#include "seam_rsasig.c"

#include "seam_host_parker.c"

#define TESTNAME "parentM1"

static void init_local_interface(void)
{
    init_parker_interface(TRUE);
    nat_traversal_enabled = TRUE;
}

static void init_fake_secrets(void)
{
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/parker.secrets"
			       , NULL, NULL);
}

bool no_cr_send = FALSE;

#include "../lp02-parentI1/parentI1_main.c"


 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
