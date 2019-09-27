#include "../lp10-parentI2/parentI2_head.c"
#include "seam_gi_sha1.c"
#include "seam_gi_sha1_group14.c"
#include "seam_finish.c"
#include "seam_ikev2_sendI1.c"
#include "seam_keys2.c"
#include "seam_x509.c"
#include "seam_finish.c"
#include "seam_rsa_check.c"
#include "seam_natt.c"
#include "seam_ke.c"
#include "seam_dh_v2.c"
#include "seam_host_parker.c"

#define TESTNAME "cryptoI2"

static void init_local_interface(void)
{
    init_parker_interface(TRUE);
}

static void init_fake_secrets(void)
{
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , SAMPLEDIR "/twoparker.secrets"
			       , NULL, NULL);
}

static void init_loaded(void) {}

#include "seam_parentI2.c"
#include "../lp10-parentI2/parentI2_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
