#include "../lp02-parentI1/parentI1_head.c"
#include "seam_x509.c"
#include "seam_pending.c"
#include "seam_whack.c"
#include "seam_initiate.c"
#include "seam_keys.c"
#include "seam_dnskey.c"

#include "seam_host_parker.c"

#define TESTNAME "h2hI1"

static void init_local_interface(void)
{
    init_parker_interface(TRUE);
}

static void init_fake_secrets(void)
{
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/parker.secrets"
			       , NULL);
}

#include "../lp02-parentI1/parentI1_main.c"


 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
