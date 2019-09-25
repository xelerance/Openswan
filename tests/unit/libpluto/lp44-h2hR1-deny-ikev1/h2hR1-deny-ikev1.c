#define INCLUDE_IKEV1_PROCESSING
/* repeats existing test case */
#include "../lp08-parentR1/parentR1_head.c"
#include "seam_gr_sha1_group14.c"
#include "seam_finish.c"
#include "seam_x509.c"
#include "seam_host_jamesjohnson.c"
#include "seam_ikev1_phase2.c"
#include "seam_ikev1_crypto.c"
#include "seam_natt_vid.c"
#include "seam_dpd.c"
#include "seam_command.c"
#include "seam_ikev1_aggr.c"
#include "seam_unpend.c"
#include "seam_rsasig.c"

#define TESTNAME "h2h-deny-ikev1"

bool no_cr_send = 0;

static inline void init_local_interface(void)
{
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


 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
