#include "../lp02-parentI1/parentI1_head.c"
#include "seam_gi_md5.c"
#include "seam_finish.c"
#include "seam_ikev2_sendI1.c"
#include "seam_demux.c"
#include "seam_x509_list.c"
#include "../../programs/pluto/x509keys.c"
#include "seam_pending.c"
#include "seam_whack.c"
#include "seam_initiate.c"
#include "seam_dnskey.c"
#include "seam_rsasig.c"

#include "seam_host_parker.c"

#define TESTNAME "h2hI1"

static void init_local_interface(void)
{
    init_parker_interface(TRUE);
}

static void init_fake_secrets(void)
{
    osw_init_ipsecdir_str("../samples/davecert");
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/parker.secrets"
			       , NULL, NULL );
}

#include "../lp02-parentI1/parentI1_main.c"


 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
