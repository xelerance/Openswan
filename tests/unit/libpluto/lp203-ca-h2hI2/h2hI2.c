#include "../lp10-parentI2/parentI2_head.c"
#include "seam_gi_md5.c"
#include "seam_finish.c"
#include "seam_ikev2_sendI1.c"
#include "seam_keys.c"
#include "seam_x509_list.c"
#include "../../programs/pluto/x509keys.c"
#include "seam_host_parker.c"
#include "seam_natt.c"
#include "seam_rsasig.c"

#define TESTNAME "h2hI2"

static void init_local_interface(void)
{
    init_parker_interface(TRUE);
}

static void init_fake_secrets(void)
{
    osw_init_ipsecdir("../samples/davecert");
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/parker.secrets"
			       , NULL, NULL);
    load_authcerts("CA cert", "../samples/davecert/cacerts", AUTH_CA);
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
