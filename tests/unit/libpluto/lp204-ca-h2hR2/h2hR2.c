#include "../lp12-parentR2/parentR2_head.c"
#include "seam_natt.c"
#include "seam_host_jamesjohnson.c"
#include "seam_x509_list.c"
#include "../../programs/pluto/x509keys.c"
#include "seam_gr_md5.c"
#include "seam_finish.c"
#include "seam_kernel.c"

#define TESTNAME "h2hR2"

static void init_local_interface(void)
{
    init_jamesjohnson_interface();
}

static void init_fake_secrets(void)
{
    osw_init_ipsecdir("../samples/gatewaycert");
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/jj.secrets"
			       , NULL, NULL);
    load_authcerts("CA cert", "../samples/gatewaycert/cacerts", AUTH_CA);
}

static void init_loaded(void)
{   /* nothing */ }

#include "../lp12-parentR2/parentR2_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
