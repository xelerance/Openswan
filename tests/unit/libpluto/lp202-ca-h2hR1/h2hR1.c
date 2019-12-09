/* repeats existing test case */
#include "../lp08-parentR1/parentR1_head.c"
#include "seam_gr_md5.c"
#include "seam_finish.c"
#include "seam_x509_list.c"
#include "seam_rsasig.c"
#include "seam_host_jamesjohnson.c"

#include "../../programs/pluto/x509keys.c"


#define TESTNAME "h2hR1"

static inline void init_local_interface(void)
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
#include "../lp08-parentR1/parentR1_main.c"


 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
