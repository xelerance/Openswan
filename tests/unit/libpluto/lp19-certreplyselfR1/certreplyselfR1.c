/* repeats existing test case */
#include "../lp08-parentR1/parentR1_head.c"
#include "seam_gi_sha256_group14.c"
#include "seam_finish.c"
#include "../seam_host_jamesjohnson.c"
#include "seam_rsasig.c"
#include "seam_x509_list.c"

#define TESTNAME "certreplytselffR1"

static inline void init_local_interface(void)
{
    init_jamesjohnson_interface();
}

static void init_fake_secrets(void)
{
    prompt_pass_t pass;
    memset(&pass, 0, sizeof(pass));
    osw_init_ipsecdir_str("../samples/gatewaycert");

    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/gatewaycert.secrets"
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


 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
