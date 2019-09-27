#include "../lp10-parentI2/parentI2_head.c"
#include "seam_gi_sha1.c"
#include "seam_gi_sha1_group14.c"
#include "seam_finish.c"
#include "seam_ikev2_sendI1.c"
#include "seam_x509_list.c"
#include "seam_host_rw.c"
#include "seam_natt.c"
#include "seam_rsasig.c"
#include "seam_keys.c"

#define TESTNAME "certificateselfI2"

static void init_local_interface(void)
{
    init_rw_interface();
}

static void init_fake_secrets(void)
{
    prompt_pass_t pass;
    memset(&pass, 0, sizeof(pass));
    osw_init_ipsecdir("../samples/rwcert");

    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/rwcert.secrets"
			       , &pass, NULL);
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
