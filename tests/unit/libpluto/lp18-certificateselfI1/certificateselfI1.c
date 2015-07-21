/* repeats existing test case */
#include "../lp02-parentI1/parentI1_head.c"
#include "../seam_host_rw.c"
#include "seam_x509_list.c"

#define TESTNAME "certificateselfI1"

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
			       , &pass);
}
#include "../lp02-parentI1/parentI1_main.c"


 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
