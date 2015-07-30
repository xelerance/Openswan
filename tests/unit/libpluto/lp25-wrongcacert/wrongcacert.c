#include "../lp12-parentR2/parentR2_head.c"
#include "seam_host_jamesjohnson.c"
#include "seam_x509_list.c"

#define TESTNAME "wrongcacert"

static void init_local_interface(void)
{
    init_jamesjohnson_interface();
}

static void init_fake_secrets(void)
{
    prompt_pass_t pass;
    memset(&pass, 0, sizeof(pass));
    osw_init_ipsecdir("../samples/wrongcert");

    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/gatewaycert.secrets"
			       , &pass);
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
