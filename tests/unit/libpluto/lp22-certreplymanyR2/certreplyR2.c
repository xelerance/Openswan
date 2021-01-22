#define FIND_ID_EXTENDED_DEBUG 1

#include "../lp12-parentR2/parentR2_head.c"
#include "seam_natt.c"
#include "seam_host_jamesjohnson.c"
#include "seam_x509_list.c"
#include "seam_gi_sha256_group14.c"
#include "seam_finish.c"
#include "seam_kernel.c"

#define TESTNAME "certreplyselfR2"

static void init_local_interface(void)
{
    init_jamesjohnson_interface();
}

static void init_fake_secrets(void)
{
    prompt_pass_t pass;
    memset(&pass, 0, sizeof(pass));
    osw_init_ipsecdir("../samples/gatewaycert");

    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/gatewaycert.secrets"
			       , &pass, NULL);
}

static void init_loaded(void)
{
    /* loading X.509 CA certificates */
    load_authcerts("CA cert", oco->cacerts_dir, AUTH_CA);

    hostpair_list();
}

#include "../lp12-parentR2/parentR2_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
