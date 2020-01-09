#include "../lp10-parentI2/parentI2_head.c"
#include "seam_gi_sha1.c"
#include "seam_gi_sha256_group14.c"
#include "seam_finish.c"
#include "seam_ikev2_sendI1.c"
#include "seam_x509_list.c"
#include "seam_host_dave.c"
#include "seam_natt.c"
#include "seam_rsasig.c"

#define TESTNAME "certificateselfI2"

static void init_local_interface(void)
{
    init_dave_interface();
}

static void init_fake_secrets(void)
{
    prompt_pass_t pass;
    memset(&pass, 0, sizeof(pass));
    osw_init_ipsecdir("../samples/davecert");

    rnd_offset = 13;

    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/davecert.secrets"
			       , &pass, NULL);
}

static void init_loaded(void)
{
    //struct connection *c;

    /* loading X.509 CA certificates */
    load_authcerts("CA cert", oco->cacerts_dir, AUTH_CA);
}

#include "seam_parentI2.c"
#include "../lp10-parentI2/parentI2_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
