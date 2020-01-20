#include "../lp12-parentR2/parentR2_head.c"
#include "seam_natt.c"
#include "seam_host_jamesjohnson.c"
#include "seam_x509.c"
#include "seam_gi_sha256_group14.c"
#include "seam_finish.c"
#include "seam_kernel.c"

#define TESTNAME "davecertR2-id"

static void init_local_interface(void)
{
    init_jamesjohnson_interface();
}

bool now_regression;
time_t regression_time;

static void init_fake_secrets(void)
{
    prompt_pass_t pass;
    memset(&pass, 0, sizeof(pass));
    osw_init_ipsecdir("../samples/selfsigned");

    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/gatewaycert.secrets"
			       , NULL, NULL);

    now_regression = TRUE;
    regression_time = 1482174719; /* Mon Dec 19 14:12:09 EST 2016 */
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
