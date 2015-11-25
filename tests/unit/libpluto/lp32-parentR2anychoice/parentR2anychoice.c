#include "../lp12-parentR2/parentR2_head.c"
#include "seam_host_jamesjohnson.c"
#include "seam_x509.c"

#define TESTNAME "parentR2anychoice"

static void init_local_interface(void)
{
    init_jamesjohnson_interface();
}

static void init_fake_secrets(void)
{
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/jj.secrets"
			       , NULL);
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
