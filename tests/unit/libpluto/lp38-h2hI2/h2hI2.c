#include "../lp10-parentI2/parentI2_head.c"
#include "seam_keys.c"
#include "seam_x509.c"
#include "seam_host_parker.c"

#define TESTNAME "h2hI2"

static void init_local_interface(void)
{
    init_parker_interface(TRUE);
}

static void init_fake_secrets(void)
{
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/parker.secrets"
			       , NULL);
}

static void init_loaded(void) {}

#include "../lp10-parentI2/parentI2_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
