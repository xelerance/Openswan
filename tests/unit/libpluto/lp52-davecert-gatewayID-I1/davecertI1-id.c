/* repeats existing test case */
#include "../lp02-parentI1/parentI1_head.c"
#include "seam_gi_sha1.c"
#include "seam_gi_sha1_group14.c"
#include "seam_finish.c"
#include "seam_ikev2_sendI1.c"
#include "seam_demux.c"
#include "../seam_host_dave.c"
#include "seam_pending.c"
#include "seam_whack.c"
#include "seam_initiate.c"
#include "seam_dnskey.c"
#include "seam_x509_list.c"
#include "seam_rsasig.c"

#define TESTNAME "davecertI1-id"

static void init_local_interface(void)
{
    init_dave_interface();
}

static void init_fake_secrets(void)
{
    prompt_pass_t pass;
    memset(&pass, 0, sizeof(pass));
    osw_init_ipsecdir_str("../samples/selfsigned");

    rnd_offset = 13;

    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/davecert.secrets"
			       , &pass, NULL);
}
#include "../lp02-parentI1/parentI1_main.c"


 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
