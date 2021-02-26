#include "../lp12-parentR2/parentR2_head.c"
#include "seam_natt.c"
#include "seam_host_jamesjohnson.c"
#include "seam_x509_list.c"
#include "seam_gi_sha256_group14.c"
#include "seam_finish.c"
#include "seam_kernel.c"

#define TESTNAME "wrongcacert"

static void init_local_interface(void)
{
    init_jamesjohnson_interface();
}

static void init_fake_secrets(void)
{
    prompt_pass_t pass;
    memset(&pass, 0, sizeof(pass));

    now_regression  = TRUE;
    regression_time = 1448316734L;
    osw_init_ipsecdir_str("../samples/wrongcert");

    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/gatewaycert.secrets"
			       , &pass, NULL);
}

static void init_loaded(void)
{   /* nothing */ }

#define FINISH_PCAP 1
void finish_pcap(void) {
    time_t n;
    n = 1438262454;   /* Thu Jul 30 09:21:01 EDT 2015 in seconds */
    list_certs(n);
}



#include "../lp12-parentR2/parentR2_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
