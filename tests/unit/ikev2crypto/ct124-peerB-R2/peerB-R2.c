#define NO_SEAM_RSASIG 1
#include "../lp12-parentR2/parentR2_head.c"
#include "seam_natt.c"
#include "seam_host_peerB.c"
#include "seam_x509_list.c"
#include "seam_gi_sha256_group14.c"
#include "seam_dh_v2.c"
#include "seam_ke.c"
#include "seam_finish.c"
#include "seam_kernel.c"

#define TESTNAME "peerB-R2"

static void init_local_interface(void)
{
    init_peerB_interface();
}

static void init_fake_secrets(void)
{
    prompt_pass_t pass;
    memset(&pass, 0, sizeof(pass));
    osw_init_ipsecdir_str(SAMPLEDIR "carol");

    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , SAMPLEDIR "carol.secrets"
			       , &pass, NULL);
}

static void init_loaded(void) {
    cur_debugging |= DBG_X509;

    oco = osw_init_options();

    /* loading X.509 CA certificates */
    load_authcerts("CA cert", oco->cacerts_dir, AUTH_CA);
    /* loading X.509 AA certificates */
    load_authcerts("AA cert", oco->aacerts_dir, AUTH_AA);
    /* loading X.509 OCSP certificates */
    load_authcerts("OCSP cert", oco->ocspcerts_dir, AUTH_OCSP);

    /* loading X.509 CRLs */
    load_crls();
    /* loading attribute certificates (experimental) */
    load_acerts();

    list_certs(1);

    list_authcerts("CA", AUTH_CA, 1);
}

#include "../lp12-parentR2/parentR2_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
