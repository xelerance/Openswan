#define INCLUDE_IKEV1_PROCESSING
#define INCLUDE_QUICK_MODE
#define OMIT_MAIN_MODE
#define NAT_TRAVERSAL
#define SEAM_CRYPTO
#include "../lp12-parentR2/parentR2_head.c"
#include "nat_traversal.h"
#include "seam_dpd.c"
#include "seam_ikev1_aggr.c"
#include "seam_ikealg.c"
#include "seam_crypt.c"
#include "seam_x509.c"
#include "seam_ke.c"
#include "seam_dh_v2.c"
#include "seam_nonce.c"
#include "seam_rsasig.c"
#include "seam_ikev1_crypto.c"
#include "seam_gi_sha256_group14.c"
#include "seam_finish.c"
#include "seam_ikev1_crypto.c"
#include "seam_host_jamesjohnson.c"
#include "seam_mockxfrm.c"

#define TESTNAME "xf79-childQR1"

bool no_cr_send = TRUE;

void delete_cryptographic_continuation(struct state *st) {}

static void init_local_interface(void)
{
    nat_traversal_support_non_ike = TRUE;
    nat_traversal_support_port_floating = TRUE;
    nat_traversal_enabled = TRUE;
    init_jamesjohnson_interface();
}

static void init_fake_secrets(void)
{
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , SAMPLEDIR "jj.secrets"
			       , NULL, NULL);
}

static void init_loaded(void)
{
    xfrm_init_base_algorithms();
}


#define PCAP_INPUT_COUNT 4

#include "seam_parentR2.c"

recv_pcap recv_inputs[PCAP_INPUT_COUNT]={
    recv_pcap_packet1ikev1,
    recv_pcap_packet2ikev1,
    recv_pcap_packet2ikev1,
    recv_pcap_packet3ikev1,
};

#define FINISH_NEGOTIATION
static void finish_negotiation(void)
{
    volatile struct state *st;
    st = state_with_serialno(1);
    passert(st != NULL);

    passert(st->st_oakley.integ_hash == IKEv2_AUTH_HMAC_SHA1_96);
    passert(st->st_oakley.prf_hash   == IKEv2_AUTH_HMAC_SHA1_96);
    passert(st->st_oakley.encrypt    == IKEv2_ENCR_AES_CBC);
    passert(st->st_oakley.enckeylen  == 128);

    st = state_with_serialno(2);
    passert(st != NULL);

    passert(st->st_esp.present);
    passert(st->st_esp.attrs.transattrs.integ_hash == IKEv2_AUTH_HMAC_SHA1_96);
    passert(st->st_esp.attrs.transattrs.encrypt    == IKEv2_ENCR_AES_CBC);
    passert(st->st_esp.attrs.transattrs.enckeylen  == 128);
}

#include "../lp12-parentR2/parentR2_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
