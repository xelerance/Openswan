#define INCLUDE_IKEV1_PROCESSING
#define INCLUDE_QUICK_MODE
#define OMIT_MAIN_MODE
#define OMIT_SEAM_INITIATE
#define OMIT_ADD_PENDING
#define OMIT_IKEv1
#define OMIT_PENDING_USE
#define NAT_TRAVERSAL
#define SEAM_CRYPTO
#include "../lp12-parentR2/parentR2_head.c"
#include "seam_host_sun.c"
#include "nat_traversal.h"
#include "seam_dpd.c"
#include "seam_ikev1_aggr.c"
#include "seam_command.c"
#include "seam_kernel.c"
#include "seam_crypt.c"
#include "seam_x509.c"
#include "seam_nonce.c"
#include "seam_rsasig.c"
#include "seam_rsa_check.c"
#include "seam_gi_3des_md5.c"
#include "seam_finish.c"
#include "seam_ikev1_crypto.c"

#define TESTNAME "v1rwnatQR1"

static void init_local_interface(void)
{
    struct osw_conf_options *oco = osw_init_options();

    oco->no_cr_send = TRUE;
    nat_traversal_support_non_ike = TRUE;
    nat_traversal_support_port_floating = TRUE;
    nat_traversal_enabled = TRUE;
    init_sun_interface(TRUE);
}

static void init_fake_secrets(void)
{
    prompt_pass_t pass;
    memset(&pass, 0, sizeof(pass));

    osw_init_ipsecdir(SAMPLEDIR "sun");
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , SAMPLEDIR "sun.secrets"
			       , &pass, NULL);
}

static void init_loaded(void)
{   /* nothing */ }


#define PCAP_INPUT_COUNT 4

// #include "seam_gi_sha1.c"

static void update_ngi_tc3(struct pcr_kenonce *kn)
{
    if(kn->thespace.len == 0) {
        fprintf(stderr, "failed to setup crypto_req, exiting\n");
        exit(89);
    }

    /* now fill in the KE values from a constant.. not calculated */
    clonetowirechunk(&kn->thespace, kn->space, &kn->secret, SS(secret.ptr), SS(secret.len));
    clonetowirechunk(&kn->thespace, kn->space, &kn->n,      SS(ni.ptr), SS(ni.len));
    clonetowirechunk(&kn->thespace, kn->space, &kn->gi,     SS(gi.ptr), SS(gi.len));
}

void recv_pcap_packet1ikev1(u_char *user
                      , const struct pcap_pkthdr *h
                      , const u_char *bytes)
{
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    recv_pcap_packet_gen(user, h, bytes);

    /* find st involved */
    st = state_with_serialno(1);
    if(st) {
      st->st_connection->extra_debugging = DBG_PRIVATE|DBG_CRYPT|DBG_PARSING|DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;
    }
}

void recv_pcap_packet2ikev1_128(u_char *user
                      , const struct pcap_pkthdr *h
                      , const u_char *bytes)
{
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    recv_pcap_packet_gen(user, h, bytes);

    /* find st involved */
    st = state_with_serialno(1);
    if(st) {
      st->st_connection->extra_debugging = DBG_PRIVATE|DBG_CRYPT|DBG_PARSING|DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;
      update_ngi_tc3(kn);
      run_continuation(crypto_req);
    }

    passert(st->st_suspended_md == NULL);
}

void recv_pcap_packet3ikev1(u_char *user
                      , const struct pcap_pkthdr *h
                      , const u_char *bytes)
{
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    /* before receiving the packet, need to complete the async calculation of the g^xy */


    cur_debugging |= DBG_PRIVATE|DBG_CRYPT|DBG_PARSING|DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;
    recv_pcap_packet_gen(user, h, bytes);

    /* find st involved */
    st = state_with_serialno(1);
    if(st) {
      run_continuation(crypto_req);
    }
}

recv_pcap recv_inputs[PCAP_INPUT_COUNT]={
    recv_pcap_packet1ikev1,
    recv_pcap_packet2ikev1_128,
    recv_pcap_packet3ikev1,
    recv_pcap_packet3ikev1,
};

#include "../lp12-parentR2/parentR2_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
