#include "../lp12-parentR2/parentR2_head.c"
#include "pluto_crypt.h"
#include "seam_gi_sha256_group14.c"
#include "seam_finish.c"
#include "seam_pending.c"
#include "seam_ikev1.c"
#include "seam_ikev1_aggr.c"
#include "seam_kernel.c"
#include "seam_x509_list.c"
#include "seam_host_jamesjohnson.c"
#include "seam_crypt.c"
#include "seam_rsasig.c"
#include "seam_natt.c"

#define TESTNAME "certreplyselfR2"

static void init_local_interface(void)
{
    init_jamesjohnson_interface();
    init_seam_kernelalgs();
}

static void init_fake_secrets(void)
{
    prompt_pass_t pass;
    memset(&pass, 0, sizeof(pass));
    osw_init_ipsecdir_str("../samples/gatewaycert");

    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/gatewaycert.secrets"
			       , &pass, NULL);
}

/* this step is an INIT, so no state, but need KE values */
void recv_pcap_packet3(u_char *user
                      , const struct pcap_pkthdr *h
                      , const u_char *bytes)
{
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    recv_pcap_packet_gen(user, h, bytes);

    /* find st involved */
    st = state_with_serialno(3);
    if(st) {
        st->st_connection->extra_debugging = DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;

        /* now fill in the KE values from a constant.. not calculated */
        clonetowirechunk(&kn->thespace, kn->space, &kn->secret, SS(secret.ptr),SS(secret.len));
        clonetowirechunk(&kn->thespace, kn->space, &kn->n,   SS(nr.ptr), SS(nr.len));
        clonetowirechunk(&kn->thespace, kn->space, &kn->gi,  SS(gr.ptr), SS(gr.len));

        run_continuation(crypto_req);
    }
}

static void init_loaded(void)
{
    struct connection *c;

    /* loading X.509 CA certificates */
    load_authcerts("CA cert", oco->cacerts_dir, AUTH_CA);

    c = con_by_name("rw-carol", TRUE);
    assert(c != NULL);
    show_one_connection(c, whack_log);

    c = con_by_name("rw-dave", TRUE);
    assert(c != NULL);
    show_one_connection(c, whack_log);

    hostpair_list();
}



#define PCAP_INPUT_COUNT 3
void recv_pcap_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void recv_pcap_packet2(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

recv_pcap recv_inputs[]={
    recv_pcap_packet,
    recv_pcap_packet2,
    recv_pcap_packet3
};

#include "seam_parentR2.c"
#include "../lp12-parentR2/parentR2_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
