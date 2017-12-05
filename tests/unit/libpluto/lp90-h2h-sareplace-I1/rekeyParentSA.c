#include "../lp12-parentR2/parentR2_head.c"
#include "seam_natt.c"
#include "seam_host_jamesjohnson.c"
#include "seam_x509.c"
#include "seam_debug.c"
#include "seam_keys.c"
#include "seam_gr_sha1_group14.c"
#include "seam_finish.c"
#include "seam_kernel.c"

#define TESTNAME "rekeyParentSA"

static void init_local_interface(void)
{
    init_jamesjohnson_interface();
}

static void init_fake_secrets(void)
{
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/jj.secrets"
			       , NULL, NULL);
}

static void init_loaded(void)
{   /* nothing */ }

void recv_pcap_packet2_and_rekey(u_char *user
                      , const struct pcap_pkthdr *h
                      , const u_char *bytes)
{
    static int call_counter = 0;
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    call_counter++;
    DBG_log("%s() call %d: enter", __func__, call_counter);

    enable_debugging();
    enable_debugging_on_sa(1);
    enable_debugging_on_sa(2);

    recv_pcap_packet2_with_ke(user, h, bytes);

    /* find st involved */
    st = state_with_serialno(1);
    passert(st != NULL);

    DBG_log("%s() call %d: start IKE rekey", __func__, call_counter);

    /* now arrange to rekey the SA */
    ipsecdoi_replace(st, LEMPTY, LEMPTY, st->st_try);

    /* now arrange to expire the SA, as in timer.c */
    delete_dpd_event(st);

    /* which really leads to deleting the PARENT SA */
    delete_state(st);

    /* ipsecdoi_replace() queued a 'build_ke', which we have to emulate...
     * now fill in the KE values from a constant.. not calculated */
    passert(kn->oakley_group == SS(oakleygroup));
    clonetowirechunk(&kn->thespace, kn->space, &kn->secret, SS(secret.ptr),SS(secret.len));
    clonetowirechunk(&kn->thespace, kn->space, &kn->n,   SS(nr.ptr), SS(nr.len));
    clonetowirechunk(&kn->thespace, kn->space, &kn->gi,  SS(gr.ptr), SS(gr.len));

    DBG_log("%s() call %d: continuation", __func__, call_counter);
    run_one_continuation(crypto_req);

    DBG_log("%s() call %d: exit", __func__, call_counter);
}


#ifndef PCAP_INPUT_COUNT
#define PCAP_INPUT_COUNT 2
recv_pcap recv_inputs[PCAP_INPUT_COUNT]={
    recv_pcap_packet_with_ke,
    recv_pcap_packet2_and_rekey,
};
#endif

#include "../lp12-parentR2/parentR2_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
