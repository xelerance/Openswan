/* we want to link against the real timer code for this test */
#define NAT_TRAVERSAL
#include "../lp12-parentR2/parentR2_head.c"
#include "seam_natt.c"
#include "seam_host_jamesjohnson.c"
#include "seam_x509.c"
#include "seam_debug.c"
#include "seam_gr_sha1_group14.c"
#include "seam_finish.c"
#include "seam_keys.c"

#include "../../programs/pluto/replace.c"

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
    //struct event ev;

    call_counter++;
    DBG_log("%s() call %d: enter", __func__, call_counter);

    enable_debugging();
    enable_debugging_on_sa(1);
    enable_debugging_on_sa(2);

    recv_pcap_packet2_with_ke(user, h, bytes);

    DBG_log("%s() call %d: look at negotiated SAs", __func__, call_counter);
    show_states_status();

    /* make sure things look ok */

    st = state_with_serialno(1);
    passert(st != NULL);
    passert(IS_PARENT_SA(st));

    /* next we replace the parent SA */

    DBG_log("%s() call %d: start IKE SA replace", __func__, call_counter);

    /* enable LIFECYCLE to observe the sa_replace() refuse to replace
     * the parent SA with the peer behind NAT */
    cur_debugging |= DBG_LIFECYCLE;

    /* initiate the replace */
    sa_replace(st, EVENT_SA_REPLACE);

    /* there should be no continuation */

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
