#define NAT_TRAVERSAL
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../lp13-parentI3/parentI3_head.c"
#include "seam_x509.c"
#include "seam_rsasig.c"
#include "seam_keys.c"
#include "seam_gi_sha1.c"
#include "seam_gi_sha1_group14.c"
#include "seam_finish.c"
#include "seam_ikev2_sendI1.c"
#include "seam_debug.c"

#include "../../programs/pluto/replace.c"

#define TESTNAME "rekeyParentSA"

/* this is replicated in the unit test cases since the patching up of the crypto values is case specific */
void recv_pcap_packet(u_char *user
		      , const struct pcap_pkthdr *h
		      , const u_char *bytes)
{
    static int call_counter = 0;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    call_counter++;
    DBG_log("%s() call %d: enter", __func__, call_counter);

    enable_debugging();
    enable_debugging_on_sa(1);
    enable_debugging_on_sa(2);

    recv_pcap_packet_gen(user, h, bytes);

    DBG_log("%s() call %d: continuation", __func__, call_counter);
    run_continuation(crypto_req);

    DBG_log("%s() call %d: exit", __func__, call_counter);
}

void recv_pcap_packet2(u_char *user
                      , const struct pcap_pkthdr *h
                      , const u_char *bytes)
{
    static int call_counter = 0;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;
    struct state *st;

    call_counter++;
    DBG_log("%s() call %d: enter", __func__, call_counter);

    enable_debugging();
    enable_debugging_on_sa(1);
    enable_debugging_on_sa(2);

    recv_pcap_packet_gen(user, h, bytes);

    DBG_log("%s() call %d: look at negotiated SAs", __func__, call_counter);
    show_states_status();

    /* make sure things look ok */

    st = state_with_serialno(1);
    passert(st);
    passert(IS_PARENT_SA(st));

    /* next we replace the parent SA */

    DBG_log("%s() call %d: start IKE SA replace", __func__, call_counter);

    /* enable LIFECYCLE to observe the sa_replace() variables/decisions */
    cur_debugging |= DBG_LIFECYCLE;

    /* initiate the replace */
    sa_replace(st, EVENT_SA_REPLACE);

    /* EVENT_SA_REPLACE, is followed by an immediate EVENT_SA_EXPIRE */
    sa_expire(st);

    /* ipsecdoi_replace() queued a 'build_ke', which we have to emulate...
     * now fill in the KE values from a constant.. not calculated */
    passert(kn->oakley_group == SS(oakleygroup));
    clonetowirechunk(&kn->thespace, kn->space, &kn->secret, SS(secret.ptr),SS(secret.len));
    clonetowirechunk(&kn->thespace, kn->space, &kn->n,   SS(nr.ptr), SS(nr.len));
    clonetowirechunk(&kn->thespace, kn->space, &kn->gi,  SS(gr.ptr), SS(gr.len));

    /* lookup the new state */

    st = state_with_serialno(3);
    DBG_log("%s() call %d: #%lu st_state=%u\n",
	    __func__, call_counter, st->st_serialno, st->st_state);
    passert(st != NULL);
    passert(st->st_state == STATE_PARENT_I1);

    /* run crypto continuation */

    DBG_log("%s() call %d: continuation", __func__, call_counter);
    run_one_continuation(crypto_req);

    /* done */

    DBG_log("%s() call %d: exit", __func__, call_counter);
}

static void init_fake_secrets(void)
{
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/parker.secrets"
			       , NULL, NULL);
}

static void init_loaded(void)
{   /* nothing */ }

#define PCAP_INPUT_COUNT 2
recv_pcap recv_inputs[PCAP_INPUT_COUNT]={
    recv_pcap_packet,
    recv_pcap_packet2,
};


#include "../lp13-parentI3/parentI3_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
