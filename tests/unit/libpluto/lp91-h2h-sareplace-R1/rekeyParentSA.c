#include "../lp13-parentI3/parentI3_head.c"
#include "seam_x509.c"
#include "seam_gi_sha1.c"
#include "seam_gi_sha1_group14.c"
#include "seam_finish.c"
#include "seam_ikev2_sendI1.c"
#include "seam_debug.c"
#include "seam_rsasig.c"
#include "seam_keys.c"
#include "seam_kernel.c"

#define TESTNAME "rekeyParentSA"

/* this is replicated in the unit test cases since the patching up of the crypto values is case specific */
void recv_pcap_packet(u_char *user
		      , const struct pcap_pkthdr *h
		      , const u_char *bytes)
{
    static int call_counter = 0;

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

    call_counter++;
    DBG_log("%s() call %d: enter", __func__, call_counter);

    enable_debugging();
    enable_debugging_on_sa(1);
    enable_debugging_on_sa(2);

    recv_pcap_packet_gen(user, h, bytes);

    if (call_counter == 3) {
	    /* we received the third packet, ISAKMP_v2_SA_INIT,
	     * and queued a 'build_ke', which we have to emulate...
	     * now fill in the KE values from a constant.. not calculated */
	    passert(kn->oakley_group == SS(oakleygroup));
	    clonetowirechunk(&kn->thespace, kn->space, &kn->secret, SS(secret.ptr),SS(secret.len));
	    clonetowirechunk(&kn->thespace, kn->space, &kn->n,   SS(ni.ptr), SS(ni.len));
	    clonetowirechunk(&kn->thespace, kn->space, &kn->gi,  SS(gi.ptr), SS(gi.len));
    }

    DBG_log("%s() call %d: continuation", __func__, call_counter);
    run_continuation(crypto_req);

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
