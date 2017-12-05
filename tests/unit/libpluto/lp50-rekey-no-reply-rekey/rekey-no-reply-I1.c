#include "../lp13-parentI3/parentI3_head.c"
#include "seam_x509.c"
#include "seam_gi_sha1.c"
#include "seam_gi_sha1_group14.c"
#include "seam_finish.c"
#include "seam_ikev2_sendI1.c"
#include "seam_rsasig.c"
#include "seam_keys.c"
#include "seam_kernel.c"
#include "ike_continuations.h"

static void init_fake_secrets(void)
{
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/parker.secrets"
			       , NULL, NULL);
}

static void init_loaded(void)
{   /* nothing */ }

#define TESTNAME "rekeyikev2"
#define AFTER_CONN rekeyit

/* this is replicated in the unit test cases since the patching up of the crypto values is case specific */
void recv_pcap_packet(u_char *user
		      , const struct pcap_pkthdr *h
		      , const u_char *bytes)
{
    struct state *st;
    //struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    recv_pcap_packet_gen(user, h, bytes);

    /* find st involved */
    st = state_with_serialno(1);
    if(st != NULL) {
        passert(st != NULL);
        st->st_connection->extra_debugging = DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE|DBG_CRYPT|DBG_PRIVATE;
    }

    run_continuation(crypto_req);
}

#define PCAP_INPUT_COUNT 2
recv_pcap recv_inputs[PCAP_INPUT_COUNT]={
    recv_pcap_packet,
    recv_pcap_packet,
};

so_serial_t rekeyit_once(unsigned int pass, so_serial_t n)
{
    so_serial_t new_sa;
    struct state *st = NULL;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;
    char output[128];

    fprintf(stderr, "\n\n\nnow pretend (%u) that the keylife timer is up, and rekey the connection\n", pass);
    show_states_status();

    timer_list();
    st = state_with_serialno(n);

    /* capture the rekey message */
    snprintf(output, 128, "OUTPUT/rekeyikev2-%u-I1.pcap", pass);
    send_packet_setup_pcap(output);

    if(st) {
        DBG(DBG_LIFECYCLE
            , openswan_log("replacing stale %s SA"
                           , (IS_PHASE1(st->st_state)|| IS_PHASE15(st->st_state ))? "ISAKMP" : "IPsec"));
        ipsecdoi_replace(st, LEMPTY, LEMPTY, 1);
    } else {
        fprintf(stderr, "no state #%lu found\n", n);
    }

    passert(kn->oakley_group == SS(oakleygroup));

    /* now fill in the KE values from a constant.. not calculated */
    clonetowirechunk(&kn->thespace, kn->space, &kn->secret, SS(secret.ptr),SS(secret.len));
    clonetowirechunk(&kn->thespace, kn->space, &kn->n,   SS(ni.ptr), SS(ni.len));  /* maybe change nonce for rekey? */
    clonetowirechunk(&kn->thespace, kn->space, &kn->gi,  SS(gi.ptr), SS(gi.len));

    new_sa = 0;
    if(continuation) {
        struct dh_continuation *dh = (struct dh_continuation *)continuation;
        struct msg_digest *md = dh->md;
        struct state *const st = md->st;

        new_sa = st->st_serialno;
    }
    run_continuation(crypto_req);

    send_packet_close();

    fprintf(stderr, "Newly created state is #%lu\n", new_sa);

    return new_sa;
}

void rekeyit()
{
    so_serial_t sst = rekeyit_once(1, 2);
    //resend_packet();
    rekeyit_once(2, sst);
}


#include "../lp13-parentI3/parentI3_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
