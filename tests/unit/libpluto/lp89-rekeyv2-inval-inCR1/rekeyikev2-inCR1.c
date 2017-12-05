#define WANT_THIS_DBG DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE|DBG_CRYPT|DBG_PRIVATE|DBG_PARSING
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../lp13-parentI3/parentI3_head.c"
#include "seam_x509.c"
#include "seam_rsasig.c"
#include "seam_gi_sha1.c"
#include "seam_gi_sha1_group14.c"
#include "seam_finish.c"
#include "seam_keys.c"
#include "seam_ikev2_sendI1.c"
#include "seam_debug.c"
#include "seam_kernel.c"

static void init_fake_secrets(void)
{
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/parker.secrets"
			       , NULL, NULL);
}

static void init_loaded(void)
{   /* nothing */ }

#define TESTNAME "rekeyikev2-CR1"


/* this is replicated in the unit test cases since the patching up of the crypto values is case specific */
void recv_pcap_packet(u_char *user
		      , const struct pcap_pkthdr *h
		      , const u_char *bytes)
{
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    recv_pcap_packet_gen(user, h, bytes);

    enable_debugging();
    enable_debugging_on_sa(2);

    /* find st involved */
    st = state_with_serialno(1);
    if(st != NULL) {
        passert(st != NULL);
        st->st_connection->extra_debugging = WANT_THIS_DBG;
    }

    run_continuation(crypto_req);
}

/*
 * this routine accepts the I3 packet, and the causes a rekey to be queued */
void recv_pcap_I3_rekey(u_char *user
		      , const struct pcap_pkthdr *h
		      , const u_char *bytes)
{
    struct state *st = NULL;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    /* create a socket for a possible whack process that is doing --up */
    int fake_whack_fd = open("/dev/null", O_RDWR);
    passert(fake_whack_fd != -1);

    recv_pcap_packet(user, h, bytes);

    fprintf(stderr, "now pretend that the keylife timer is up, and rekey the connection\n");
    show_states_status();

    timer_list();
    st = state_with_serialno(2);
    st->st_whack_sock = fake_whack_fd;

    if(st) {
        DBG(DBG_LIFECYCLE
            , openswan_log("replacing stale %s SA"
                           , (IS_PHASE1(st->st_state)|| IS_PHASE15(st->st_state ))? "ISAKMP" : "IPsec"));

        ipsecdoi_replace(st, LEMPTY, LEMPTY, 1);
    } else {
        fprintf(stderr, "no state #2 found\n");
    }

    /* find new state! */
    st = state_with_serialno(3);
    passert(st->st_whack_sock != -1);

    passert(kn->oakley_group == SS(oakleygroup));

    /* now fill in the KE values from a constant.. not calculated */
    clonetowirechunk(&kn->thespace, kn->space, &kn->secret, SS(secret.ptr),SS(secret.len));
    clonetowirechunk(&kn->thespace, kn->space, &kn->n,   SS(ni.ptr), SS(ni.len));  /* maybe change nonce for rekey? */
    clonetowirechunk(&kn->thespace, kn->space, &kn->gi,  SS(gi.ptr), SS(gi.len));

    run_continuation(crypto_req);
}

#define PCAP_INPUT_COUNT 3
recv_pcap recv_inputs[PCAP_INPUT_COUNT]={
    recv_pcap_packet,
    recv_pcap_I3_rekey,
    recv_pcap_packet,
};



#include "../lp13-parentI3/parentI3_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
