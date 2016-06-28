#include "../lp13-parentI3/parentI3_head.c"

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

    /* find st involved */
    st = state_with_serialno(1);
    if(st != NULL) {
        passert(st != NULL);
        st->st_connection->extra_debugging = DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE|DBG_CRYPT|DBG_PRIVATE;
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

    recv_pcap_packet(user, h, bytes);

    fprintf(stderr, "now pretend that the keylife timer is up, and rekey the connection\n");
    show_states_status();

    timer_list();
    st = state_with_serialno(2);

    if(st) {
        DBG(DBG_LIFECYCLE
            , openswan_log("replacing stale %s SA"
                           , (IS_PHASE1(st->st_state)|| IS_PHASE15(st->st_state ))? "ISAKMP" : "IPsec"));
        ipsecdoi_replace(st, LEMPTY, LEMPTY, 1);
    } else {
        fprintf(stderr, "no state #2 found\n");
    }

    passert(kn->oakley_group == tc14_oakleygroup);

    /* now fill in the KE values from a constant.. not calculated */
    clonetowirechunk(&kn->thespace, kn->space, &kn->secret, tc14_secret,tc14_secret_len);
    clonetowirechunk(&kn->thespace, kn->space, &kn->n,   tc14_ni, tc14_ni_len);  /* maybe change nonce for rekey? */
    clonetowirechunk(&kn->thespace, kn->space, &kn->gi,  tc14_gi, tc14_gi_len);

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
