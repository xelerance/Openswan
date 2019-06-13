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

void rekeyit()
{
    struct state *st = NULL;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    fprintf(stderr, "now pretend that the keylife timer is up, and rekey the connection\n");
    show_states_status();

    timer_list();
    st = state_with_serialno(2);

    /* capture the rekey message */
    send_packet_setup_pcap("OUTPUT/" TESTNAME ".pcap");

    if(st) {
        DBG(DBG_LIFECYCLE
            , openswan_log("replacing stale %s SA"
                           , (IS_PHASE1(st->st_state)|| IS_PHASE15(st->st_state ))? "ISAKMP" : "IPsec"));
        ipsecdoi_replace(st, LEMPTY, LEMPTY, 1);
    } else {
        fprintf(stderr, "no state #2 found\n");
    }

    passert(kn->oakley_group == SS(oakleygroup));

    /* now fill in the KE values from a constant.. not calculated */
    clonetowirechunk(&kn->thespace, kn->space, &kn->secret, SS(secret.ptr),SS(secret.len));
    clonetowirechunk(&kn->thespace, kn->space, &kn->n,   SS(ni.ptr), SS(ni.len));  /* maybe change nonce for rekey? */
    clonetowirechunk(&kn->thespace, kn->space, &kn->gi,  SS(gi.ptr), SS(gi.len));

    run_continuation(crypto_req);

    send_packet_close();
}

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
