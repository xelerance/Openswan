/* this is replicated in the unit test cases since the patching up of the crypto values is case specific */
void recv_pcap_packet(u_char *user
		      , const struct pcap_pkthdr *h
		      , const u_char *bytes)
{
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    recv_pcap_packet_gen(user, h, bytes);

    enable_debugging();
    enable_debugging_on_sa(1);

    /* find st involved */
    st = state_with_serialno(1);
    if(st != NULL) {
        passert(st != NULL);
        st->st_connection->extra_debugging = WANT_THIS_DBG;
    }

    run_continuation(crypto_req);
}

/* this is our override to the unpack_nonce() in prgrams/pluto/ipsec_doi.c */
static int unpack_nonce_will_corrupt = 0;
void unpack_nonce(chunk_t *n, struct pluto_crypto_req *r)
{
    struct pcr_kenonce *kn = &r->pcr_d.kn;

    openswan_log("********************************************************************************");
    openswan_log("********************************************************************************");
    openswan_log("********************************************************************************");
    openswan_log("This version of unpack_nonce(), used in OpenSWAN unit testing purposefully "
		 "corrupts the Nonce payload to force a subsequent unit test to respond with "
		 "an encrypted Notification.");

    freeanychunk(*n);
    clonetochunk(*n, wire_chunk_ptr(kn, &(kn->n))
                 , DEFAULT_NONCE_SIZE, "initiator nonce");

    if (unpack_nonce_will_corrupt) {
	    openswan_log("unpack_nonce_will_corrupt=%d, we are now corrupting the nonce.",
			 unpack_nonce_will_corrupt);
	    n->len = 2;
    }

    openswan_log("********************************************************************************");
    openswan_log("********************************************************************************");
    openswan_log("********************************************************************************");
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

    enable_debugging();
    enable_debugging_on_sa(2);

    timer_list();
    st = state_with_serialno(2);

    /* capture the rekey message */
    send_packet_setup_pcap("OUTPUT/" TESTNAME ".pcap");

    if(st) {
        /* for this packet, we will corrupt */
        unpack_nonce_will_corrupt = 1;

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
