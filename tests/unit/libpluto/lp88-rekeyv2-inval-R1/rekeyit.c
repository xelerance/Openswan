void recv_pcap_packetC1(u_char *user
                      , const struct pcap_pkthdr *h
                      , const u_char *bytes)
{
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    recv_pcap_packet_gen(user, h, bytes);

    enable_debugging();
    enable_debugging_on_sa(3);

    /* find st involved */
    st = state_with_serialno(3);
    if (st) st->st_connection->extra_debugging = WANT_THIS_DBG;

    /* now fill in the KE values from a constant.. not calculated */
    clonetowirechunk(&kn->thespace, kn->space, &kn->n,   SS(nr.ptr), SS(nr.len));
    clonetowirechunk(&kn->thespace, kn->space, &kn->gi,  SS(gr.ptr), SS(gr.len));

    run_one_continuation(crypto_req);

    /* now do the second calculation */
    clonetowirechunk(&kn->thespace, kn->space, &kn->secret, SS(secret.ptr),SS(secret.len));
    run_one_continuation(crypto_req);
}

#define PCAP_INPUT_COUNT 3
recv_pcap recv_inputs[PCAP_INPUT_COUNT]={
    recv_pcap_packet_with_ke,
    recv_pcap_packet2_with_ke,
    recv_pcap_packetC1
};

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
