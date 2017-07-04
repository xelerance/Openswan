void recv_pcap_packetC1(u_char *user
                      , const struct pcap_pkthdr *h
                      , const u_char *bytes)
{
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    recv_pcap_packet_gen(user, h, bytes);

    /* find st involved */
    st = state_with_serialno(3);
    st->st_connection->extra_debugging = DBG_PRIVATE|DBG_CRYPT|DBG_PARSING|DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;

    /* now fill in the KE values from a constant.. not calculated */
    clonetowirechunk(&kn->thespace, kn->space, &kn->n,   tc14_nr, tc14_nr_len);
    clonetowirechunk(&kn->thespace, kn->space, &kn->gi,  tc14_gr, tc14_gr_len);

    run_one_continuation(crypto_req);

    /* now do the second calculation */
    clonetowirechunk(&kn->thespace, kn->space, &kn->secret, tc14_secretr,tc14_secretr_len);
    run_one_continuation(crypto_req);
}

#define PCAP_INPUT_COUNT 3
recv_pcap recv_inputs[PCAP_INPUT_COUNT]={
    recv_pcap_packet,
    recv_pcap_packet2,
    recv_pcap_packetC1
};

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
