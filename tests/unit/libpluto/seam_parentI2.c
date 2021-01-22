/* this is replicated in the unit test cases since the patching up of the crypto values is case specific */
void recv_pcap_packet(u_char *user
		      , const struct pcap_pkthdr *h
		      , const u_char *bytes)
{
    static int call_counter = 0;
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    call_counter++;
#if 0
    DBG_log("%s() call %d: enter", __func__, call_counter);
#endif

    enable_debugging_on_sa(1);

    recv_pcap_packet_gen(user, h, bytes);

    /* find st involved */
    st = state_with_serialno(1);
    if(st != NULL) {
        passert(st != NULL);
        st->st_connection->extra_debugging = DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE|DBG_CRYPT|DBG_PRIVATE;
    }

    run_continuation(crypto_req);
}

#ifndef PCAP_INPUT_COUNT
#define PCAP_INPUT_COUNT 1
recv_pcap recv_inputs[PCAP_INPUT_COUNT]={
    recv_pcap_packet,
};
#endif
