void update_ngi(struct pcr_kenonce *kn)
{

    if(kn->thespace.len == 0) {
        fprintf(stderr, "failed to setup crypto_req, exiting\n");
        exit(89);
    }

    /* now fill in the KE values from a constant.. not calculated */
    clonetowirechunk(&kn->thespace, kn->space, &kn->secret, SS(secret.ptr), SS(secret.len));
    clonetowirechunk(&kn->thespace, kn->space, &kn->n,      SS(ni.ptr), SS(ni.len));
    clonetowirechunk(&kn->thespace, kn->space, &kn->gi,     SS(gi.ptr), SS(gi.len));
}

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
        st->hidden_variables.st_nat_traversal |= NAT_T_WITH_NATD;

        update_ngi(kn);

    }

    run_continuation(crypto_req);
}

void recv_pcap_packet2ikev1(u_char *user
                      , const struct pcap_pkthdr *h
                      , const u_char *bytes)
{
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    recv_pcap_packet_gen(user, h, bytes);

    /* find st involved */
    st = state_with_serialno(1);
    if(st) {
      st->st_connection->extra_debugging = DBG_PRIVATE|DBG_CRYPT|DBG_PARSING|DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;
      update_ngi(kn);
      run_continuation(crypto_req);
    }
}

void recv_pcap_packet3ikev1(u_char *user
                      , const struct pcap_pkthdr *h
                      , const u_char *bytes)
{
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    /* before receiving the packet, need to complete the async calculation of the g^xy */


    cur_debugging |= DBG_PRIVATE|DBG_CRYPT|DBG_PARSING|DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;
    recv_pcap_packet_gen(user, h, bytes);

    /* find st involved */
    st = state_with_serialno(2);
    if(st) {
      run_continuation(crypto_req);
    }
}
