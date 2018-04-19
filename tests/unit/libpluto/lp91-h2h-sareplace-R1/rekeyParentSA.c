#include "../lp13-parentI3/parentI3_head.c"

#define TESTNAME "rekeyParentSA"

#define WANT_THIS_DBG DBG_EMITTING|DBG_PARSING|DBG_CONTROL|DBG_CONTROLMORE|DBG_CRYPT|DBG_PRIVATE

void enable_debugging(void)
{
    base_debugging = WANT_THIS_DBG;
    reset_debugging();
}

void enable_debugging_on_sa(int num)
{
    struct state *st;
    lset_t to_enable = WANT_THIS_DBG;
    st = state_with_serialno(num);
    if(st != NULL) {
        passert(st->st_connection != NULL);
        st->st_connection->extra_debugging = to_enable;
    }
}

/* this is replicated in the unit test cases since the patching up of the crypto values is case specific */
void recv_pcap_packet(u_char *user
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

    DBG_log("%s() call %d: continuation", __func__, call_counter);
    run_continuation(crypto_req);

    DBG_log("%s() call %d: exit", __func__, call_counter);
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
