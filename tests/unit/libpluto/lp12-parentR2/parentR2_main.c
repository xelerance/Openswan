u_int8_t reply_buffer[MAX_OUTPUT_UDP_SIZE];

/* this is replicated in the unit test cases since
 * the patching up of the crypto values is case specific */
void recv_pcap_packet_with_ke(u_char *user
		      , const struct pcap_pkthdr *h
		      , const u_char *bytes)
{
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    recv_pcap_packet_gen(user, h, bytes);

    /* find st involved */
    st = state_with_serialno(1);
    if(st) {
        st->st_connection->extra_debugging = DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;

        /* now fill in the KE values from a constant.. not calculated */
        clonetowirechunk(&kn->thespace, kn->space, &kn->n,   SS(nr.ptr), SS(nr.len));
        clonetowirechunk(&kn->thespace, kn->space, &kn->gi,  SS(gr.ptr), SS(gr.len));

        run_one_continuation(crypto_req);
    }
}

void recv_pcap_packet2_with_ke(u_char *user
                      , const struct pcap_pkthdr *h
                      , const u_char *bytes)
{
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    recv_pcap_packet_gen(user, h, bytes);

    /* find st involved */
    st = state_with_serialno(1);
    st->st_connection->extra_debugging = DBG_PRIVATE|DBG_CRYPT|DBG_PARSING|DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;
    clonetowirechunk(&kn->thespace, kn->space, &kn->secret, SS(secret.ptr),SS(secret.len));

    run_one_continuation(crypto_req);
}

#ifndef PCAP_INPUT_COUNT
#define PCAP_INPUT_COUNT 2
recv_pcap recv_inputs[PCAP_INPUT_COUNT]={
    recv_pcap_packet_with_ke,
    recv_pcap_packet2_with_ke,
};
#endif

#ifndef FINISH_PCAP
void finish_pcap(void) {}
#endif

int main(int argc, char *argv[])
{
    char *infile;
    char *conn_name;
    char *pcapin[PCAP_INPUT_COUNT];
    int   i;
    char *pcap_out;
    int regression;
    struct connection *c1;
    struct state *st;

#ifdef HAVE_EFENCE
    EF_PROTECT_FREE=1;
#endif

    progname = argv[0];
    leak_detective = 1;
    zero(pcapin);

    /* skip argv0 */
    argc--; argv++;

    if(argc > 0 && strcmp(argv[0], "-r")==0) {
        regression = 1;
        argc--; argv++;
    }

    (void)regression;

    if(argc != 3+PCAP_INPUT_COUNT) {
	fprintf(stderr, "Usage: [%u!=%u, count=%u] %s <whackrecord> <conn-name> <pcapout> <pcapin1> <pcapin2>..\n", argc, 3+PCAP_INPUT_COUNT, PCAP_INPUT_COUNT, progname);
	exit(10);
    }

    oco = osw_init_options();
    tool_init_log();
    init_crypto();
    load_oswcrypto();
    init_fake_vendorid();
    init_local_interface();
    init_fake_secrets();
    enable_debugging();
    init_demux();
    init_seam_kernelalgs();

    infile = argv[0];
    conn_name = argv[1];
    pcap_out  = argv[2];
    for(i=0; i<PCAP_INPUT_COUNT; i++) {
        pcapin[i] = argv[3+i];
    }

    cur_debugging = DBG_CONTROL|DBG_CONTROLMORE;
    if(readwhackmsg(infile) == 0) exit(10);
    c1 = con_by_name(conn_name, TRUE);
    assert(c1 != NULL);

    assert(orient(c1, 500));
    show_one_connection(c1, whack_log);
    init_loaded();

    for(i=0; i<PCAP_INPUT_COUNT; i++) {
        if((i+1) < PCAP_INPUT_COUNT) {
            /* omit the R1 reply */
            send_packet_setup_pcap("/dev/null");
        } else {
            fprintf(stderr, "%u: output to %s\n", i, pcap_out);
            send_packet_setup_pcap(pcap_out);
        }

        /* setup to process the n'th packet */
        recv_pcap_setup(pcapin[i]);

        /* process first I1 packet */
        cur_debugging = DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;
        pcap_dispatch(pt, 1, recv_inputs[i], NULL);

        /* set up output file */
        pcap_close(pt);
    }

    finish_pcap();

    /* clean up so that we can see any leaks */
    st = state_with_serialno(1);
    if(st!=NULL) {
        free_state(st);
    }

    report_leaks();

    tool_close_log();
    exit(0);
}


 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
