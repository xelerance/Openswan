u_int8_t reply_buffer[MAX_OUTPUT_UDP_SIZE];


#ifndef FINISH_PCAP
void finish_pcap(void) {}
#endif

int main(int argc, char *argv[])
{
    int   len;
    char *infile;
    char *conn_name;
    char *pcapin[PCAP_INPUT_COUNT];
    int   i;
    char *pcap_out;
    int  lineno=0;
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

    if(argc != 3+PCAP_INPUT_COUNT) {
	fprintf(stderr, "Usage: %s <whackrecord> <conn-name> <pcapout> <pcapin1> <pcapin2>..\n", progname);
	exit(10);
    }

    oco = osw_init_options();
    tool_init_log();
    init_crypto();
    init_fake_vendorid();
    init_local_interface();
    init_fake_secrets();
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
        fprintf(stderr, "%u: input from %s\n", i, pcapin[i]);
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
