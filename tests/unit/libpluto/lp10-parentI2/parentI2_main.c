#ifndef FINISH_PCAP
void finish_pcap(void) {}
#endif

int main(int argc, char *argv[])
{
    int   len;
    char *infile;
    char *conn_name;
    int  lineno=0;
    int  regression = 0;
    struct connection *c1;
    struct state *st;
    char *pcap_out;
    char *pcapin[PCAP_INPUT_COUNT];
    int   i;

#ifdef HAVE_EFENCE
    EF_PROTECT_FREE=1;
#endif

    unsetenv("TZ"); tzset();
    progname = argv[0];
    leak_detective = 1;

    /* skip argv0 */
    argc--; argv++;

    if(argc > 0 && strcmp(argv[0], "-r")==0) {
        regression = 1;
        argc--; argv++;
    }

    if(argc != 3+PCAP_INPUT_COUNT) {
        fprintf(stderr, "Wrong number of arguments, received: %u rather than %u\n",
                argc, 3+PCAP_INPUT_COUNT);
	fprintf(stderr, "Usage: %s [-r] <whackrecord> <conn-name> <pcapout> <pcapfile>\n", progname);
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

    /* output first packets to /dev/null */
    send_packet_setup_pcap("/dev/null");

    c1 = con_by_name(conn_name, TRUE);
    assert(c1 != NULL);

    assert(orient(c1, 500));
    show_one_connection(c1, whack_log);
    init_loaded();

    reset_globals();
    st = sendI1(c1, DBG_CONTROL, regression == 0);
    enable_debugging_on_sa(1);

    cur_debugging = DBG_CONTROL|DBG_CONTROLMORE|DBG_PARSING;
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

        /* process next Rx packet */
        cur_debugging = DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;
        pcap_dispatch(pt, 1, recv_inputs[i], NULL);

        /* set up output file */
        pcap_close(pt);
    }

    finish_pcap();

#ifdef FINISH_NEGOTIATION
    finish_negotiation();
#endif
    send_packet_setup_pcap("/dev/null");
    fprintf(stderr, "%u: output closed\n", i);
    delete_connection(c1, TRUE);

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
