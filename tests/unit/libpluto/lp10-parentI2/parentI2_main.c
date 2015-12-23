
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
    }

    run_continuation(crypto_req);
}

int main(int argc, char *argv[])
{
    int   len;
    char *infile;
    char *conn_name;
    int  lineno=0;
    int  regression = 0;
    struct connection *c1;
    struct state *st;

#ifdef HAVE_EFENCE
    EF_PROTECT_FREE=1;
#endif

    progname = argv[0];
    leak_detective = 1;

    /* skip argv0 */
    argc--; argv++;

    if(argc != 5 && argc != 4) {
	fprintf(stderr, "Usage: %s [-r] <whackrecord> <conn-name> <pcapfile> <pcapout>\n", progname);
	exit(10);
    }
    if(strcmp(argv[0], "-r")==0) {
        regression = 1;
        argc--; argv++;
    }

    oco = osw_init_options();
    tool_init_log();
    init_crypto();
    load_oswcrypto();
    init_fake_vendorid();
    init_local_interface();
    init_fake_secrets();

    infile = argv[0];
    conn_name = argv[1];

    cur_debugging = DBG_CONTROL|DBG_CONTROLMORE;
    if(readwhackmsg(infile) == 0) exit(10);

    /* input packets */
    recv_pcap_setup(argv[2]);

    /* output first packets to /dev/null */
    send_packet_setup_pcap("/dev/null");

    c1 = con_by_name(conn_name, TRUE);
    assert(c1 != NULL);

    assert(orient(c1, 500));
    show_one_connection(c1, whack_log);
    init_loaded();

    st = sendI1(c1, DBG_CONTROL, regression == 0);

    /* now accept the reply packet:
       output interesting packet to capture file
    */
    send_packet_setup_pcap(argv[3]);

    cur_debugging = DBG_CONTROL|DBG_CONTROLMORE|DBG_PARSING;
    pcap_dispatch(pt, 1, recv_pcap_packet, NULL);

    /* dump the delete message that comes out */
    send_packet_setup_pcap("/dev/null");
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
