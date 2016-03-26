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

    if(argc != 3 && argc!=4) {
	fprintf(stderr, "Usage: %s [-r] <whackrecord> <conn-name>\n", progname);
	exit(10);
    }
    /* skip argv0 */
    argc--; argv++;

    if(strcmp(argv[0], "-r")==0) {
        regression = 1;
        argc--; argv++;
    }

    tool_init_log();
    load_oswcrypto();
    init_fake_vendorid();
    init_fake_secrets();
    init_local_interface();

    infile = argv[0];
    conn_name = argv[1];

    cur_debugging = DBG_CONTROL|DBG_CONTROLMORE;
    if(readwhackmsg(infile) == 0) {
        fprintf(stderr, "failed to read whack file: %s\n", infile);
        exit(11);
    }

    send_packet_setup_pcap("OUTPUT/" TESTNAME ".pcap");

    c1 = con_by_name(conn_name, TRUE);
    assert(c1 != NULL);
#ifdef INIT_LOADED
    INIT_LOADED(c1);
#endif

    //list_public_keys(FALSE, FALSE);
#ifndef SKIP_ORIENT_ASSERT
    assert(orient(c1, 500));
#endif
    show_one_connection(c1, whack_log);

#ifndef SKIP_INITIATE
    /* do calculation if not -r for regression */
    st = sendI1(c1, DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE, regression == 0);

    st = state_with_serialno(1);
    if(st!=NULL) {
        delete_state(st);
        free_state(st);
    }
#endif

    delete_connection(c1, TRUE);

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
