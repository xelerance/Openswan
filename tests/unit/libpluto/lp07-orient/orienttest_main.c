int main(int argc, char *argv[])
{
    char *infile;
    char *conn_name;
    struct connection *c1 = NULL;

#ifdef HAVE_EFENCE
    EF_PROTECT_FREE=1;
#endif

    progname = argv[0];
    leak_detective = 1;

    struct osw_conf_options *oco = osw_init_options();
    pfree_z(oco->pluto_shared_secrets_file);
    oco->pluto_shared_secrets_file = clone_str("/dev/null", "main");

    if(argc < 3) {
	fprintf(stderr, "Usage: %s <whackrecord> <conn-name>\n", progname);
	exit(10);
    }
    /* argv[1] == "-r" */

    tool_init_log();
    init_fake_vendorid();
    init_local_interface(TRUE);
    init_fake_secrets();

    argc--;
    argv++;

    infile = *argv;
    if(readwhackmsg(infile) == 0) exit(10);

    argc--;
    argv++;

    while(argc-->0) {
        conn_name = *argv++;
        printf("processing %s\n", conn_name);
        c1 = con_by_name(conn_name, TRUE);
	if(!c1) {
		printf("no connection %s found\n", conn_name);
		exit(10);
	}
        show_one_connection(c1, whack_log);
        assert(c1 != NULL);
        assert(orient(c1, oco->pluto_port500));
    }

    delete_connection(c1, TRUE, FALSE);
    tool_close_log();

    report_leaks();

    exit(0);
}


/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
