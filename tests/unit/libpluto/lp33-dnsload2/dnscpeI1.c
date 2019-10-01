#include "../lp02-parentI1/parentI1_head.c"
#include "seam_gi_sha1.c"
#include "seam_gi_sha1_group14.c"
#include "seam_finish.c"
#include "seam_ikev2_sendI1.c"
#include "seam_natt.c"
#include "seam_demux.c"
#include "seam_x509.c"
#include "seam_whack.c"
#include "seam_host_parker.c"
#include "seam_makealg.c"
#include "seam_rsasig.c"

#define TESTNAME "dnscpeI1"

static void init_local_interface(void)
{
    init_parker_interface(FALSE);
}

static void init_fake_secrets(void)
{
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/parker.secrets"
			       , NULL, NULL);
}

unsigned int sort_dns_answers;

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
    sort_dns_answers = 1;

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
    init_adns();
    init_fake_vendorid();
    init_fake_secrets();
    init_local_interface();

    infile = argv[0];
    conn_name = argv[1];

    cur_debugging = DBG_CONTROL|DBG_CONTROLMORE;
    if(readwhackmsg(infile) == 0) exit(11);

    send_packet_setup_pcap("OUTPUT/" TESTNAME ".pcap");

    c1 = con_by_name(conn_name, TRUE);
    assert(c1 != NULL);

    show_one_connection(c1, whack_log);

    /*
     * this is now 0, since an address family has *NOT* been chosen,
     * given that this=>%defaultroute, and that=>%dns
     */
    assert(c1->end_addr_family == 0);

    reset_globals();
    /* do calculation if not -r for regression */
    st = sendI1(c1, DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE, regression == 0);

    /* should have not created any state, no IP address yet */
    assert(st == NULL);

    reset_globals();
    send_unsent_ADNS_queries();

    /* now process returned DNS packets (NOTES: needs example.com to be alive!) */
    /* XXX -- mock out the DNS system */
    handle_adns_answer();

    /* should be no continuations created... */
    assert(continuation == NULL);

    /* and now see about running continuations */
    sendI1b(c1, DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE, regression == 0);

    show_states_status();

    /* should still be no continuations created */
    assert(continuation == NULL);

    /* so give it some attention */
    c1->policy |= POLICY_UP;
    st = sendI1(c1, DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE, regression == 0);
    if(st!=NULL) {
        delete_state(st);
        free_state(st);
    }

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
