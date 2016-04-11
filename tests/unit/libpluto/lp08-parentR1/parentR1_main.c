u_int8_t reply_buffer[MAX_OUTPUT_UDP_SIZE];

#include <pcap.h>

#include "seam_gr_sha1_group14.c"

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
    if(st) {
        st->st_connection->extra_debugging = DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;

        /* now fill in the KE values from a constant.. not calculated */
        clonetowirechunk(&kn->thespace, kn->space, &kn->secret, tc14_secretr,tc14_secretr_len);
        clonetowirechunk(&kn->thespace, kn->space, &kn->n,   tc14_nr, tc14_nr_len);
        clonetowirechunk(&kn->thespace, kn->space, &kn->gi,  tc14_gr, tc14_gr_len);

        run_continuation(crypto_req);
    }
}



int main(int argc, char *argv[])
{
    int   len;
    char *infile, *pcapin, *pcapout;
    char *conn_name;
    int  lineno=0;
    struct connection *c1;
    struct state *st;
    char   eb1[256];  /* error buffer for pcap open */

#ifdef HAVE_EFENCE
    EF_PROTECT_FREE=1;
#endif

    progname = argv[0];
    leak_detective = 1;

    if(argc <= 4) {
    usage:
	fprintf(stderr, "Usage: %s <whackrecord> <conn-name> <pcapin> <pcapout>\n", progname);
	exit(10);
    }
    /* argv[1] == "-r" ?? */

    tool_init_log();
    init_crypto();
    init_fake_vendorid();
    init_fake_secrets();
    init_jamesjohnson_interface();
    init_demux();

    infile = NULL;
    conn_name = NULL;
    pcapin  = NULL;
    pcapout = NULL;
    argc--; argv++;
    if(argc > 0) {
        infile = argv[0];
        argc--; argv++;
    }
    if(argc > 0) {
        conn_name = argv[0];
        argc--; argv++;
    }
    if(argc > 0) {
        pcapin = argv[0];
        argc--; argv++;
    }
    if(argc > 0) {
        pcapout = argv[0];
        argc--; argv++;
    }
    if(conn_name == NULL ||
       infile    == NULL ||
       pcapin    == NULL ||
       pcapout   == NULL) {
        goto usage;
    }

    cur_debugging = DBG_CONTROL|DBG_CONTROLMORE;
    if(readwhackmsg(infile) == 0) exit(10);
    c1 = con_by_name(conn_name, TRUE);
    assert(c1 != NULL);

    assert(orient(c1, 500));
    show_one_connection(c1, whack_log);

    send_packet_setup_pcap(pcapout);

    /* setup to process the I1 packet */
    recv_pcap_setup(pcapin);

    cur_debugging = DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;
    pcap_dispatch(pt, 1, recv_pcap_packet, NULL);

    /* clean up so that we can see any leaks */
    st = state_with_serialno(1);
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
