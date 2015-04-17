#define LEAK_DETECTIVE
#define AGGRESSIVE 1
#define XAUTH
#define MODECFG
#define DEBUG 1
#define PRINT_SA_DEBUG 1
#define USE_KEYRR 1

#include "constants.h"
#include "oswalloc.h"
#include "whack.h"
#include "../../programs/pluto/rcv_whack.h"

#include "../../programs/pluto/connections.c"

#include "whackmsgtestlib.c"
#include "seam_timer.c"
#include "seam_fakevendor.c"
#include "seam_pending.c"
#include "seam_ikev1.c"
#include "seam_crypt.c"
#include "seam_kernel.c"
#include "seam_rnd.c"
#include "seam_log.c"
#include "seam_xauth.c"
#include "seam_jamesjohnson.c"
#include "seam_terminate.c"
#include "seam_x509.c"
#include "seam_spdbstruct.c"
#include "seam_demux.c"
#include "seam_commhandle.c"
#include "seam_whack.c"
#include "seam_keys.c"
#include "seam_exitlog.c"
#include "seam_natt.c"
#include "seam_kernelalgs.c"

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

void recv_pcap_packet2(u_char *user
                      , const struct pcap_pkthdr *h
                      , const u_char *bytes)
{
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    recv_pcap_packet_gen(user, h, bytes);

    /* find st involved */
    st = state_with_serialno(1);
    st->st_connection->extra_debugging = DBG_PRIVATE|DBG_CRYPT|DBG_PARSING|DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;

    run_continuation(crypto_req);

}



main(int argc, char *argv[])
{
    int   len;
    char *infile;
    char *conn_name;
    char *pcap1in;
    char *pcap2in;
    char *pcap_out;
    int  lineno=0;
    int regression;
    pcap_t *pt;
    struct connection *c1;
    struct state *st;
    char   eb1[256];  /* error buffer for pcap open */

    EF_PROTECT_FREE=1;

    progname = argv[0];
    leak_detective = 1;

    /* skip argv0 */
    argc--; argv++;

    if(strcmp(argv[0], "-r")==0) {
        regression = 1;
        argc--; argv++;
    }

    if(argc != 5) {
	fprintf(stderr, "Usage: %s <whackrecord> <conn-name> <pcapin1> <pcapin2> <pcapout>\n", progname);
	exit(10);
    }

    tool_init_log();
    init_crypto();
    load_oswcrypto();
    init_fake_vendorid();
    init_jamesjohnson_interface();
    init_seam_kernelalgs();

    infile = argv[0];
    conn_name = argv[1];
    pcap1in   = argv[2];
    pcap2in   = argv[3];
    pcap_out  = argv[4];

    cur_debugging = DBG_CONTROL|DBG_CONTROLMORE;
    if(readwhackmsg(infile) == 0) exit(10);
    c1 = con_by_name(conn_name, TRUE);
    assert(c1 != NULL);

    assert(orient(c1, 500));
    show_one_connection(c1);

    /* omit the R1 reply */
    send_packet_setup_pcap("/dev/null");

    pt = pcap_open_offline(pcap1in, eb1);
    if(!pt) {
	fprintf(stderr, "can not open %s: %s\n", argv[3], eb1);
	exit(50);
    }

    /* process first I1 packet */
    cur_debugging = DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;
    pcap_dispatch(pt, 1, recv_pcap_packet, NULL);

    /* set up output file */
    send_packet_setup_pcap(pcap_out);
    pcap_close(pt);

    /* now process the I2 packet */
    pt = pcap_open_offline(pcap2in, eb1);
    if(!pt) {
	fprintf(stderr, "can not open %s: %s\n", argv[3], eb1);
	exit(50);
    }

    cur_debugging = DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;
    pcap_dispatch(pt, 1, recv_pcap_packet2, NULL);

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
