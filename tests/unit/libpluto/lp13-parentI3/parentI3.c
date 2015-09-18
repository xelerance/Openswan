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
#include "seam_host_parker.c"
#include "seam_terminate.c"
#include "seam_x509.c"
#include "seam_spdbstruct.c"
#include "seam_demux.c"
#include "seam_commhandle.c"
#include "seam_whack.c"
#include "seam_exitlog.c"
#include "seam_natt.c"
#include "seam_dnskey.c"
#include "seam_kernelalgs.c"

u_int8_t reply_buffer[MAX_OUTPUT_UDP_SIZE];

#include "seam_gi_sha1.c"
#include "seam_gi_sha1_group14.c"
#include "seam_finish.c"

#include "ikev2sendI1.c"

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

    if(strcmp(argv[0], "-r")==0) {
        regression = 1;
        argc--; argv++;
    }
    if(argc != 4) {
	fprintf(stderr, "Usage: %s [-r] <whackrecord> <conn-name> <pcapR1> <pcapR2>\n", progname);
	exit(10);
    }

    tool_init_log();
    init_crypto();
    load_oswcrypto();
    init_fake_vendorid();
    init_parker_interface();
    init_seam_kernelalgs();
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/parker.secrets"
			       , NULL);

    infile = argv[0];
    conn_name = argv[1];
    pcap1in   = argv[2];
    pcap2in   = argv[3];

    cur_debugging = DBG_CONTROL|DBG_CONTROLMORE;
    if(readwhackmsg(infile) == 0) exit(10);
    c1 = con_by_name(conn_name, TRUE);
    assert(c1 != NULL);

    assert(orient(c1, 500));
    show_one_connection(c1);

    /* output first packets to /dev/null */
    send_packet_setup_pcap("/dev/null");

    st = sendI1(c1, DBG_CONTROL, regression == 0);

    /* input packet R1 */
    recv_pcap_setup(pcap1in);

    cur_debugging = DBG_CONTROL|DBG_CONTROLMORE|DBG_PARSING;
    pcap_dispatch(pt, 1, recv_pcap_packet, NULL);

    /* now process the R2 packet */
    recv_pcap_setup(pcap2in);

    cur_debugging = DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;
    pcap_dispatch(pt, 1, recv_pcap_packet2, NULL);

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
