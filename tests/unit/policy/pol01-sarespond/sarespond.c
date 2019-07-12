#define LEAK_DETECTIVE
#define AGGRESSIVE 1
#define XAUTH
#define MODECFG
#define DEBUG 1
#define PRINT_SA_DEBUG 1
#define USE_KEYRR 1

#include <stdlib.h>
#include "constants.h"
#include "oswalloc.h"
#include "oswcrypto.h"
#include "whack.h"
#include "../../programs/pluto/rcv_whack.h"

#include "pluto/defs.h"
#include "state.h"
#include "sysdep.h"
#include "constants.h"
#include "oswalloc.h"
#include "oswtime.h"
#include "id.h"
#include "pluto/x509lists.h"
#include "certs.h"
#include "secrets.h"
#include "demux.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "keys.h"
#include "pluto/connections.h"
#include "ikev2.h"

#include "whackmsgtestlib.c"
#include "seam_debug.c"
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
#include "seam_initiate.c"
#include "seam_exitlog.c"
#include "seam_natt.c"
#include "seam_dnskey.c"
#include "seam_kernelalgs.c"
#include "seam_gi_sha1.c"
#include "seam_gi_sha256_group14.c"
#include "seam_finish.c"
#include "seam_ke.c"
#include "seam_dh_v2.c"
#include "seam_rsasig.c"

u_int8_t reply_buffer[MAX_OUTPUT_UDP_SIZE];

#include "seam_debug.c"

#define TESTNAME "sarespond"

int main(int argc, char *argv[])
{
    int   len;
    char *infile;
    char *conn_name;
    int   i;
    char *pcap_out;
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

    if(argc < 2) {
        fprintf(stderr, "Wrong number of arguments: %d >= %d\n", argc, 2);
	fprintf(stderr, "Usage: %s [-r] <whackrecord> <conn-name> \n", progname);
	exit(9);
    }

    tool_init_log();
    init_crypto();
    load_oswcrypto();
    init_fake_vendorid();
    init_parker_interface(TRUE);
    init_seam_kernelalgs();
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/parker.secrets"
			       , NULL, NULL);
    enable_debugging();

    infile = argv[0];
    conn_name = argv[1];

    cur_debugging = DBG_CONTROL|DBG_CONTROLMORE;
    if(readwhackmsg(infile) == 0) exit(10);
    c1 = con_by_name(conn_name, TRUE);
    assert(c1 != NULL);

    assert(orient(c1, 500));
    show_one_connection(c1, whack_log);

    /* allocate a dummy state to pass in */
    st = new_state();
    st->st_connection = c1;

    /* XXX should be in a loop from a structure, or perhaps read in from a test file */
    {
        stf_status stf;
        struct connection *bestc = NULL;
        struct spd_route  *bestsr= NULL;

        struct traffic_selector tsi[16];
        struct traffic_selector tsr[16];
        unsigned int tsi_n = 0;
        unsigned int tsr_n = 0;

        tsi[0].ts_type = IKEv2_TS_IPV4_ADDR_RANGE;
        tsi[0].ipprotoid=0;
        tsi[0].startport=0;
        tsi[0].endport=65535;
        ttoaddr("192.168.1.1", 0, AF_INET, &tsi[0].low);
        ttoaddr("192.168.1.1", 0, AF_INET, &tsi[0].high);
        tsi_n++;

        tsr[0].ts_type = IKEv2_TS_IPV4_ADDR_RANGE;
        tsr[0].ipprotoid=0;  /* upper-layer protocol */
        tsr[0].startport=0;
        tsr[0].endport=65535;
        ttoaddr("132.213.238.7", 0, AF_INET, &tsr[0].low);
        ttoaddr("132.213.238.7", 0, AF_INET, &tsr[0].high);
        tsr_n++;

        stf = ikev2_child_ts_evaluate(tsi, tsi_n, tsr, tsr_n, INITIATOR
                                      , st, c1, &bestc, &bestsr);
        printf("test case 1: %s\n", stf_status_name(stf));
    }

    show_states_status();

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
