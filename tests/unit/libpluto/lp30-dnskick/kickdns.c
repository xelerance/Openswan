#define _GNU_SOURCE
#define LEAK_DETECTIVE
#define AGGRESSIVE 1
#define XAUTH
#define MODECFG
#define DEBUG 1
#define PRINT_SA_DEBUG 1
#define USE_KEYRR 1

#include <stdlib.h>
#include "sysdep.h"
#include "efencedef.h"
#include "constants.h"
#include "openswan.h"
#include "oswtime.h"
#include "oswalloc.h"
#include "oswcrypto.h"
#include "whack.h"
#include "../../programs/pluto/rcv_whack.h"

#include "pluto/defs.h"
#include "pluto/demux.h"
#include "pluto/connections.h"
#include "pluto/state.h"

#include "whackmsgtestlib.c"
#include "seam_timer.c"
#include "seam_vendor.c"
#include "seam_pending.c"
#include "seam_kernel.c"
#include "seam_io.c"
#include "seam_log.c"
#include "seam_west.c"
#include "seam_xauth.c"
#include "seam_terminate.c"
#include "seam_secretday.c"
#include "seam_natt.c"
#include "seam_keys.c"
#include "seam_crypt.c"
#include "seam_whack.c"
#include "seam_initiate.c"
#include "seam_ipsecdoi.c"
#include "seam_exitlog.c"
#include "seam_dnskey.c"
#include "seam_host_parker.c"
#include "seam_demux.c"
#include "seam_x509.c"
#include "seam_delete.c"
#include "seam_ke.c"

const char *progname=NULL;
int verbose=0;
int warningsarefatal = 0;

#define TESTNAME "kickdns"

static void init_local_interface(void)
{
    init_parker_interface(TRUE);
}

static void init_fake_secrets(void)
{
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/parker.secrets"
			       , NULL, NULL);
}

int main(int argc, char *argv[])
{
    bool  recalculate = FALSE;
    char *infile;
    char *conn_name;
    struct connection *c1 = NULL;

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
        recalculate = 1;    /* do all crypto */
        argc--; argv++;
    }

    (void)recalculate;

    tool_init_log();
    load_oswcrypto();
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

    //list_public_keys(FALSE, FALSE);
    assert(orient(c1, 500));
    show_one_connection(c1, whack_log);

    kick_adns_connection_lookup(c1, &c1->spd.that, TRUE);

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


