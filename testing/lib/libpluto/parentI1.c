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
#include "seam_pending.c"
#include "seam_ikev1.c"
#include "seam_crypt.c"
#include "seam_kernel.c"
#include "seam_rnd.c"
#include "seam_log.c"
#include "seam_xauth.c"
#include "seam_initiate.c"
#include "seam_alg.c"
#include "seam_x509.c"
#include "seam_spdbstruct.c"
#include "seam_demux.c"

u_int8_t reply_buffer[MAX_OUTPUT_UDP_SIZE];
bool nat_traversal_support_non_ike = FALSE;
bool nat_traversal_support_port_floating = FALSE;

main(int argc, char *argv[])
{
    int   len;
    char *infile;
    char *conn_name;
    int  lineno=0;
    struct connection *c1;

    EF_PROTECT_FREE=1;
    EF_FREE_WIPES  =1;

    progname = argv[0];

    if(argc != 3) {
	fprintf(stderr, "Usage: %s <whackrecord> <conn-name>\n", progname);
	exit(10);
    }
    /* argv[1] == "-r" */

    tool_init_log();
    
    infile = argv[1];
    conn_name = argv[2];

    readwhackmsg(infile);
 
    c1 = con_by_name(conn_name, TRUE);

    ipsecdoi_initiate(/* whack-sock=stdout */1
		      , c1
		      , c1->policy
		      , 0
		      , FALSE
		      , pcim_demand_crypto);

    report_leaks();

    tool_close_log();
    exit(0);
}


/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make parentI1"
 * End:
 */
