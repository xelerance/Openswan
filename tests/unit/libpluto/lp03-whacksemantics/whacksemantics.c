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
#include "seam_vendor.c"
#include "seam_pending.c"
#include "seam_ikev1.c"
#include "seam_crypt.c"
#include "seam_kernel.c"
#include "seam_rnd.c"
#include "seam_log.c"
#include "seam_xauth.c"
#include "seam_west.c"
#include "seam_initiate.c"
#include "seam_terminate.c"
#include "seam_x509.c"
#include "seam_spdbstruct.c"
#include "seam_demux.c"
#include "seam_whack.c"
#include "seam_keys.c"
#include "seam_exitlog.c"
#include "seam_natt.c"

u_int8_t reply_buffer[MAX_OUTPUT_UDP_SIZE];

#include "seam_gi_sha1.c"

#include "ikev2sendI1.c"

main(int argc, char *argv[])
{
    int   len;
    char *infile;
    char *conn_name;
    int  lineno=0;
    struct connection *c1;
    struct state *st;

    EF_PROTECT_FREE=1;
    EF_FREE_WIPES  =1;

    progname = argv[0];
    leak_detective = 1;

    if(argc != 4) {
	fprintf(stderr, "Usage: %s <cfgrootdir> <cfgfile> <conn-name>\n", progname);
	exit(10);
    }
    /* argv[1] == "-r" */

    tool_init_log();
    init_fake_vendorid();

    rootdir2[0]='\0';
    strlcat(rootdir2, argv[1], sizeof(rootdir2));

    starter_use_log (verbose, 1, verbose ? 0 : 1);
    cfg = confread_load(argv[2], &err, FALSE, NULL,FALSE);
    conn_name = argv[3];

    /* load all conns marked as auto=add or better */
    for(conn = cfg->conns.tqh_first;
	conn != NULL;
	conn = conn->link.tqe_next)
    {
        if(strcasecmp(conn->name, conn_name)==0) {
        }
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
