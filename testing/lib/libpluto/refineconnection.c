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
#include "rcv_whack.h"

#include "../../programs/pluto/connections.c"

#include "whackmsgtestlib.c"
#include "seam_timer.c"
#include "seam_ipsecdoi.c"
#include "seam_pending.c"
#include "seam_crypt.c"
#include "seam_kernel.c"
#include "seam_rnd.c"

main(int argc, char *argv[])
{
    int   len;
    char *infile;

    EF_PROTECT_FREE=1;
    EF_FREE_WIPES  =1;

    progname = argv[0];

    if(argc > 2 ) {
	fprintf(stderr, "Usage: %s <whackrecord>\n", progname);
	    exit(10);
    }
    /* argv[1] == "-r" */

    tool_init_log();
    
    infile = argv[1];

    readwhackmsg(infile);

    {
	struct state *st1 = new_state();
	struct connection *nc;
	struct id peer_id;

	/* set it to the first connection, there may be only one?? */
	st1->st_connection = connections;
	st1->st_oakley.auth = OAKLEY_RSA_SIG;

	atoid("@west", &peer_id, TRUE);
	
	nc = refine_host_connection(st1, &peer_id, FALSE, FALSE);
	
	printf("new name: %s\n", nc ? nc->name : "<none>");
    }

    report_leaks();

    tool_close_log();
    exit(0);
}


/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make refineconnection"
 * End:
 */
