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
#include "seam_log.c"
#include "seam_state.c"
#include "seam_initiate.c"
#include "seam_xauth.c"
#include "seam_alg.c"

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

    report_leaks();

    tool_close_log();
    exit(0);
}


/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make whackmsgtest"
 * End:
 */
