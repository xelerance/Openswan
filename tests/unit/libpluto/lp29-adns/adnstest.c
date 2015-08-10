#define LEAK_DETECTIVE
#define AGGRESSIVE 1
#define XAUTH
#define MODECFG
#define DEBUG 1
#define PRINT_SA_DEBUG 1
#define USE_KEYRR 1

#include <stdlib.h>
#include <sys/resource.h>
#include <signal.h>
#include <errno.h>
#include "sysdep.h"
#include "efencedef.h"
#include "constants.h"
#include "openswan.h"
#include "oswtime.h"
#include "oswalloc.h"
#include "whack.h"
#include "../../programs/pluto/rcv_whack.h"

#include "dnskey.h"
#include "pluto/defs.h"
#include "demux.h"

/* seams */
#include "whackmsgtestlib.c"
#include "seam_log.c"
#include "seam_whack.c"
#include "seam_exitlog.c"

const char *progname=NULL;
int verbose=0;
int warningsarefatal = 0;

#define TESTNAME "adnstest"

/* perform wait4() on all children */
static void
reapchildren(void)
{
    pid_t child;
    int status;
    struct rusage r;

    errno=0;

    while((child = wait3(&status, WNOHANG, &r)) > 0) {
	/* got a child to reap */
	if(adns_reapchild(child, status)) continue;

	openswan_log("child pid=%d (status=%d) is not my child!", child, status);
    }

    if(child == -1) {
	openswan_log("reapchild failed with errno=%d %s",
		     errno, strerror(errno));
    }
}

static void
childhandler(int sig UNUSED)
{
    reapchildren();
}


main(int argc, char *argv[])
{
    bool  recalculate = FALSE;
    int   len;
    err_t err = NULL;
    char *infile;
    char *conn_name;
    int  lineno=0;
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

    tool_init_log();
    init_adns();

    {
    	int r;
	struct sigaction act;

	act.sa_handler = &childhandler;
	act.sa_flags   = SA_RESTART;
	r = sigaction(SIGCHLD, &act, NULL);
	passert(r == 0);
    }

    /* setup a query */

    while(unsent_ADNS_queries) {
        send_unsent_ADNS_queries();
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


