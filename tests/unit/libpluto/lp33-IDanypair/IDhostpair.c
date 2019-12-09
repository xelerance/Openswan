#define LEAK_DETECTIVE
#define AGGRESSIVE 1
#define XAUTH
#define MODECFG
#define DEBUG 1
#define PRINT_SA_DEBUG 1
#define USE_KEYRR 1

#include "constants.h"
#include "oswalloc.h"
#include "oswcrypto.h"
#include "oswconf.h"
#include "whack.h"
#include "../../programs/pluto/rcv_whack.h"

#include "../../programs/pluto/connections.c"

#include "whackmsgtestlib.c"
#include "seam_timer.c"
#include "seam_vendor.c"
#include "seam_fakevendor.c"
#include "seam_pending.c"
#include "seam_initiate.c"
#include "seam_ikev1.c"
#include "seam_crypt.c"
#include "seam_kernel.c"
#include "seam_rnd.c"
#include "seam_log.c"
#include "seam_xauth.c"
#include "seam_terminate.c"
#include "seam_spdbstruct.c"
#include "seam_demux.c"
#include "seam_delete.c"
#include "seam_ipsecdoi.c"
#include "seam_whack.c"
#include "seam_exitlog.c"
#include "seam_natt.c"
#include "seam_dnskey.c"
#include "seam_x509_list.c"
#include "seam_ke.c"

#include "seam_host_jamesjohnson.c"
#define TESTNAME "IDhostpair"

static void init_local_interface(void)
{
    init_jamesjohnson_interface();
}

static void init_fake_secrets(void)
{
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "biggate.secrets"
			       , NULL, NULL);
}

int main(int argc, char *argv[])
{
    char *infile;
    int  regression = 0;

#ifdef HAVE_EFENCE
    EF_PROTECT_FREE=1;
#endif

    progname = argv[0];
    leak_detective = 1;

    if(argc != 3 && argc!=4) {
	fprintf(stderr, "Usage: %s [-r] <whackrecord>\n", progname);
	exit(10);
    }
    /* skip argv0 */
    argc--; argv++;

    if(strcmp(argv[0], "-r")==0) {
        regression = 1;
        argc--; argv++;
    }

    (void)regression;

    tool_init_log();
    load_oswcrypto();
    init_fake_vendorid();
    init_fake_secrets();
    init_local_interface();

    infile = argv[0];

    cur_debugging = DBG_CONTROL|DBG_CONTROLMORE;
    if(readwhackmsg(infile) == 0) exit(11);

    hostpair_list();
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
