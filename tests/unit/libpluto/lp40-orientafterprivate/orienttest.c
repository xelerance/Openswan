#define LEAK_DETECTIVE
#define AGGRESSIVE 1
#define XAUTH
#define MODECFG
#define DEBUG 1
#define PRINT_SA_DEBUG 1
#define USE_KEYRR 1
#define FIND_ID_EXTENDED_DEBUG 1

#include "constants.h"
#include "oswalloc.h"
#include "oswcrypto.h"
#include "oswconf.h"
#include "whack.h"
#include "../../programs/pluto/rcv_whack.h"

#include "../../programs/pluto/connections.c"
#include "../../programs/pluto/hostpair.c"

#include "whackmsgtestlib.c"
#include "seam_timer.c"
#include "seam_fakevendor.c"
#include "seam_initiate.c"
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
#include "seam_whack.c"
#include "seam_exitlog.c"
#include "seam_dnskey.c"
#include "seam_natt.c"
#include "seam_rsasig.c"

#include "seam_gi_sha1.c"
#include "seam_finish.c"

u_int8_t reply_buffer[MAX_OUTPUT_UDP_SIZE];

int main(int argc, char *argv[])
{
    int   i;
    char *infile;
    char *conn_name;
    struct connection *c1;

#ifdef HAVE_EFENCE
    EF_PROTECT_FREE=1;
#endif

    progname = argv[0];
    leak_detective = 1;

    if(argc < 3) {
	fprintf(stderr, "Usage: %s <whackrecord> <conn-name>\n", progname);
	exit(10);
    }
    /* argv[1] == "-r" */

    tool_init_log();
    init_fake_vendorid();

    argc--;
    argv++;

    infile = *argv;
    if(readwhackmsg(infile) == 0) exit(10);

    argc--;
    argv++;

    for(i=0; i < argc; i++) {
        conn_name = argv[i];
        fprintf(stderr, "processing %s\n", conn_name);
        c1 = con_by_name(conn_name, TRUE);
        show_one_connection(c1, whack_log);
        assert(c1 != NULL);
        assert(orient(c1, pluto_port500) == FALSE);
    }

    hostpair_list();
    init_parker_interface(TRUE);

    {
        prompt_pass_t pass;
        memset(&pass, 0, sizeof(pass));
        osw_init_ipsecdir("../samples/parker");

        osw_load_preshared_secrets(&pluto_secrets
                                   , TRUE
                                   , "../samples/parker.secrets"
                                   , &pass, NULL);
    }
    fprintf(stderr, "listening now\n");
    cur_debugging = DBG_CONTROL|DBG_CONTROLMORE;
    whack_listen();
    hostpair_list();

    for(i=0; i < argc; i++) {
        conn_name = argv[i];
        fprintf(stderr, "re-processing %s\n", conn_name);
        c1 = con_by_name(conn_name, TRUE);
        show_one_connection(c1, whack_log);
        assert(c1 != NULL);
        assert(orient(c1, pluto_port500) == TRUE);
    }
    hostpair_list();

    for(i=0; i < argc; i++) {
        conn_name = argv[i];
        c1 = con_by_name(conn_name, TRUE);
        delete_connection(c1, TRUE);
    }

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
