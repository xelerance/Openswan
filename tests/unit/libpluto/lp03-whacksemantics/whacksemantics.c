#define LEAK_DETECTIVE
#define AGGRESSIVE 1
#define XAUTH
#define MODECFG
#define DEBUG 1
#define PRINT_SA_DEBUG 1
#define USE_KEYRR 1

#include <stdlib.h>
#include "efencedef.h"
#include "constants.h"
#include "oswalloc.h"
#include "whack.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/confwrite.h"
#include "ipsecconf/starterlog.h"
#include "ipsecconf/files.h"
#include "ipsecconf/starterwhack.h"

#include "../../programs/pluto/rcv_whack.h"
#include "../../programs/pluto/connections.c"

#include "whackmsgtestlib.c"
#include "seam_timer.c"
#include "seam_crypt.c"
#include "seam_pending.c"
#if 0
#include "seam_ikev1.c"
#include "seam_rnd.c"
#include "seam_vendor.c"
#endif
#include "seam_kernel.c"
#include "seam_log.c"
#include "seam_west.c"
#include "seam_xauth.c"
#include "seam_terminate.c"
#if 0
#include "seam_spdbstruct.c"
#include "seam_demux.c"
#endif
#include "seam_delete.c"
#include "seam_secretday.c"
#include "seam_ipsecdoi.c"
#include "seam_natt.c"
#include "seam_x509.c"
#include "seam_keys.c"
#include "seam_whack.c"
#include "seam_exitlog.c"
#include "seam_dnskey.c"

const char *progname=NULL;
int verbose=0;
int warningsarefatal = 0;

void delete_cryptographic_continuation(struct state *st) {}

int main(int argc, char *argv[])
{
    err_t err = NULL;
    char *conn_name;
    struct starter_config *cfg = NULL;
    struct starter_conn *conn = NULL;
    struct connection *c;

#ifdef HAVE_EFENCE
    EF_PROTECT_FREE=1;
#endif

    progname = argv[0];
    leak_detective = 1;

    if(argc < 4) {
	fprintf(stderr, "Usage: %s <cfgrootdir> <cfgfile> <conn-name>.. \n", progname);
	exit(10);
    }
    /* argv[1] == "-r" */

    tool_init_log();
    //init_fake_vendorid();

    rootdir[0]='\0';
    strlcat(rootdir, argv[1], sizeof(rootdir));

    starter_use_log(1, 1, 1);
    cfg = confread_load(argv[2], &err, FALSE, NULL,FALSE);
    argv+=3;
    argc-=3;

    printf("processing requested conn adds\n");

    /* load all conns marked as auto=add or better */
    for(; argc>0; argc--, argv++) {
	struct whack_message msg1;

	conn_name = *argv;
	printf("%s: was requested\n", conn_name);

	for(conn = cfg->conns.tqh_first;
	    conn != NULL;
	    conn = conn->link.tqe_next)
	{
            if(!strcasecmp(conn->name, conn_name))
		break;
	}

	if (!conn) {
	    printf("%s: was not loaded\n", conn_name);
	    continue;
	}
	printf("%s: was loaded\n", conn_name);

	if(starter_whack_build_basic_conn(cfg, &msg1, conn)==0) {
	    printf("%s: calling add_connection()\n", conn_name);
	    add_connection(&msg1);
	}

	c = con_by_name(conn_name, 0);

	if (!conn) {
	    printf("%s: was not added\n", conn_name);
	    continue;
	}
	printf("%s: was added\n", conn_name);

	printf("%s: policy %s\n", c->name , prettypolicy(c->policy));

    }

    confread_free(cfg);

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
