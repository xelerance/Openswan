#include "../lp02-parentI1/parentI1_head.c"
#include "seam_gi_md5.c"
#include "seam_finish.c"
#include "seam_ikev2_sendI1.c"
#include "seam_demux.c"
#include "seam_x509.c"
#include "seam_pending.c"
#include "seam_whack.c"
#include "seam_initiate.c"
#include "seam_dnskey.c"
#include "seam_rsasig.c"

#include "seam_host_parker.c"

#include "h2hI3-statetable.c"

#define TESTNAME "s2sI1"

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

    /* and also for the initial statetable entries */
    h2h_insert_states();
}

static void init_loaded(struct connection *c)
{
    h2h_conn_0.IPhost_pair = c->IPhost_pair;
}
#define INIT_LOADED init_loaded

#include "../lp02-parentI1/parentI1_main.c"


 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
