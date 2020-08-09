#define OMIT_MAIN_MODE 1
#define NO_SEAM_NATT

#include "../lp02-parentI1/parentI1_head.c"
#include "seam_demux.c"
#include "seam_x509.c"
#include "seam_pending.c"
#include "seam_whack.c"
#include "seam_initiate.c"
#include "seam_dnskey.c"
#include "seam_rsasig.c"
#include "seam_gi_sha256_group14.c"
#include "seam_ikev2_sendI1.c"
#include "seam_finish.c"
#include "seam_ikev1_phase2.c"
#include "seam_ikev1_crypto.c"
#include "seam_rsa_check.c"

#include "seam_host_parker.c"

#define TESTNAME "ikev1cycle"

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

bool no_cr_send = FALSE;

#define INIT_LOADED load_cycle_twice

struct connection *load_cycle_twice(struct connection *c1)
{
    struct state *st = NULL;

    assert(orient(c1, 500));
    show_one_connection(c1, whack_log);

    /* do calculation if not -r for regression */
    st = sendI1(c1, DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE, TRUE);
    st = state_with_serialno(1);

    passert(st != NULL);
    passert(st->st_sadb != NULL);
    //passert(st->st_sadb->parentSA == TRUE);
    passert(st->st_sadb->prop_ctx != NULL);

    passert(st->st_connection == c1);

    do_state_frees();  /* should do nothing */
    passert(st->st_sadb->prop_ctx != NULL);

    delete_connection(c1, TRUE);
    c1 = NULL;
    do_state_frees();  /* should do delete st */
    st = state_with_serialno(1);
    passert(st == NULL);

    if(readwhackmsg("OUTPUT/ikev2client.record.x86_64") == 0) {
        fprintf(stderr, "failed to read whack file: %s\n", "record");
        exit(11);
    }
    c1 = con_by_name("t4901-ikev1", TRUE);
    return c1;
}

#include "../lp02-parentI1/parentI1_main.c"


 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
