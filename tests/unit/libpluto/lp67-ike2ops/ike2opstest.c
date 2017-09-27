#define LEAK_DETECTIVE
#define AGGRESSIVE 1
#define XAUTH 1
#define PRINT_SA_DEBUG 1
#include <stdlib.h>

#include "constants.h"
#include "oswalloc.h"
#include "oswlog.h"
#include "pluto/defs.h"
#include "pluto/db2_ops.h"
#include "pluto/state.h"
#include "alg_info.h"

const char *progname;

void exit_tool(int stat)
{
    exit(stat);
}

int main(int argc, char *argv[])
{
    int i;
    err_t e = NULL;
    struct db2_context *dc;
    struct db_sa *sadb;
    struct alg_info *ai;
    const char *ikepolicy;

    progname = argv[0];
    leak_detective=1;

    tool_init_log();

    ikepolicy="aes128-sha1-prfsha1-modp2048";
    DBG_log("for input ike=%s", ikepolicy);
    ai = (struct alg_info *)alg_info_ike_create_from_str(ikepolicy, &e);

    if(e) {
        DBG_log("failed to parse %s: %s\n", ikepolicy, e);
        exit(10);
    }
    passert(ai != NULL);

    sadb = alginfo2db2(ai);
    alg_info_free(ai);

    sa_v2_print(sadb);
    free_sa(sadb);

    ikepolicy="aes128-sha1-sha1-modp2048";
    DBG_log("for input ike=%s", ikepolicy);
    ai = (struct alg_info *)alg_info_ike_create_from_str(ikepolicy, &e);

    if(e) {
        DBG_log("failed to parse %s: %s\n", ikepolicy, e);
        exit(10);
    }
    passert(ai != NULL);

    sadb = alginfo2db2(ai);
    alg_info_free(ai);

    sa_v2_print(sadb);
    free_sa(sadb);

    /* now do the defaults */
    DBG_log("IKEv2 defaults\n");
    ai = alg_info_ike_defaults();

    if(e) {
        DBG_log("failed to parse %s: %s\n", ikepolicy, e);
        exit(10);
    }
    passert(ai != NULL);

    sadb = alginfo2db2(ai);
    alg_info_free(ai);

    sa_v2_print(sadb);
    free_sa(sadb);

    report_leaks();
    tool_close_log();
    exit(0);
}

/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * End:
 */