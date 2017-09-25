<<<<<<< HEAD
#include "ike2opstest_head.c"
#include "../seam_crypto_desc.c"
#include "../seam_crypto.c"
#include "ike2opstest_main.c"
=======
#define LEAK_DETECTIVE
#define AGGRESSIVE 1
#define XAUTH 1
#define PRINT_SA_DEBUG 1
#include <stdlib.h>

#include "constants.h"
#include "oswalloc.h"
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
    struct alg_info *ai;
    const char *ikepolicy;

    progname = argv[0];
    leak_detective=1;

    tool_init_log();

    ikepolicy="aes128-sha1-prfsha1-modp2048";
    printf("for input ike=%s", ikepolicy);
    ai = (struct alg_info *)alg_info_ike_create_from_str(ikepolicy, &e);

    if(e) {
        printf("failed to parse %s: %s\n", ikepolicy, e);
        exit(10);
    }
    passert(ai != NULL);

    dc = alginfo2db2(ai);

    db2_print(dc);
    db2_free(dc);

    ikepolicy="aes128-sha1-sha1-modp2048";
    printf("for input ike=%s", ikepolicy);
    ai = (struct alg_info *)alg_info_ike_create_from_str(ikepolicy, &e);

    if(e) {
        printf("failed to parse %s: %s\n", ikepolicy, e);
        exit(10);
    }
    passert(ai != NULL);

    dc = alginfo2db2(ai);

    db2_print(dc);
    db2_free(dc);

    /* now do the defaults */
    printf("IKEv2 defaults\n");
    ai = alg_info_ike_defaults();

    if(e) {
        printf("failed to parse %s: %s\n", ikepolicy, e);
        exit(10);
    }
    passert(ai != NULL);

    sadb = alginfo2db2(ai);

    sa_v2_print(sadb);
    db2_free(dc);


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
