#define DEBUG
#define USE_KEYRR
#include <stdlib.h>
#include "openswan.h"
#include "openswan/passert.h"
#include "constants.h"
#include "pluto/defs.h"
#include "oswalloc.h"
#include "oswlog.h"
#include "oswcrypto.h"
#include "secrets.h"
#include "id.h"
#include "pluto/keys.h"
#include "hexdump.c"
#include "alg_info.h"
#include "pluto/db_ops.h"
#include "pluto/db2_ops.h"
#include "pluto/crypto.h"
#include "seam_kernel.c"
#include "seam_keys.c"
#include "seam_ipcomp.c"

const char *progname;

void exit_tool(int stat)
{
    exit(stat);
}

int main(int argc, char *argv[])
{
    int i;
    struct id one;
    struct alg_info_ike *ei;
    struct db_sa *sadb = NULL;
    char info_buf[1024];

    tool_init_log();
    init_crypto();
    load_oswcrypto();

    progname = argv[0];
    cur_debugging = DBG_EMITTING;

    zero(info_buf);
    ei = alg_info_ike_defaults();
    alg_info_snprint_ike(info_buf, sizeof(info_buf), ei);
    DBG_log("EI starts with: %s", info_buf);

    sadb = alginfo2parent_db2(ei);

    DBG_log("IKEv2 outsa starts ");
    sa_v2_print(sadb);

    passert(extrapolate_v1_from_v2(sadb, LEMPTY, INITIATOR) == TRUE);
    DBG_log("IKEv1 outsa is now ");
    sa_print(sadb);

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
