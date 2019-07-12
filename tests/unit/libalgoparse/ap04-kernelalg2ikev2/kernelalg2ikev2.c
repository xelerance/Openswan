#define DEBUG
#include <stdlib.h>
#include "openswan.h"
#include "openswan/passert.h"
#include "constants.h"
#include "oswalloc.h"
#include "oswlog.h"
#include "oswcrypto.h"
#include "kernel_alg.h"
#include "secrets.h"
#include "id.h"
#include "pluto/keys.h"
#include "hexdump.c"

const char *progname;

void exit_tool(int stat)
{
    exit(stat);
}

int main(int argc, char *argv[])
{
    int i;
    struct id one;

    load_oswcrypto();

    progname = argv[0];

    tool_init_log();

    passert(kernelalg2ikev2(AH_SHA) == IKEv2_AUTH_HMAC_SHA1_96);
    passert(kernelalg2ikev2(AH_SHA2_256) == IKEv2_AUTH_HMAC_SHA2_256_128);

    /* check a value which does not exist */
    passert(kernelalg2ikev2(AH_RIPEMD) == IKEv2_AUTH_NONE);

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
