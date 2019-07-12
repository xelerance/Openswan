#define DEBUG
#include <stdlib.h>
#include "openswan.h"
#include "openswan/passert.h"
#include "constants.h"
#include "oswalloc.h"
#include "oswlog.h"
#include "oswcrypto.h"
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

    passert(ikev1toikev2integ(OAKLEY_MD5)    == IKEv2_AUTH_HMAC_MD5_96);
    passert(ikev1toikev2integ(OAKLEY_SHA1)   == IKEv2_AUTH_HMAC_SHA1_96);
    passert(ikev1toikev2integ(OAKLEY_SHA2_256) == IKEv2_AUTH_HMAC_SHA2_256_128);
    passert(ikev1toikev2integ(OAKLEY_SHA2_384) == IKEv2_AUTH_HMAC_SHA2_384_192);
    passert(ikev1toikev2integ(OAKLEY_SHA2_512) == IKEv2_AUTH_HMAC_SHA2_512_256);

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
