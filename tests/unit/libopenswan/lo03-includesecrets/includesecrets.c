#define DEBUG
#include <stdlib.h>
#include "openswan.h"
#include "openswan/passert.h"
#include "constants.h"
#include "oswalloc.h"
#include "oswlog.h"
#include "secrets.h"
#include "id.h"
#include "pluto/keys.h"
#include "hexdump.c"

const char *progname;

struct prng not_very_random;

void exit_tool(int stat)
{
    exit(stat);
}

int count_secrets(struct secret *secret,
                  struct private_key_stuff *pks,
                  void *uservoid)
{
    int *pcount = (int *)uservoid;
    (*pcount)++;

    return 1;
}

void load_secrets(void)
{
    struct secret *secrets = NULL;
    int count;

    osw_load_preshared_secrets(&secrets, TRUE, "key-2048.secrets", NULL);
    assert(secrets != NULL);
    count = 0;
    osw_foreach_secret(secrets, count_secrets, &count);
    assert(count == 2);
}

int main(int argc, char *argv[])
{
    int i;
    struct id one;

    load_oswcrypto();
    prng_init(&not_very_random, "01234567", 8);

    progname = argv[0];

    tool_init_log();

#ifdef HAVE_LIBNSS
    exit(1);
#endif

    set_debugging(DBG_CONTROL|DBG_CRYPT);
    load_secrets();

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
