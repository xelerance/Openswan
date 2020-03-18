#define DEBUG
/* for get_current_dir_name() */
#define _GNU_SOURCE

#include <stdlib.h>
#include <unistd.h>
#include "openswan.h"
#include "openswan/passert.h"
#include "constants.h"
#include "oswalloc.h"
#include "oswcrypto.h"
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

void load_secrets(const char *rootdir)
{
    struct secret *secrets = NULL;
    int count;

    osw_load_preshared_secrets(&secrets, TRUE, "key-2048.secrets", NULL, rootdir);
    assert(secrets != NULL);
    count = 0;
    osw_foreach_secret(secrets, count_secrets, &count);
    assert(count == 2);
}

extern void load_oswcrypto(void);

int main(int argc, char *argv[])
{
    const char *rootdir=get_current_dir_name();

    load_oswcrypto();
    prng_init(&not_very_random, "01234567", 8);

    progname = argv[0];

    if(argc > 1) {
        rootdir = argv[1];
    }

    tool_init_log();

#ifdef HAVE_LIBNSS
    exit(1);
#endif

    set_debugging(DBG_CONTROL|DBG_CRYPT);
    load_secrets(rootdir);

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
