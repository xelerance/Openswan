#define DEBUG
#include <stdlib.h>
#include "openswan.h"
#include "openswan/passert.h"
#include "constants.h"
#include "oswalloc.h"
#include "oswlog.h"
#include "secrets.h"
#include "id.h"
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

void verify_sig_key(const char *keyfile, unsigned int keysize)
{
    struct secret *secrets = NULL;
    char   thingtosign[16];
    char   signature_buf[8192];
    int    count;
    struct private_key_stuff *pks1;
    char secretsfile[512];

    memset(signature_buf, 0, sizeof(signature_buf));
    snprintf(secretsfile, sizeof(secretsfile), "key-%s.secrets", keyfile);

    osw_load_preshared_secrets(&secrets, TRUE, secretsfile, NULL);
    assert(secrets != NULL);
    count = 0;
    osw_foreach_secret(secrets, count_secrets, &count);
    assert(count == 1);
    pks1 = osw_get_pks(secrets);
    assert(pks1->kind == PPK_RSA);
    assert(keysize <= sizeof(signature_buf));

    /* now pick number at pseudo-random */
    prng_bytes(&not_very_random, thingtosign, 16);
    hexdump(thingtosign, 0, 16);

    /* XXX should also run this with a signature_buf that is TOO SMALL */
    sign_hash(&pks1->u.RSA_private_key, thingtosign, 16,
              signature_buf, keysize);

    hexdump(signature_buf, 0, sizeof(signature_buf));
}

int main(int argc, char *argv[])
{
    int i;
    struct id one;

    load_oswcrypto();
    prng_init(&not_very_random, "01234567", 8);

    progname = argv[0];

    tool_init_log();

    set_debugging(DBG_CONTROL);
    verify_sig_key("0512", 512/8);

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
