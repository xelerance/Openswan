#define LEAK_DETECTIVE
#define AGGRESSIVE 1
#define XAUTH 1
#define PRINT_SA_DEBUG 1
#define DEBUG 1
#include <stdlib.h>

#include "constants.h"
#include "hexdump.c"
#include "oswalloc.h"
#include "oswlog.h"
#include "pluto/ike_alg.h"
#include "pluto/crypto.h"

const char *progname;

void exit_tool(int stat)
{
    exit(stat);
}

extern int ike_alg_sha2_init(void);

int main(int argc, char *argv[])
{
    int i;
    err_t e = NULL;
    const struct ike_integ_desc *sha256;
    char  inbuf[256];
    char  outbuf[256];
    char *hash;
    union hash_ctx hc;

    progname = argv[0];
    leak_detective=1;
    tool_init_log();

    /* register it! */
    ike_alg_sha2_init();

    passert(ikev2_alg_integ_present(IKEv2_AUTH_HMAC_SHA2_256_128, 128));

    sha256 = ike_alg_get_integ(IKEv2_AUTH_HMAC_SHA2_256_128);

    /* initialize the sample */
    for(i=0; i<sizeof(inbuf); i++) {
        inbuf[i] = i&0xff;
    }

    printf("plaintext input:\n");
    hexdump(stdout, inbuf, 0, sizeof(outbuf));

    hash = alloc_bytes(sha256->hash_digest_len, "digest output");

    /* now encrypt! */
    sha256->hash_init(&hc);
    sha256->hash_update(&hc, inbuf, 256);
    sha256->hash_update(&hc, inbuf, 256);
    sha256->hash_final(hash, &hc);

    printf("hash output:\n");
    hexdump(stdout, hash, 0, sha256->hash_digest_len);

    pfreeany(hash);

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
