#define DEBUG
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include "openswan.h"
#include "openswan/passert.h"
#include "constants.h"
#include "oswalloc.h"
#include "oswlog.h"
#include "secrets.h"
#include "mpzfuncs.h"
#include "id.h"
#include "pluto/keys.h"
#include "hexdump.c"
#include "defs.h"
#include "state.h"
#include "packet.h"

struct spd_route;
struct payload_digest;
#include "ikev2.h"

const char *progname;
struct prng not_very_random;

void whack_log(int mess_no, const char *message, ...)
{
}

void exit_tool(int stat)
{
    exit(stat);
}

int attack(uint8_t low_exponent, size_t modulus_bit_len)
{
    /* this would be our message digest */
    uint8_t helloworldSHA1Bytes[] = {
        0x2A, 0xAE, 0x6C, 0x35, 0xC9, 0x4F, 0xCF, 0xB4, 0x15, 0xDB,
        0xE9, 0x5F, 0x40, 0x8B, 0x9C, 0xE9, 0x1E, 0xE8, 0x46, 0xED
    };

    uint8_t attackBytes[] = {
        /* fake signature for 1024-bit modulus */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4e, 0xe7, 0x01, 0x3b,
        0x05, 0xba, 0x96, 0x90, 0x7a, 0x1f, 0xd0, 0x34, 0x4e, 0x77, 0x75, 0xce, 0x9a, 0x6b, 0x9e, 0xbc,
        0xb8, 0x0e, 0x72, 0x18, 0x1b, 0x48, 0x5e, 0x24, 0x9b, 0x96, 0x52, 0x4e, 0xca, 0xcc, 0xb8, 0x55
    };

    /* if the attk is successful, this should not matter */
    size_t modulus_byte_len = modulus_bit_len/8;
    uint8_t modulusBytes[modulus_byte_len];

    /* choose any 128-byte (1024-bit) modulus */
    prng_bytes(&not_very_random, modulusBytes, modulus_byte_len);
    printf("modulusBytes[%lu]:\n", modulus_byte_len);
    hexdump(stdout, modulusBytes, 0, modulus_byte_len);

    /* low-exponent ... let's say 3 */
    uint8_t pubExpBytes[] = {
        low_exponent
    };
    printf("pubExpBytes[%lu]:\n", sizeof(pubExpBytes));
    hexdump(stdout, pubExpBytes, 0, sizeof(pubExpBytes));

    /* prepare the public key */
    struct pubkey pk;
    pk.u.rsa.k = sizeof(attackBytes);
    n_to_mpz(&(pk.u.rsa.e), pubExpBytes, sizeof(pubExpBytes));
    n_to_mpz(&(pk.u.rsa.n), modulusBytes, sizeof(modulusBytes));

    /* prepare a place holder state */
    struct state st;
    memset(&st, 0, sizeof(struct state));

    pb_stream sig_pbs;
    sig_pbs.cur = attackBytes;
    sig_pbs.roof = attackBytes+sizeof(attackBytes);
    err_t e = NULL;

    e = try_RSA_signature_v2(
                             helloworldSHA1Bytes,            // const u_char hash_val[MAX_DIGEST_LEN]
                             sizeof(helloworldSHA1Bytes),    // size_t hash_len
                             &sig_pbs,                       // const pb_stream *sig_pbs
                             &pk,                            // struct pubkey *kr
                             &st                             // struct state *st
                            );

    printf("try_RSA_signature_v2: %s\n",
           e ? e : "OK");

    int rc = 0;
    if (e)
	    rc = strtoul(e, NULL, 0);

    /* we caught the attack, return success */
    if (rc && rc != ULONG_MAX)
	    return 0;

    printf("ERROR: try_RSA_signature_v2() was fooled by our attack!\n");
    return -1;
}

extern void load_oswcrypto(void);

int main(int argc, char *argv[])
{
    int rc;

    load_oswcrypto();

    progname = argv[0];

    prng_init(&not_very_random, "01234567", 8);

    rc = attack(3, 1024);

    exit(rc);
}

/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * End:
 */
