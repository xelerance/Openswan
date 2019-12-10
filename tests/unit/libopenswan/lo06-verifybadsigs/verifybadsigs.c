#define DEBUG
#include <stdlib.h>
#include <stddef.h>
#include "openswan.h"
#include "openswan/passert.h"
#include "constants.h"
#include "oswalloc.h"
#include "oswlog.h"
#include "secrets.h"
#include "id.h"
#include "pluto/keys.h"
#include "hexdump.c"
#include "oswcrypto.h"
#include "mpzfuncs.h"

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

static void hack_zero_first_pad_byte(u_char *sig_val, size_t sig_len)
{
    u_char *p = sig_val;
    //u_char *end = sig_val + sig_len;

    assert(p[0] == 0x00);
    assert(p[1] == 0x01);
    assert(p[2] == 0xFF);

    p[2] = 0;
}

static void hack_zero_last_pad_byte(u_char *sig_val, size_t sig_len)
{
    u_char *p = sig_val;
    u_char *end = sig_val + sig_len;

    assert(p[0] == 0x00);
    assert(p[1] == 0x01);
    assert(p[2] == 0xFF);

    for (p+=2; *p==0xFF; p++);

    assert(p<end);
    assert(p[-1] == 0xFF);
    assert(p[0] == 0x00);

    p[-1] = 0;
}

static void hack_zero_all_pad_bytes(u_char *sig_val, size_t sig_len)
{
    u_char *p = sig_val;
    u_char *end = sig_val + sig_len;

    assert(p[0] == 0x00);
    assert(p[1] == 0x01);
    assert(p[2] == 0xFF);

    for (p+=2; *p==0xFF; p++) *p = 0;

    assert(p<end);
    assert(p[0] == 0x00);
}

static void hack_remove_pad_add_trailing(u_char *sig_val, size_t sig_len)
{
    u_char *p = sig_val, *s;
    u_char *end = sig_val + sig_len;
    ssize_t rest, padlen;

    assert(p[0] == 0x00);
    assert(p[1] == 0x01);
    assert(p[2] == 0xFF);

    for (p+=2, s=p; *p==0xFF; p++);

    assert(p<end);
    assert(s[0] == 0xFF);       // s is the first byte of padding
    assert(p[-1] == 0xFF);      // p-1 is last byte of padding
    assert(p[0] == 0x00);       // p is the first byte after padding

    rest = end-p;
    padlen = p-s;

    if (padlen>8) {
        memmove(s+1, p-1, rest+1);      // keep 2 bytes of pad, shift rest down
        memset(s+rest+2, 0xFF, padlen); // fill end with 0xFFs
    }
}

struct hack {
	const char *name;
	void (*corrupt)(u_char *sig_val, size_t sig_len);
        int expected_error;
} hacks[] = {
	{ "zero-first-pad-byte",     hack_zero_first_pad_byte,     4 },
	{ "zero-last-pad-byte",      hack_zero_last_pad_byte,      4 },
	{ "zero-all-pad-bytes",      hack_zero_all_pad_bytes,      4 },
        { "remove-pad-add-trailing", hack_remove_pad_add_trailing, 3 },
	{ NULL }
};

/* copied from lib/liboswkeys/signatures.c
 * modified to create a corrupted signature using the hack structure */
static void sign_hash_hack(struct hack *hack
			   , const struct private_key_stuff *pks
			   , const u_char *hash_val, size_t hash_len
			   , u_char *sig_val, size_t sig_len)
{
    chunk_t ch;
    mpz_t t1;
    size_t padlen;
    u_char *p = sig_val;
    const struct RSA_private_key *k = &pks->u.RSA_private_key;

    DBG(DBG_CONTROL | DBG_CRYPT,
	DBG_log("signing hash with RSA Key *%s", pks->pub->u.rsa.keyid)
        );

    /* PKCS#1 v1.5 8.1 encryption-block formatting */
    *p++ = 0x00;
    *p++ = 0x01;	/* BT (block type) 01 */
    padlen = sig_len - 3 - hash_len;
    memset(p, 0xFF, padlen);
    p += padlen;
    *p++ = 0x00;
    memcpy(p, hash_val, hash_len);
    passert(p + hash_len - sig_val == (ptrdiff_t)sig_len);

/* XXX - hack start {{{ */
    printf("applying signature corruption '%s'\n", hack->name);
#if 0
    printf("before(%lu)...\n", sig_len);
    hexdump(sig_val, 0, sig_len);
#endif
    hack->corrupt(sig_val, sig_len);
#if 0
    printf("after(%lu)...\n", sig_len);
    hexdump(sig_val, 0, sig_len);
    fflush(stdout);
#endif
/* XXX - hack end }}} */

    /* PKCS#1 v1.5 8.2 octet-string-to-integer conversion */
    n_to_mpz(t1, sig_val, sig_len);	/* (could skip leading 0x00) */

    /* PKCS#1 v1.5 8.3 RSA computation y = x^c mod n
     * Better described in PKCS#1 v2.0 5.1 RSADP.
     * There are two methods, depending on the form of the private key.
     * We use the one based on the Chinese Remainder Theorem.
     */
    oswcrypto.rsa_mod_exp_crt(t1, t1, &k->p, &k->dP, &k->q, &k->dQ, &k->qInv);
    /* PKCS#1 v1.5 8.4 integer-to-octet-string conversion */
    ch = mpz_to_n(t1, sig_len);
    memcpy(sig_val, ch.ptr, sig_len);
    pfree(ch.ptr);

    mpz_clear(t1);
}

void verify_sig_key_hack(struct hack *hack, const char *keyfile,
			 unsigned int keysize)
{
    struct secret *secrets = NULL;
    char   thingtosign[64];
    size_t signed_len;
    char   signature_buf[8192];
    int    count;
    struct private_key_stuff *pks1;
    char secretsfile[512];

    printf("-----------------------------------------------\n"
	   ">>> %s(\"%s\", \"%s\", %u)\n",
	   __func__, hack->name, keyfile, keysize);
    fflush(stdout);

    memset(signature_buf, 0, sizeof(signature_buf));
    snprintf(secretsfile, sizeof(secretsfile), "../lo02-verifysigs/key-%s.secrets", keyfile);

    osw_load_preshared_secrets(&secrets, TRUE, secretsfile, NULL, NULL);
    assert(secrets != NULL);
    count = 0;
    osw_foreach_secret(secrets, count_secrets, &count);
    assert(count == 1);
    pks1 = osw_get_pks(secrets);
    assert(pks1->kind == PPK_RSA);
    assert(keysize <= sizeof(signature_buf));

    /* now pick number at pseudo-random */
    memcpy(thingtosign, der_digestinfo, der_digestinfo_len);
    prng_bytes(&not_very_random, thingtosign+der_digestinfo_len, 16);
    signed_len = 16+der_digestinfo_len;
    printf("signed_len: %d\n", (int)signed_len);
    hexdump(stdout, thingtosign, 0, signed_len);
    fflush(stdout);

    sign_hash_hack(hack, pks1, thingtosign, signed_len,
		   signature_buf, keysize);

    printf("signature_buf: %d\n", (int)keysize);
    hexdump(stdout, signature_buf, 0, sizeof(signature_buf));
    fflush(stdout);

    /* now verify the signature using the public key part of this secret */

    {
        u_char s[RSA_MAX_OCTETS];	/* working space for decrypted sig_val */
        u_char *sig = NULL;
        const u_char *sig_val = signature_buf;
        size_t        sig_len = keysize;
        //size_t       hash_len = 16;
        const struct RSA_public_key *k = &pks1->pub->u.rsa;
        err_t err = NULL;
        long num = 0;
        char *end = NULL;

        err = verify_signed_hash(k, s, sizeof(s), &sig, signed_len, sig_val, sig_len);
        assert(err != NULL);

        num = strtol(err, &end, 10);
        assert(end>err);

        printf("verify_signed_hash() returned=%ld, expected=%d\n",
               num, hack->expected_error);
        assert(num == hack->expected_error);

        printf("<<< %s(\"%s\", \"%s\", %u) = (%ld) \"%s\"\n",
               __func__, hack->name, keyfile, keysize, num, err);
    }
}

void verify_sig_key(const char *keyfile, unsigned int keysize)
{
    typeof(*hacks) *hack;
    for (hack=hacks; hack->name; hack++) {
	    verify_sig_key_hack(hack, keyfile, keysize);
    }
}

extern void load_oswcrypto(void);

int main(int argc, char *argv[])
{
    load_oswcrypto();
    prng_init(&not_very_random, "01234567", 8);

    progname = argv[0];

    tool_init_log();

#ifdef HAVE_LIBNSS
    exit(1);
#endif

    set_debugging(DBG_CONTROL|DBG_CRYPT);
    verify_sig_key("0512", 512/8);
    verify_sig_key("1024", 1024/8);
    verify_sig_key("2048", 2048/8);
    verify_sig_key("3072", 3072/8);
    verify_sig_key("4096", 4096/8);
    verify_sig_key("8192", 8192/8);

    printf("tests completed\n");

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
