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

void verify_sig_key(const char *keyfile, unsigned int keysize)
{
    struct secret *secrets = NULL;
    char   thingtosign[64];
    size_t signed_len;
    char   signature_buf[8192];
    int    count;
    struct private_key_stuff *pks1;
    char secretsfile[512];

    memset(signature_buf, 0, sizeof(signature_buf));
    snprintf(secretsfile, sizeof(secretsfile), "key-%s.secrets", keyfile);

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

    /* XXX should also run this with a signature_buf that is TOO SMALL */
    sign_hash(pks1, thingtosign, signed_len,
              signature_buf, keysize);

    hexdump(stdout, signature_buf, 0, sizeof(signature_buf));
    {
        char outname[512];
        FILE *outfile;
        snprintf(outname, sizeof(outname), "OUTPUT/sig-%s.bin", keyfile);
        outfile = fopen(outname, "wb");
        if(!outfile) {
            perror(outname);
            exit(10);
        }
        fwrite(signature_buf, keysize, 1, outfile);
        fclose(outfile);
    }
    printf("\n");

    /* now verify the signature using the public key part of this secret */

    {
        u_char s[RSA_MAX_OCTETS];	/* working space for decrypted sig_val */
        u_char *sig = NULL;
        const u_char *sig_val = signature_buf;
        size_t        sig_len = keysize;
        size_t       hash_len = 16;
        const struct RSA_public_key *k = &pks1->pub->u.rsa;
        err_t e = NULL;

        e = verify_signed_hash(k, s, sizeof(s), &sig, signed_len, sig_val, sig_len);
        if(e) puts(e);
        assert(e == NULL);

        /* 2 verify that the has was done with SHA1 */
        assert(memcmp(der_digestinfo, sig, der_digestinfo_len) ==0);
        sig += der_digestinfo_len;


        DBG(DBG_CRYPT,
            DBG_dump("v2rsa decrypted SIG:", sig, hash_len);
            DBG_dump("v2rsa computed hash:", thingtosign+der_digestinfo_len, hash_len);
            );

        assert(memcmp(sig, thingtosign+der_digestinfo_len, hash_len) == 0);
    }

}

extern void load_oswcrypto(void);

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
    verify_sig_key("0512", 512/8);
    verify_sig_key("1024", 1024/8);
    verify_sig_key("2048", 2048/8);
    verify_sig_key("3072", 3072/8);
    verify_sig_key("4096", 4096/8);
    verify_sig_key("8192", 8192/8);

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
