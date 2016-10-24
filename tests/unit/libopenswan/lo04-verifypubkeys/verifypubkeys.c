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

void verify_signature(unsigned int keysize_bits,
                      const struct RSA_public_key *pubkey)
{
    size_t signed_len;
    char   signature_buf[8192];
    char   sig_buf_name[512];
    unsigned int keysize = keysize_bits / 8;

    FILE *infile;
    snprintf(sig_buf_name, sizeof(sig_buf_name), "sig-%04d.bin", keysize_bits);
    infile = fopen(sig_buf_name, "rb");
    if(!infile) {
        perror(sig_buf_name);
        exit(10);
    }

    if(fread(signature_buf, keysize, 1, infile) != 1) {
        perror("fread");
        exit(21);
    }
    fclose(infile);

    hexdump(signature_buf, 0, keysize);
    printf("\n");

    signed_len = 16+der_digestinfo_len;

    /* now verify the signature using the public key part of this secret */
    {
        u_char s[RSA_MAX_OCTETS];	/* working space for decrypted sig_val */
        u_char *sig = NULL;
        const u_char *sig_val = signature_buf;
        size_t        sig_len = keysize;
        size_t       hash_len = 16;
        err_t e = NULL;

        e = verify_signed_hash(pubkey, s, sizeof(s), &sig, signed_len, sig_val, sig_len);
        if(e) puts(e);
        assert(e == NULL);

        /* 2 verify that the has was done with SHA1 */
        assert(memcmp(der_digestinfo, sig, der_digestinfo_len) ==0);
        sig += der_digestinfo_len;

        DBG(DBG_CRYPT,
            DBG_dump("v2rsa decrypted SIG:", sig, hash_len);
            );
    }
}

int main(int argc, char *argv[])
{
    int i;
    struct id one;
    struct RSA_public_key pubkey;
    chunk_t   pubkey_binary;
    err_t  e;
    FILE *pubkey_file;
    char *pubkey_space = NULL;
    size_t pubkey_space_len;
    char   pubkey_bin_space[65536];
    size_t pubkey_bin_space_len;

    load_oswcrypto();

    progname = argv[0];

    tool_init_log();

#ifdef HAVE_LIBNSS
    exit(1);
#endif

    pubkey_file = fopen("pubkey-0512.pubkey", "r");
    if(!pubkey_file) {
        perror("pubkey-0512");
        exit(12);
    }
    pubkey_space_len = 0;
    if(getline(&pubkey_space, &pubkey_space_len, pubkey_file) < 0) {
        perror("getline");
        exit(13);
    }

    pubkey_space_len = strlen(pubkey_space);
    pubkey_space[pubkey_space_len - 1] = '\0';

    e = ttodatav(pubkey_space, 0, 0,
                pubkey_bin_space, sizeof(pubkey_bin_space), &pubkey_bin_space_len,
                (char *)NULL, (size_t)0, TTODATAV_IGNORESPACE);

    if(e) {
        printf("error: %s decoding base64", e);
        exit(11);
    }

    setchunk(pubkey_binary, pubkey_bin_space, pubkey_bin_space_len);

    /* this decodes the public key from the binary (wire) representation of it */
    e = unpack_RSA_public_key(&pubkey, &pubkey_binary);
    if(e) {
        printf("error: %s decoding public key", e);
        exit(11);
    }

    set_debugging(DBG_CONTROL|DBG_CRYPT);
    verify_signature(512, &pubkey);

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
