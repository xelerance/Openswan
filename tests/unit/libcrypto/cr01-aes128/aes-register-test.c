#define LEAK_DETECTIVE
#define AGGRESSIVE 1
#define XAUTH 1
#define PRINT_SA_DEBUG 1
#define DEBUG 1
#include <stdlib.h>

#ifndef TESTKEY
#define TESTKEY "thisthisthisthis";
#define TESTKEYLEN 16
#endif

#include "constants.h"
#include "hexdump.c"
#include "oswalloc.h"
#include "oswlog.h"
#include "ike_alg.h"

const char *progname;

void exit_tool(int stat)
{
    exit(stat);
}

extern int ike_alg_aes_init(void);

int main(int argc, char *argv[])
{
    int i;
    err_t e = NULL;
    const struct ike_encr_desc *aes;
    char  inbuf[256];
    char  outbuf[256];
    char  keybuf[TESTKEYLEN] = TESTKEY;
    char  ivbuf[AES_CBC_BLOCK_SIZE];

    progname = argv[0];
    leak_detective=1;
    tool_init_log();

    /* register it! */
    ike_alg_aes_init();

    passert(ike_alg_enc_present(IKEv2_ENCR_AES_CBC, 128));
    passert(ike_alg_enc_present(IKEv2_ENCR_AES_CBC, 256));

    aes = ike_alg_get_encr(IKEv2_ENCR_AES_CBC);

    /* initialize the sample */
    for(i=0; i<sizeof(inbuf); i++) {
        inbuf[i] = i&0xff;
    }
    /* initialize the IV */
    for(i=0; i<sizeof(ivbuf); i++) {
        ivbuf[i] = i&0xff;
    }
    memcpy(outbuf, inbuf, sizeof(outbuf));

    printf("plaintext input:\n");
    hexdump(stdout, outbuf, 0, sizeof(outbuf));

    /* now encrypt! */
    aes->do_crypt(outbuf, sizeof(outbuf),
                  keybuf, sizeof(keybuf),
                  ivbuf, TRUE);

    printf("ciphertext output:\n");
    hexdump(stdout, outbuf, 0, sizeof(outbuf));

    /* reset the IV */
    for(i=0; i<sizeof(ivbuf); i++) {
        ivbuf[i] = i&0xff;
    }
    /* now decrypt! */
    aes->do_crypt(outbuf, sizeof(outbuf),
                  keybuf, sizeof(keybuf),
                  ivbuf, FALSE);


    printf("plaintext output: %s\n",
           memcmp(inbuf, outbuf, sizeof(outbuf))==0 ? "matches" : "failed");
    hexdump(stdout, outbuf, 0, sizeof(outbuf));

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
