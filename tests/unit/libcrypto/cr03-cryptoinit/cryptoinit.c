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
#include "pluto/crypto.h"
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
    init_crypto();

    tool_close_log();

    report_leaks();
    exit(0);
}

/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * End:
 */
