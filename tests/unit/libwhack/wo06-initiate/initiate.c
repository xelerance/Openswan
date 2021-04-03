#include <stdlib.h>
#include "constants.h"
#include "oswlog.h"
#include "oswalloc.h"
#include "whack.h"

#include "seam_exitlog.c"

const char *progname=NULL;
int verbose=0;
int warningsarefatal = 0;

int main(int argc, char *argv[])
{
    err_t err = NULL;
    char  wm_buf[4096];
    char *conn_name;
    struct whack_message wm1;
    size_t outsize = 0;
    size_t insize;

    progname = argv[0];
    leak_detective = 1;

    if(argc != 1) {
	fprintf(stderr, "Usage: %s .. \n", progname);
	exit(10);
    }
    tool_init_log();

    FILE *fin = fopen("wm04.bin", "rb");
    if(fin==NULL) { perror("wm04"); exit(4); }
    insize = fread(wm_buf, 1, sizeof(wm_buf), fin);

    /* */
    memset(&wm1, 0, sizeof(wm1));

    wm1.magic = WHACK_MAGIC;
    wm1.whack_initiate = TRUE;
    wm1.name_len = 8;
    wm1.name     = "mytunnel";

    outsize = sizeof(wm_buf);
    err_t ugh = whack_cbor_encode_msg(&wm1, wm_buf, &outsize);
    if(ugh) { printf("error: %s\n", ugh); exit(3); }

    FILE *omsg = fopen("OUTPUT/wm06.bin", "wb");
    if(omsg == NULL) { perror("output"); exit(4); }
    fwrite(wm_buf, outsize, 1, omsg);
    fclose(omsg);

    report_leaks();

    tool_close_log();
    exit(0);
}


/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
