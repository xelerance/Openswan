#include <stdlib.h>
#include "constants.h"
#include "oswlog.h"
#include "oswalloc.h"
#include "whack.h"

#include "seam_exitlog.c"

const char *progname=NULL;
int verbose=0;
int warningsarefatal = 0;

/* sysdep_*.c */
bool use_interface(const char *rifn) {}

int main(int argc, char *argv[])
{
    err_t err = NULL;
    char  wm_buf[4096];
    char *conn_name;
    struct whack_message wm1;
    size_t insize;

    progname = argv[0];
    leak_detective = 1;

    if(argc != 1) {
	fprintf(stderr, "Usage: %s .. \n", progname);
	exit(10);
    }
    tool_init_log();

    /* */
    memset(&wm1, 0, sizeof(wm1));

    wm1.magic = WHACK_MAGIC;
    wm1.whack_initiate = TRUE;
    wm1.name_len = 8;
    wm1.name     = "mytunnel";

    chunk_t wmchunk = { wm_buf, sizeof(wm_buf) };
    err_t ugh = whack_cbor_encode_msg(&wm1, &wmchunk );
    if(ugh) { printf("error: %s\n", ugh); exit(3); }

    FILE *omsg = fopen("OUTPUT/wm06.bin", "wb");
    if(omsg == NULL) { perror("output"); exit(4); }
    fwrite(wmchunk.ptr, wmchunk.len, 1, omsg);
    fclose(omsg);

    FILE *fin = fopen("OUTPUT/wm06.bin", "rb");
    if(fin==NULL) { perror("wm06"); exit(4); }
    insize = fread(wm_buf, 1, sizeof(wm_buf), fin);

    /* clear it all out */
    memset(&wm1, 0, sizeof(wm1));

    err = whack_cbor_decode_msg(&wm1, wm_buf, &insize);
    passert(err == NULL);

    passert(wm1.whack_initiate == TRUE);

    tool_close_log();

    report_leaks();
    exit(0);
}


/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
