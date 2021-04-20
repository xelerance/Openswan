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

    FILE *fin = fopen("wm04.bin", "rb");
    if(fin==NULL) { perror("wm04"); exit(4); }
    insize = fread(wm_buf, 1, sizeof(wm_buf), fin);

    /* */
    memset(&wm1, 0, sizeof(wm1));

    /* should complain about missing magic tag */
    size_t insize2 = insize-12;
    err = whack_cbor_decode_msg(&wm1, wm_buf+12, &insize2);
    passert(err != NULL);

    err = whack_cbor_decode_msg(&wm1, wm_buf, &insize);
    if(err) { printf("decode error: %s\n", err); exit(4); }

    /* encode it again, and write it out */
    chunk_t wmchunk = { wm_buf, sizeof(wm_buf) };
    err = whack_cbor_encode_msg(&wm1, &wmchunk );
    if(err) { printf("recode: error: %s\n", err); exit(5); }

    FILE *omsg = fopen("OUTPUT/wm05o.bin", "wb");
    if(omsg == NULL) { perror("output"); exit(4); }
    fwrite(wmchunk.ptr, wmchunk.len, 1, omsg);
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
