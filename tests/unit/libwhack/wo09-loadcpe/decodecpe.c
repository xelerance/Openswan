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

    if(argc != 2) {
	fprintf(stderr, "Usage: %s whackfile \n", progname);
	exit(10);
    }
    tool_init_log();

    FILE *fin = fopen(argv[1], "rb");
    if(fin==NULL) { perror(argv[1]); exit(4); }
    insize = fread(wm_buf, 1, sizeof(wm_buf), fin);

    err = whack_cbor_decode_msg(&wm1, wm_buf, &insize);
    if(err) { printf("decode error: %s\n", err); exit(4); }

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
