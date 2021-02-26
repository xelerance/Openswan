#include <stdlib.h>
#include "constants.h"
#include "oswlog.h"
#include "oswalloc.h"
#include "whack.h"
#include "pluto/opts.h"

#include "seam_exitlog.c"

const char *progname=NULL;
int verbose=0;
int warningsarefatal = 0;

int main(int argc, char *argv[])
{
    err_t err = NULL;
    chunk_t cborout;
    char  wm_buf[4096];

    progname = argv[0];
    argv++;
    argc--;
    leak_detective = 1;

    tool_init_log();

    /* First argument is the output file. The rest is fed to pluto_options_process */

    FILE *omsg = fopen(argv[0], "wb");
    argv++;
    argc--;

    cborout.ptr = wm_buf;
    cborout.len = sizeof(wm_buf);

    err = pluto_options_process(argc, argv, &cborout);
    if(err) {
        fprintf(stderr, "error: %s\n", err);
        exit(3);
    }

    if(omsg == NULL) { perror("output"); exit(4); }
    fwrite(cborout.ptr, cborout.len, 1, omsg);
    fclose(omsg);

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
