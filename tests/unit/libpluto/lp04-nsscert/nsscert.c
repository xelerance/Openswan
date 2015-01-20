#define LEAK_DETECTIVE
#define AGGRESSIVE 1
#define XAUTH 1
#define PRINT_SA_DEBUG 1
#include "../../programs/pluto/crypt_ke.c"

#include "seam_timer.c"
#include "seam_cryptohelper.c"
#include "seam_exitlog.c"
#include "seam_natt.c"
#include "seam_vendor.c"

char *progname;

main(int argc, char *argv[])
{
    int i;
    struct pluto_crypto_req r1;
    zero(&r1);

    progname = argv[0];
    leak_detective=1;

    tool_init_log();

    /* init something with the calculator */
    calc_ke(&r1);

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
