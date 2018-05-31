#include "../lp13-parentI3/parentI3_head.c"
#include "seam_gi_sha1.c"
#include "seam_gi_sha1_group14.c"
#include "seam_finish.c"
#include "seam_ikev2_sendI1.c"

static void init_loaded(void)
{   /* nothing */ }

#define TESTNAME "rekeyikev2"
#define AFTER_CONN rekeyit

#include "../lp46-rekeyikev2-I1/rekeyit.c"
#include "../lp13-parentI3/parentI3_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
