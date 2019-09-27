/* repeats existing test case */
#include "../lp08-parentR1/parentR1_head.c"
#include "seam_gr_sha1_group14.c"
#include "seam_finish.c"
#include "seam_x509.c"
#include "seam_rsasig.c"
#include "seam_keys.c"
#include "../seam_host_jamesjohnson.c"
#include "ikev2_microcode.h"

#include "seam_rsasig.c"

#define TESTNAME "respondselfR1"

static inline void init_local_interface(void)
{
    init_jamesjohnson_interface();
}


static void init_fake_secrets(void)
{
    struct state_v2_microcode *svm;
    int svm_num;

    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/jj.secrets"
			       , NULL, NULL);

    /* corrupt the microcode table to prevent our ability to
     * respond to INIT messages */
    svm_num=0;
    for(svm = v2_state_microcode_table; svm->state != STATE_IKEv2_ROOF; svm_num++,svm++) {

        if (svm->recv_type != ISAKMP_v2_SA_INIT)
            continue;

        DBG_log("%s() corrupting svm #%u, '%s' recv=0x%x",
                __func__, svm_num, svm->svm_name, svm->recv_type);
        svm->recv_type = 9999;
    }
}
#include "../lp08-parentR1/parentR1_main.c"


 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */


 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
