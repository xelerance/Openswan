#define LEAK_DETECTIVE
#define AGGRESSIVE 1
#define XAUTH 1
#define PRINT_SA_DEBUG 1
#include <stdlib.h>

#include "constants.h"
#include "oswlog.h"
#include "oswalloc.h"
#include "pluto/defs.h"
#include "state.h"
#include "pluto/db2_ops.h"

const char *progname;

void exit_tool(int stat)
{
    exit(stat);
}

int main(int argc, char *argv[])
{
    int i;
    struct db2_context *dc2;
    struct db_sa *sa1 = NULL;
    struct db_sa *sa2 = NULL;
    struct alg_info *defaults;
    struct alg_info_ike *ai;

    progname = argv[0];
    leak_detective=1;

    tool_init_log();

    /* validate we can destroy NULL */
    db2_destroy(NULL);
    db2_print(NULL);

    /* allocate a context */
    dc2 = db2_prop_new(10, 10, 10);

    /* destroy it! */
    db2_destroy(dc2);
    db2_print(dc2);

    /* free it! */
    db2_free(dc2);

    /* make a new one again */
    dc2 = db2_prop_new(10, 10, 11);

    /* leak the above item! */
    dc2 = db2_prop_new(10, 10, 12);

    /* now add some stuff to it! */
    db2_prop_add(dc2, PROTO_ISAKMP, 0);
    db2_trans_add(dc2, IKEv2_TRANS_TYPE_ENCR, IKEv2_ENCR_AES_CBC);

    db2_attr_add(dc2,  IKEv2_KEY_LENGTH, 128);
    db2_trans_add(dc2, IKEv2_TRANS_TYPE_INTEG, IKEv2_AUTH_HMAC_SHA1_96);
    db2_trans_add(dc2, IKEv2_TRANS_TYPE_PRF,   IKEv2_PRF_HMAC_SHA1);
    db2_trans_add(dc2, IKEv2_TRANS_TYPE_DH,    OAKLEY_GROUP_MODP2048);

    db2_trans_add(dc2, IKEv2_TRANS_TYPE_ENCR, IKEv2_ENCR_AES_CTR);
    db2_attr_add(dc2,  IKEv2_KEY_LENGTH, 256);

    db2_trans_add(dc2, IKEv2_TRANS_TYPE_INTEG, IKEv2_AUTH_AES_XCBC_96);
    db2_print(dc2);

    /* second proposal */
    db2_prop_add(dc2, PROTO_ISAKMP, 0);
    db2_trans_add(dc2, IKEv2_TRANS_TYPE_ENCR, IKEv2_ENCR_AES_GCM_8);
    db2_attr_add(dc2,  IKEv2_KEY_LENGTH, 128);
    db2_trans_add(dc2, IKEv2_TRANS_TYPE_ENCR, IKEv2_ENCR_AES_GCM_12);
    db2_attr_add(dc2,  IKEv2_KEY_LENGTH, 256);
    db2_trans_add(dc2, IKEv2_TRANS_TYPE_PRF,   IKEv2_PRF_HMAC_SHA2_256);
    db2_trans_add(dc2, IKEv2_TRANS_TYPE_INTEG, IKEv2_AUTH_AES_128_GMAC);
    db2_trans_add(dc2, IKEv2_TRANS_TYPE_DH,    OAKLEY_GROUP_MODP3072);

    db2_prop_close(dc2);

    db2_print(dc2);
    db2_free(dc2);

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
