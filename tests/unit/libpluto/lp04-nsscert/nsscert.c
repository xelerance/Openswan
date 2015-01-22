#define LEAK_DETECTIVE
#define AGGRESSIVE 1
#define XAUTH 1
#define PRINT_SA_DEBUG 1

#include <stdlib.h>
#include "openswan.h"
#include "openswan/ipsec_policy.h"
#include "oswalloc.h"
#include "constants.h"
#include "certs.h"
#include "oswlog.h"
#include "oswconf.h"
#include "oswtime.h"

#include "../seam_exitlog.c"

char *progname;

/** by default pluto does not check crls dynamically */
long crl_check_interval = 0;
struct pubkey_list *pluto_pubkeys = NULL;
struct secret *pluto_secrets = NULL;

main(int argc, char *argv[])
{
    int i;
    chunk_t blob, crl_uri;
    err_t e;
    cert_t cacert,t1;
    time_t until;

    progname = argv[0];
    leak_detective=1;

    tool_init_log();
    load_oswcrypto();

    set_debugging(DBG_X509);
    set_fake_x509_time(1421896274);  /* Wed Jan 21 22:11:14 2015 */

    /* load CAcert */
    if(!load_cert(CERT_NONE, argv[1], TRUE, "cacert", &cacert)) {
        printf("could not load cert file: %s\n", argv[1]);
        exit(1);
    }
    add_authcert(cacert.u.x509, 0);

    /* load target cert */
    if(!load_cert(CERT_NONE, argv[2], TRUE, "test1", &t1)) {
        printf("could not load cert file: %s\n", argv[1]);
        exit(1);
    }

    time(&until);
    until += 86400;
#if 0
    e=check_validity(t1.u.x509, &until);
    if(e) {
        printf("validity check: %s\n", e);
        exit(2);
    }
#endif
    if(verify_x509cert(t1.u.x509, TRUE, &until)) {
        printf("verify x509 failed\n");
        exit(3);
    }

    printf("cert is valid\n");

    free_x509cert(t1.u.x509);
    free_x509cert(cacert.u.x509);

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
