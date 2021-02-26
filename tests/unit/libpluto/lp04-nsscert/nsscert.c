#define LEAK_DETECTIVE
#define AGGRESSIVE 1
#define XAUTH 1
#define PRINT_SA_DEBUG 1

#include <stdlib.h>
#include "openswan.h"
#include "openswan/ipsec_policy.h"
#include "oswalloc.h"
#include "constants.h"
#include "pluto/keys.h"
#include "certs.h"
#include "oswlog.h"
#include "oswconf.h"
#include "oswtime.h"
#include "oswcrypto.h"

#include "../seam_exitlog.c"

const char *progname;

/** by default pluto does not check crls dynamically */
long crl_check_interval = 0;
struct pubkey_list *pluto_pubkeys = NULL;
struct secret *pluto_secrets = NULL;
extern int EF_DISABLE_BANNER;

int main(int argc, char *argv[])
{
    cert_t cacert,t1;
    time_t until;

    /* sadly, this is actually too late */
#ifdef HAVE_EFENCE
    EF_DISABLE_BANNER = 1;
#endif
    progname = argv[0];
    leak_detective=1;

    tool_init_log();
    load_oswcrypto();

    set_debugging(DBG_X509|DBG_PARSING|DBG_CONTROL);
    until =1421896274;
    set_fake_x509_time(until);  /* Wed Jan 21 22:11:14 2015 */

#ifdef HAVE_LIBNSS
    {
	SECStatus nss_init_status= NSS_InitReadWrite("nss.d");
	if (nss_init_status != SECSuccess) {
	    fprintf(stderr, "NSS initialization failed (err %d)\n", PR_GetError());
            exit(10);
	} else {
	    printf("NSS Initialized\n");
	    PK11_SetPasswordFunc(getNSSPassword);
        }
    }
#endif

    if(argc < 3) {
        fprintf(stderr, "Usage: nsscert CAcertfile.pem cert1.pem cert2.pem...\n");
        exit(5);
    }

    /* skip argv0 */
    argc--;
    argv++;

    /* load CAcert */
    if(!load_cert(CERT_NONE, argv[0], TRUE, "cacert", &cacert)) {
        printf("could not load CA cert file: %s\n", argv[0]);
        exit(1);
    }
    add_authcert(cacert.u.x509, AUTH_CA);

    argc--;
    argv++;

    while(argc-- > 0) {
        char *file = *argv++;
        /* load target cert */
        if(!load_cert(CERT_NONE, file, TRUE, "test1", &t1)) {
            printf("could not load cert file: %s\n", file);
            exit(1);
        }


        until += 86400;
        if(verify_x509cert(t1.u.x509, FALSE, &until) == FALSE) {
            printf("verify x509 failed\n");
            exit(3);
        }
        printf("cert: %s is valid\n", file);
        free_x509cert(t1.u.x509);
    }
    free_x509cert(cacert.u.x509);

    tool_close_log();
    report_leaks();
    exit(0);
}

/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * End:
 */
