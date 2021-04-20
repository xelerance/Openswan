#define LEAK_DETECTIVE
#define AGGRESSIVE 1
#define XAUTH
#define MODECFG
#define DEBUG 1
#define PRINT_SA_DEBUG 1
#define USE_KEYRR 1

#include <stdlib.h>
#include <sys/resource.h>
#include <signal.h>
#include <errno.h>
#include <arpa/nameser.h>
#include <poll.h>
#include "sysdep.h"
#include "efencedef.h"
#include "constants.h"
#include "openswan.h"
#include "oswtime.h"
#include "oswalloc.h"
#include "whack.h"

#include "dnskey.h"
#include "pluto/defs.h"
#include "pluto/demux.h"
#include "pluto/log.h"
#include "adns.h"
#include "setproctitle.h"

/* seams */
#include "whackmsgtestlib.c"
#include "seam_log.c"
#include "seam_whack.c"
#include "seam_exitlog.c"
#include "seam_hostpair.c"
#include "seam_adns.c"

const char *progname=NULL;
int verbose=0;
int warningsarefatal = 0;

#define TESTNAME "adnstest"

int main(int argc, char *argv[])
{
    struct addrinfo hints, *result1, *result2;
    unsigned char buffer1[1024];
    unsigned int  buffer1_len = sizeof(buffer1);
    unsigned int  serial_size;
    int i,s;

#ifdef HAVE_EFENCE
    EF_PROTECT_FREE=1;
#endif

    initproctitle(argc, argv);
    progname = argv[0];
    leak_detective = 1;

    tool_init_log();
    cur_debugging |= DBG_DNS;

    zero(&hints);
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
    hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
    hints.ai_protocol = 0;          /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    if(argc==1) {
        printf("usage: %s [name]...\n", progname);
        exit(10);
    }

    for(i=1; i < argc; i++) {
        DBG_log("looking up: %s\n", argv[i]);
        s = getaddrinfo(argv[i], NULL, &hints, &result1);
        if(s!=0) {
            printf("lookup: %s a/aaaa lookup error: %s\n"
                             , argv[i], gai_strerror(s));
            continue;
        }
        /* sort things so they come out consistently */
        result1 = sort_addr_info(result1);
        dump_addr_info(result1);

        /* now serialize it into the buffer */
        serial_size = serialize_addr_info(result1, buffer1, buffer1_len);
        freeaddrinfo(result1);

        DBG_log("serialized size=%u\n", serial_size);
        result2 = deserialize_addr_info(buffer1, serial_size);
        dump_addr_info(result2);

        osw_freeaddrinfo(result2);
    }

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


