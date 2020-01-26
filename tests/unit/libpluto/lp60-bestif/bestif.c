#define LEAK_DETECTIVE
#define AGGRESSIVE 1
#define XAUTH
#define MODECFG
#define DEBUG 1
#define PRINT_SA_DEBUG 1
#define USE_KEYRR 1

#include "constants.h"
#include "oswalloc.h"
#include "whack.h"
#include "../../programs/pluto/rcv_whack.h"

#include "../../programs/pluto/connections.c"

#include "whackmsgtestlib.c"
#include "seam_timer.c"
#include "seam_pending.c"
#include "seam_ikev1.c"
#include "seam_crypt.c"
#include "seam_kernel.c"
#include "seam_rnd.c"
#include "seam_log.c"
#include "seam_xauth.c"

#include "seam_terminate.c"
#include "seam_x509.c"
#include "seam_whack.c"
#include "seam_dnskey.c"
#include "seam_exitlog.c"
#include "seam_initiate.c"
#include "seam_demux.c"
#include "seam_spdbstruct.c"
#include "seam_gi_sha1.c"
#include "seam_finish.c"
#include "seam_natt.c"
#include "seam_rsasig.c"


u_int8_t reply_buffer[MAX_OUTPUT_UDP_SIZE];


#include "seam_iflist.c"

/* include directly to get static functions */
#include "../../../../lib/libpluto/orient.c"

#define TESTNAME "bestif"

int run_permutted_test(unsigned int numbers[6])
{
    int i = 0;
    struct spd_route sr1;
    struct iface_port *best1;

    sr1.that.host_addr.u.v4.sin_port = 500;
    sr1.that.host_addr.u.v4.sin_family=AF_INET;
    ttoaddr_num("132.213.238.7", 0, AF_INET, &sr1.this.host_addr);
    sr1.this.host_addr.u.v4.sin_port = 500;

    /* generate the permutation desired */
    interfaces = NULL;
    for(i=0; i<6; i++) {
        int selected = numbers[i];
        if(selected > 5) {
            return 1;
        }
        add_if_to_list(ifaces[selected]);
    }

    best1 = pick_matching_interfacebyfamily(interfaces,
                                            500,
                                            AF_INET,
                                            &sr1);

    printf("%d%d%d%d%d%d ", numbers[0],numbers[1],numbers[2],numbers[3],numbers[4],numbers[5]);
    if(best1) {
        printf("bestif: %s\n",    best1->ip_dev->id_rname);
    } else {
        printf("failed to pick\n");
        return 16;
    }

    return 0;
}


int main(int argc, char *argv[])
{
    int  numbers[IFACES_COUNT];
    int exits = 0;

#ifdef HAVE_EFENCE
    EF_PROTECT_FREE=1;
#endif

    progname = argv[0];
    leak_detective = 1;

    /* point stderr at same place as stdout */
    setbuf(stderr, NULL);
    setbuf(stdout, NULL);

    set_debugging(DBG_ALL);

    tool_init_log();
    init_fake_vendorid();

    /* skip argv0 */
    argc--;
    argv++;

    if(argc > 0 ) {
        if(argc == 6) {
            numbers[0] = atoi(argv[0]);
            numbers[1] = atoi(argv[1]);
            numbers[2] = atoi(argv[2]);
            numbers[3] = atoi(argv[3]);
            numbers[4] = atoi(argv[4]);
            numbers[5] = atoi(argv[5]);
            exits = run_permutted_test(numbers);
        }
        exit(exits);
    }

    for(numbers[0] = 0; numbers[0] < IFACES_COUNT; numbers[0]++) {
        for(numbers[1] = 0; numbers[1] < IFACES_COUNT; numbers[1]++) {
            if(numbers[1] == numbers[0]) continue;
            for(numbers[2] = 0; numbers[2] < IFACES_COUNT; numbers[2]++) {
                if(numbers[2] == numbers[0]) continue;
                if(numbers[2] == numbers[1]) continue;
                for(numbers[3] = 0; numbers[3] < IFACES_COUNT; numbers[3]++) {
                    if(numbers[3] == numbers[0]) continue;
                    if(numbers[3] == numbers[1]) continue;
                    if(numbers[3] == numbers[2]) continue;
                    for(numbers[4] = 0; numbers[4] < IFACES_COUNT; numbers[4]++) {
                        if(numbers[4] == numbers[0]) continue;
                        if(numbers[4] == numbers[1]) continue;
                        if(numbers[4] == numbers[2]) continue;
                        if(numbers[4] == numbers[3]) continue;
                        for(numbers[5] = 0; numbers[5] < IFACES_COUNT; numbers[5]++) {
                            if(numbers[5] == numbers[0]) continue;
                            if(numbers[5] == numbers[1]) continue;
                            if(numbers[5] == numbers[2]) continue;
                            if(numbers[5] == numbers[3]) continue;
                            if(numbers[5] == numbers[4]) continue;
                            exits += run_permutted_test(numbers);
                        }
                    }
                }
            }
        }
    }

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
