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
#include "seam_fakevendor.c"
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
#include "seam_keys.c"
#include "seam_initiate.c"
#include "seam_demux.c"
#include "seam_spdbstruct.c"
#include "seam_gi_sha1.c"
#include "seam_finish.c"
#include "seam_natt.c"


u_int8_t reply_buffer[MAX_OUTPUT_UDP_SIZE];


#include "seam_iflist.c"

/* include directly to get static functions */
#include "../../../../lib/libpluto/orient.c"

#define TESTNAME "bestif"

struct iface_dev  parker_ifd1 = {
	.id_count = 1,
	.id_vname = "ipsec0",
	.id_rname = "eth0"
};

struct iface_port parker_if1 = {
	.ip_dev = &parker_ifd1,
	.port   = 500,
        .socktypename = "AF_INET",
	.ip_addr.u.v4.sin_family = AF_INET,
	.ip_addr.u.v4.sin_addr.s_addr = 0xc0a80101, /* 192.168.1.1 -- see htonl() below */
	.fd     = -1,
	.next   = NULL,
	.ike_float = 0,
	.change    = IFN_KEEP
};

struct iface_port parker_if1b = {
	.ip_dev = &parker_ifd1,
	.port   = 4500,
	.ip_addr.u.v4.sin_family = AF_INET,
	.ip_addr.u.v4.sin_addr.s_addr = 0xc0a80101, /* 192.168.1.1 -- see htonl() below */
	.fd     = -1,
	.next   = NULL,
	.ike_float = 0,
	.change    = IFN_KEEP
};

struct iface_port parker_if2 = {
	.ip_dev = &parker_ifd1,
	.port   = 500,
	.ip_addr.u.v6.sin6_family = AF_INET6,
        /* filled in below */
	.fd     = -1,
	.next   = NULL,
	.ike_float = 0,
	.change    = IFN_KEEP
};


int main(int argc, char *argv[])
{
    int   len;
    char *infile;
    char *conn_name;
    int  lineno=0;
    struct connection *c1;
    struct state *st;
    struct iface_port *best1;
    struct spd_route sr1;


#ifdef HAVE_EFENCE
    EF_PROTECT_FREE=1;
#endif

    progname = argv[0];
    leak_detective = 1;

    tool_init_log();
    init_fake_vendorid();
    init_gatefun_interface();

    /* skip argv0 */
    argc--;
    argv++;

    sr1.this.host_addr.u.v6.sin6_port = 500;
    sr1.that.host_addr.u.v4.sin_port = 500;

    best1 = pick_matching_interfacebyfamily(interfaces,
                                            500,
                                            AF_INET,
                                            &sr1);

    printf("best: %s %s\n", best1->ip_dev->id_vname, best1->ip_dev->id_rname);

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
