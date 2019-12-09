#include "../lp02-parentI1/parentI1_head.c"
#include "seam_gi_sha1.c"
#include "seam_gi_sha1_group14.c"
#include "seam_finish.c"
#include "seam_ikev2_sendI1.c"
#include "seam_pending.c"
#include "seam_whack.c"
#include "seam_initiate.c"
#include "seam_dnskey.c"
#include "seam_x509.c"

#include "seam_demux.c"
#include "seam_rsasig.c"

#define TESTNAME "threeconns"

struct iface_dev  vzhost_ifd1 = {
	.id_count = 1,
	.id_vname = "ipsec0",
	.id_rname = "eth0"
};

struct iface_port vzhost_if1 = {
	.ip_dev = &vzhost_ifd1,
	.port   = 500,
        .socktypename = "AF_INET",
	.ip_addr.u.v4.sin_family = AF_INET,
	.ip_addr.u.v4.sin_addr.s_addr = 0xADE68547, /* 173.230.133.71 -- see htonl() below */
	.fd     = -1,
	.next   = NULL,
	.ike_float = 0,
	.change    = IFN_KEEP
};

static void init_local_interface(void)
{
    vzhost_if1.ip_addr.u.v4.sin_addr.s_addr = htonl(vzhost_if1.ip_addr.u.v4.sin_addr.s_addr);
    vzhost_if1.next = interfaces;
    interfaces = &vzhost_if1;
}

static void init_fake_secrets(void)
{
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/parker.secrets"
			       , NULL, NULL);
}

#define SKIP_ORIENT_ASSERT 1
#define SKIP_INITIATE      1

#include "../lp02-parentI1/parentI1_main.c"


 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
