#define LEAK_DETECTIVE
#define AGGRESSIVE 1
#define XAUTH
#define MODECFG
#define DEBUG 1
#define PRINT_SA_DEBUG 1
#define USE_KEYRR 1

#include <stdlib.h>
#include "constants.h"
#include "oswalloc.h"
#include "oswconf.h"
#include "oswcrypto.h"
#include "whack.h"
#include "../../programs/pluto/rcv_whack.h"

#include "sysdep.h"
#include "oswtime.h"
#include "id.h"
#include "pluto/x509lists.h"
#include "certs.h"
#include "secrets.h"

#include "pluto/defs.h"
#include "ac.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "pluto/connections.h"	/* needs id.h */
#include "pending.h"
#include "foodgroups.h"
#include "packet.h"
#include "demux.h"	/* needs packet.h */
#include "state.h"
#include "timer.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "pluto/server.h"
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "pluto/keys.h"
#include "adns.h"	/* needs <resolv.h> */
#include "dnskey.h"	/* needs keys.h and adns.h */
#include "whack.h"
#include "alg_info.h"
#include "spdb.h"
#include "ike_alg.h"
#include "plutocerts.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "xauth.h"
#include "pluto/libpluto.h"
#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

#include "pluto/virtual.h"

#include "hostpair.h"

#include "whackmsgtestlib.c"
#include "seam_debug.c"
#include "seam_timer.c"
#include "seam_fakevendor.c"
#include "seam_ikev1.c"
#include "seam_crypt.c"
#include "seam_kernel.c"
#include "seam_rnd.c"
#include "seam_log.c"
#include "seam_xauth.c"
#include "seam_terminate.c"
#ifndef OMIT_MAIN_MODE
#include "seam_spdbstruct.c"
#endif
#include "seam_exitlog.c"
#include "seam_natt.c"

#include "seam_rsasig.c"

u_int8_t reply_buffer[MAX_OUTPUT_UDP_SIZE];


 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
