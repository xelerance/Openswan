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
#include "pluto/virtual.h"

#include "hostpair.h"
