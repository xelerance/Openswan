/* Security Policy Data Base/structure output 
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>
#include "openswan/pfkeyv2.h"

#include "sysdep.h"
#include "constants.h"
#include "oswlog.h"

#include "defs.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "smartcard.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "connections.h"	/* needs id.h */
#include "state.h"
#include "packet.h"
#include "keys.h"
#include "secrets.h"
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "spdb.h"
#include "whack.h"	/* for RC_LOG_SERIOUS */
#include "plutoalg.h"

#include "sha1.h"
#include "md5.h"
#include "crypto.h" /* requires sha1.h and md5.h */

#include "alg_info.h"
#include "kernel_alg.h"
#include "ike_alg.h"
#include "db_ops.h"
#include "ikev2.h"

#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

#define return_on(var, val) do { var=val;goto return_out; } while(0);

bool
ikev2_out_sa(pb_stream *outs
	     , struct db_sa *sadb UNUSED
	     , struct state *st UNUSED
	     , u_int8_t np)
{
    pb_stream sa_pbs;
    bool ret = FALSE;

    /* SA header out */
    {
	struct ikev2_sa sa;

	memset(&sa, 0, sizeof(sa));
	sa.isasa_np     = np;
	sa.isasa_commit = ISAKMP_PAYLOAD_CRITICAL;
	/* no ipsec_doi on IKEv2 */

	if (!out_struct(&sa, &ikev2_sa_desc, outs, &sa_pbs))
	    return_on(ret, FALSE);
    }

    {
	    struct ikev2_prop p;
	    
	    memset(&p, 0, sizeof(p));

	    p.isap_np = 0;
	    p.isap_length=0;
	    p.isap_propnum = 0;
	    p.isap_protoid = 1;
	    p.isap_spisize = 0;
	    p.isap_numtrans = 1;

	    if (!out_struct(&p, &ikev2_prop_desc, &sa_pbs, NULL))
		    return_on(ret, FALSE);
    }

    close_output_pbs(&sa_pbs);
    ret = TRUE;

return_out:
    return ret;
}


    


