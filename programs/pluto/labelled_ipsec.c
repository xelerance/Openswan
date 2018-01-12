/* Labelled IPsec support
 * Copyright (C) 20??.  By someone at Redhat who cared.
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
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "pluto/connections.h"          /* needs id.h */
#include "pluto/state.h"
#include "packet.h"
#include "keys.h"
#include "secrets.h"
#include "kernel.h"          /* needs connections.h */
#include "log.h"
#include "spdb.h"
#include "whack.h"          /* for RC_LOG_SERIOUS */
#include "pluto/plutoalg.h"

#include "sha1.h"
#include "md5.h"
#include "pluto/crypto.h" /* requires sha1.h and md5.h */

#include "alg_info.h"
#include "kernel_alg.h"
#include "pluto/ike_alg.h"
#include "db_ops.h"

#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

#ifdef HAVE_LABELED_IPSEC
#include "security_selinux.h"
#endif

#ifdef HAVE_LABELED_IPSEC
bool
parse_secctx_attr (pb_stream *pbs, struct state *st)
{
		/*supported length is 256 bytes (257 including \0)*/
		char sec_ctx_value[MAX_SECCTX_LEN];
		u_int8_t  ctx_doi;
		u_int8_t  ctx_alg;
		u_int16_t net_ctx_len, ctx_len;
		int i=0;

		DBG(DBG_PARSING, DBG_log("received sec ctx"));

		/*doing sanity check*/
		if(pbs_left(pbs) < (sizeof(ctx_doi) + sizeof(ctx_alg) + sizeof(ctx_len) + 1) ) {
			DBG(DBG_PARSING, DBG_log("received perhaps corrupted security ctx (should not happen really)"));
			return FALSE;
		}

		/*reading ctx doi*/
		memcpy (&ctx_doi, pbs->cur, sizeof(ctx_doi));
		pbs->cur += sizeof(ctx_doi);

		/*reading ctx alg*/
		memcpy (&ctx_alg, pbs->cur, sizeof(ctx_alg));
		pbs->cur += sizeof(ctx_alg);

		/*reading ctx length*/
		memcpy (&net_ctx_len, pbs->cur, sizeof(ctx_len));
		pbs->cur += sizeof(ctx_len);
		ctx_len = ntohs(net_ctx_len);

		DBG(DBG_PARSING, DBG_log("   received ctx_doi = %d, ctx_alg = %d, ctx_len = %d", ctx_doi , ctx_alg, ctx_len));

		/* verifying remaining buffer length and ctx length matches or not (checking for any corruption)*/
		if(ctx_len != pbs_left(pbs) ) {
			DBG(DBG_PARSING, DBG_log("received ctx length seems to be different than the length of string present in the buffer"));
			DBG(DBG_PARSING, DBG_log("received ctx_len = %d, buffer left = %lu", ctx_len, pbs_left(pbs)));
			return FALSE;
		}

		/* do not process security labels longer than MAX_SECCTX_LEN */
		 if(pbs_left(pbs) > MAX_SECCTX_LEN) {
		    DBG(DBG_PARSING, DBG_log("received security ctx longer than MAX_SECCTX_LEN which is not supported"));
		    return FALSE;
		}

		/* reading security label*/
		memcpy(sec_ctx_value, pbs->cur, pbs_left(pbs));
		i = pbs_left(pbs);

		/*
		 * Checking if the received security label contains \0.
		 * We expect the received label to have '\0', however to be
		 * compliant with implementations that don't send \0
		 * we can add a \0 if there is space left in the buffer.
		 */

		if( sec_ctx_value[i-1] != '\0') {
			/*check if we have space left and then append \0*/
			if (i < MAX_SECCTX_LEN) {
			sec_ctx_value[i] = '\0';
			i=i+1;
			} else {
			/*there is no space left*/
			DBG(DBG_PARSING, DBG_log("received security label > MAX_SECCTX_LEN (should not happen really)"));
			return FALSE;
			}
		}

		/*while (pbs_left(pbs) != 0){
		sec_ctx_value[i++]= *pbs->cur++;
		    if(i == MAX_SECCTX_LEN){
		    DBG(DBG_PARSING, DBG_log("security label reached maximum length (MAX_SECCTX_LEN) allowed"));
		    break;
		    }
		}*/

		//sec_ctx_value[i]='\0';
		DBG(DBG_PARSING, DBG_log("   sec ctx value: %s, len=%d", sec_ctx_value, i));

		if(st->sec_ctx == NULL && st->st_state==STATE_QUICK_R0) {
		    DBG_log("Receievd sec ctx in responder state");
		    st->sec_ctx = alloc_thing(struct xfrm_user_sec_ctx_ike , "struct xfrm_user_sec_ctx_ike");
		    memcpy (st->sec_ctx->sec_ctx_value, sec_ctx_value, i);
		    st->sec_ctx->ctx_len = i;
		    st->sec_ctx->ctx_alg = ctx_alg;
		    st->sec_ctx->ctx_doi = ctx_doi;

	/* lets verify if the received security label is within range of this connection's policy's security label*/
	   if(!st->st_connection->labeled_ipsec) {
		DBG_log("This state (connection) is not labeled ipsec enabled, so can not proceed");
		return FALSE;
	   }
	   else if( st->st_connection->policy_label != NULL && within_range(st->sec_ctx->sec_ctx_value, st->st_connection->policy_label)) {
		DBG_log("security context verification succedded");
	   }
	   else {
		DBG_log("security context verification failed (perhaps policy_label is not confgured for this connection)");
		return FALSE;
	   }

	}
	else if (st->st_state==STATE_QUICK_I1 ) {
	DBG(DBG_PARSING, DBG_log("Initiator state received security context from responder state, now verifying if both are same"));
	   if(!strcmp(st->sec_ctx->sec_ctx_value, sec_ctx_value)) {
		DBG_log("security contexts are verified in the initiator state");
	   }
	   else {
		DBG_log("security context verification failed in the initiator state"
				"(shouldnt reach here unless responder (or something in between) is modifying the security context");
		return FALSE;
	   }
	}
	else if (st->st_state==STATE_QUICK_R0) {
		DBG_log("Receievd sec ctx in responder state again, already stored it so doing nothing now");
	}
	return TRUE;
}
#endif

/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * End:
 */
