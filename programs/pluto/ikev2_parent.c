/* 
 * IKEv2 parent SA creation routines
 * Copyright (C) 2007  Michael Richardson <mcr@xelerance.com>
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
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <gmp.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "state.h"
#include "id.h"
#include "connections.h"	

#include "crypto.h" /* requires sha1.h and md5.h */

#include "ike_alg.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "pluto_crypt.h"
#include "packet.h"
#include "ikev2.h"
#include "demux.h"
#include "log.h"
#include "spdb.h"          /* for out_sa */
#include "ipsec_doi.h"
#include "vendor.h"
#include "timer.h"

#include "tpm/tpm.h"

/* Initiate an Oakley Main Mode exchange.
 *       HDR, SAi1, KEi, Ni   -->
 *
 * Note: this is not called from demux.c, but from ipsecdoi_initiate().
 *
 */
stf_status
ikev2parent_outI1(int whack_sock
	       , struct connection *c
	       , struct state *predecessor
	       , lset_t policy
	       , unsigned long try
	       , enum crypto_importance importance)
{
    struct state *st = new_state();
    struct msg_digest md;   /* use reply/rbody found inside */
    int numvidtosend = 1;  /* we always send DPD VID */

    /* set up new state */
    initialize_new_state(st, c, policy, try, whack_sock, importance);
    st->st_ikev2 = TRUE;
    st->st_state = STATE_PARENT_I1;
    st->st_msgid_lastack = INVALID_MSGID;
    st->st_msgid_nextuse = 0;

    if (HAS_IPSEC_POLICY(policy))
	add_pending(dup_any(whack_sock), st, c, policy, 1
	    , predecessor == NULL? SOS_NOBODY : predecessor->st_serialno);

    if (predecessor == NULL)
	openswan_log("initiating v2 parent SA");
    else
	openswan_log("initiating v2 parent SA to replace #%lu", predecessor->st_serialno);

    /* set up reply */
    init_pbs(&md.reply, reply_buffer, sizeof(reply_buffer), "reply packet");

    /* HDR out */
    {
	struct isakmp_hdr hdr;

	zero(&hdr);	/* default to 0 */
	hdr.isa_version = IKEv2_MAJOR_VERSION << ISA_MAJ_SHIFT | IKEv2_MINOR_VERSION;
	hdr.isa_np   = ISAKMP_NEXT_v2SA;
	hdr.isa_xchg = ISAKMP_v2_SA_INIT;
	hdr.isa_flags = ISAKMP_FLAGS_I;
	memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
	/* R-cookie, are left zero */

	if (!out_struct(&hdr, &isakmp_hdr_desc, &md.reply, &md.rbody))
	{
	    reset_cur_state();
	    return STF_INTERNAL_ERROR;
	}
    }

    /* SA out */
    {
	u_char *sa_start = md.rbody.cur;
	int    policy_index = POLICY_ISAKMP(policy
					    , c->spd.this.xauth_server
					    , c->spd.this.xauth_client);

	/* if we  have an OpenPGP certificate we assume an
	 * OpenPGP peer and have to send the Vendor ID
	 */
	int np = numvidtosend > 0 ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
	if (!ikev2_out_sa(&md.rbody
			  , &oakley_sadb[policy_index]
			  , st, np))
	{
	    openswan_log("outsa fail");
	    reset_cur_state();
	    return STF_INTERNAL_ERROR;
	}
	/* save initiator SA for later HASH */
	passert(st->st_p1isa.ptr == NULL);	/* no leak!  (MUST be first time) */
	clonetochunk(st->st_p1isa, sa_start, md.rbody.cur - sa_start
	    , "sa in main_outI1");
    }

    /* Send DPD VID */
    {
	int np = --numvidtosend > 0 ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
	if(!out_vid(np, &md.rbody, VID_MISC_DPD)) {
	    reset_cur_state();
	    return STF_INTERNAL_ERROR;
	}
    }

    close_message(&md.rbody);
    close_output_pbs(&md.reply);

    /* let TCL hack it before we mark the length and copy it */
    TCLCALLOUT("v2_avoidEmitting", st, st->st_connection, &md);
    clonetochunk(st->st_tpacket, md.reply.start, pbs_offset(&md.reply)
	, "reply packet for main_outI1");

    /* Transmit */
    send_packet(st, "main_outI1", TRUE);

    /* Set up a retransmission event, half a minute henceforth */
    TCLCALLOUT("v2_adjustTimers", st, st->st_connection, &md);

#ifdef TPM
 tpm_stolen:
 tpm_ignore:
#endif
    delete_event(st);
    event_schedule(EVENT_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);

    if (predecessor != NULL)
    {
	update_pending(predecessor, st);
	whack_log(RC_NEW_STATE + STATE_MAIN_I1
	    , "%s: initiate, replacing #%lu"
	    , enum_name(&state_names, st->st_state)
	    , predecessor->st_serialno);
    }
    else
    {
	whack_log(RC_NEW_STATE + STATE_MAIN_I1
	    , "%s: initiate", enum_name(&state_names, st->st_state));
    }
    reset_cur_state();
    return STF_OK;
}

void ikev2_delete_out(struct state *st UNUSED)
{
    abort();
}


/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
 
