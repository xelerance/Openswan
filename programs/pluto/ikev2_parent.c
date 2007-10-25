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
#include "ike_continuations.h"

#include "tpm/tpm.h"

static void ikev2_parent_outI1_continue(struct pluto_crypto_req_cont *pcrc
				, struct pluto_crypto_req *r
				, err_t ugh);

static stf_status ikev2_parent_outI1_tail(struct pluto_crypto_req_cont *pcrc
						, struct pluto_crypto_req *r);

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
    struct db_sa *sadb;
    int    groupnum;
    int    policy_index = POLICY_ISAKMP(policy
					, c->spd.this.xauth_server
					, c->spd.this.xauth_client);


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

    /*
     * now, we need to initialize st->st_oakley, specifically, the group
     * number needs to be initialized.
     */

    groupnum = 0;
    
    st->st_sadb = &oakley_sadb[policy_index];
    sadb = oakley_alg_makedb(st->st_connection->alg_info_ike
			     , st->st_sadb, 0);
    if(sadb != NULL) {
	st->st_sadb = sadb;
    }
    sa_v2_convert(st->st_sadb);
    {
	int  pc_cnt;

	/* look at all the proposals */
	if(st->st_sadb->prop_disj!=NULL) {
	    for(pc_cnt=0; pc_cnt < st->st_sadb->prop_disj_cnt && groupnum==0;
		pc_cnt++)
	    {
		struct db_v2_prop *vp = &st->st_sadb->prop_disj[pc_cnt];
		int pr_cnt;	    
	    
		/* look at all the proposals */
		if(vp->props!=NULL) {
		    for(pr_cnt=0; pr_cnt < vp->prop_cnt && groupnum==0; pr_cnt++)
		    {
			int ts_cnt;	    
			struct db_v2_prop_conj *vpc = &vp->props[pr_cnt];
			
			for(ts_cnt=0; ts_cnt < vpc->trans_cnt && groupnum==0; ts_cnt++) {
			    struct db_v2_trans *tr = &vpc->trans[ts_cnt];
			    if(tr!=NULL
			       && tr->transform_type == IKEv2_TRANS_TYPE_DH) {
				groupnum = tr->transid;
			    }
			}
		    }
		}
	    }
	}
    }
    if(groupnum == 0) {
	groupnum = OAKLEY_GROUP_MODP1536;
    }
    st->st_oakley.group=lookup_group(groupnum); 

    /* now. we need to go calculate the nonce, and the KE */
    {
	struct ke_continuation *ke = alloc_thing(struct ke_continuation
						 , "ikev2_outI1 KE");
	stf_status e;

	ke->md = alloc_md();
	ke->md->st = st;
	set_suspended(st, ke->md);

	if (!st->st_sec_in_use) {
	    ke->ke_pcrc.pcrc_func = ikev2_parent_outI1_continue;
	    e = build_ke(&ke->ke_pcrc, st, st->st_oakley.group, importance);
	    if(e != STF_SUSPEND && e != STF_INLINE) {
	      loglog(RC_CRYPTOFAILED, "system too busy");
	      delete_state(st);
	    }
	} else {
	    e = ikev2_parent_outI1_tail((struct pluto_crypto_req_cont *)ke
					, NULL);
	}

	reset_globals();

	return e;
    }
}

static void
ikev2_parent_outI1_continue(struct pluto_crypto_req_cont *pcrc
			    , struct pluto_crypto_req *r
			    , err_t ugh)
{
    struct ke_continuation *ke = (struct ke_continuation *)pcrc;
    struct msg_digest *md = ke->md;
    struct state *const st = md->st;
    stf_status e;
    
    DBG(DBG_CONTROLMORE
	, DBG_log("ikev2 parent outI1: calculated ke+nonce, sending I1"));
  
    /* XXX should check out ugh */
    passert(ugh == NULL);
    passert(cur_state == NULL);
    passert(st != NULL);

    passert(st->st_suspended_md == ke->md);
    set_suspended(st,NULL);	/* no longer connected or suspended */
    
    set_cur_state(st);
    
    st->st_calculating = FALSE;

    e = ikev2_parent_outI1_tail(pcrc, r);
  
    if(ke->md != NULL) {
	complete_state_transition(&ke->md, e);
	if(ke->md) release_md(ke->md);
    }
    reset_globals();
    
    passert(GLOBALS_ARE_RESET());
}


/*
 * package up the calculate KE value, and emit it as a KE payload.
 * used by IKEv2: parent, child (PFS)
 */
static bool
ship_v2KE(struct state *st
	  , struct pluto_crypto_req *r
	  , chunk_t *g
	  , pb_stream *outs, u_int8_t np)
{
    struct ikev2_ke v2ke;
    struct pcr_kenonce *kn = &r->pcr_d.kn;
    pb_stream kepbs;

    memset(&v2ke, 0, sizeof(v2ke));
    v2ke.isak_np = np;
    v2ke.isak_group   = kn->oakley_group;
    unpack_KE(st, r, g);
    if(!out_struct(&v2ke, &ikev2_ke_desc, outs, &kepbs)) {
	return FALSE;
    }
    if(!out_chunk(st->st_gi, &kepbs, "ikev2 g^x")) {
	return FALSE;
    }
    close_output_pbs(&kepbs);
    return TRUE;
}

static stf_status
ikev2_parent_outI1_tail(struct pluto_crypto_req_cont *pcrc
			      , struct pluto_crypto_req *r)
{
    struct ke_continuation *ke = (struct ke_continuation *)pcrc;
    struct msg_digest *md = ke->md;
    struct state *const st = md->st;
    /* struct connection *c = st->st_connection; */
    int numvidtosend = 1;  /* we always send Openswan VID */

    /* set up reply */
    init_pbs(&md->reply, reply_buffer, sizeof(reply_buffer), "reply packet");

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

	if (!out_struct(&hdr, &isakmp_hdr_desc, &md->reply, &md->rbody))
	{
	    reset_cur_state();
	    return STF_INTERNAL_ERROR;
	}
    }

    /* SA out */
    {
	u_char *sa_start = md->rbody.cur;

	/* if we  have an OpenPGP certificate we assume an
	 * OpenPGP peer and have to send the Vendor ID
	 */
	if (!ikev2_out_sa(&md->rbody
			  , st->st_sadb
			  , st, ISAKMP_NEXT_v2KE))
	{
	    openswan_log("outsa fail");
	    reset_cur_state();
	    return STF_INTERNAL_ERROR;
	}
	/* save initiator SA for later HASH */
	passert(st->st_p1isa.ptr == NULL);	/* no leak!  (MUST be first time) */
	clonetochunk(st->st_p1isa, sa_start, md->rbody.cur - sa_start
	    , "sa in main_outI1");
    }

    /* send KE */
    if(!ship_v2KE(st, r, &st->st_gi, &md->rbody, ISAKMP_NEXT_v2Ni))
	return STF_INTERNAL_ERROR;

    
    /* send NONCE */
    unpack_nonce(&st->st_ni, r);
    {
	int np = numvidtosend > 0 ? ISAKMP_NEXT_v2V : ISAKMP_NEXT_NONE;
	struct ikev2_nonce in;
	pb_stream pb;
	
	memset(&in, 0, sizeof(in));
	in.isan_np = np;
	in.isan_critical = ISAKMP_PAYLOAD_CRITICAL;

	if(!out_struct(&in, &ikev2_nonce_desc, &md->rbody, &pb) ||
	   !out_raw(st->st_ni.ptr, st->st_ni.len, &pb, "IKEv2 nonce"))
	    return STF_INTERNAL_ERROR;
	close_output_pbs(&pb);
    }

    /* Send DPD VID */
    {
	int np = --numvidtosend > 0 ? ISAKMP_NEXT_v2V : ISAKMP_NEXT_NONE;

	if (!out_generic_raw(np, &isakmp_vendor_id_desc, &md->rbody
			     , pluto_vendorid, strlen(pluto_vendorid), "Vendor ID"))
	    return STF_INTERNAL_ERROR;
    }

    close_message(&md->rbody);
    close_output_pbs(&md->reply);

    /* let TCL hack it before we mark the length and copy it */
    TCLCALLOUT("v2_avoidEmitting", st, st->st_connection, md);
    clonetochunk(st->st_tpacket, md->reply.start, pbs_offset(&md->reply)
	, "reply packet for ikev2_parent_outI1");

    /* Transmit */
    send_packet(st, "main_outI1", TRUE);

    /* Set up a retransmission event, half a minute henceforth */
    TCLCALLOUT("v2_adjustTimers", st, st->st_connection, md);

#ifdef TPM
 tpm_stolen:
 tpm_ignore:
#endif
    delete_event(st);
    event_schedule(EVENT_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);

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
 
