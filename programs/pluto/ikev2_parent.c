/* 
 * IKEv2 parent SA creation routines
 * Copyright (C) 2007  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008  Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008  Antony Antony <antony@xelerance.com>
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
#include "x509.h"
#include "x509more.h"
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
#include "cookie.h"
#include "rnd.h"
#include "pending.h"
#include "kernel.h"

#include "tpm/tpm.h"

#define SEND_NOTIFICATION_AA(t, d) \
    if (st) send_v2_notification_from_state(st, st->st_state, t, d); \
    else send_v2_notification_from_md(md, t, d); 


#define SEND_NOTIFICATION(t) \
    if (st) send_v2_notification_from_state(st, st->st_state, t, NULL); \
    else send_v2_notification_from_md(md, t, NULL); 

static void ikev2_parent_outI1_continue(struct pluto_crypto_req_cont *pcrc
				, struct pluto_crypto_req *r
				, err_t ugh);

static stf_status ikev2_parent_outI1_tail(struct pluto_crypto_req_cont *pcrc
						, struct pluto_crypto_req *r);

static bool ikev2_get_dcookie(u_char *dcookie, chunk_t st_ni
	,ip_address *addr, u_int8_t *spiI); 

static stf_status ikev2_parent_outI1_common(struct msg_digest *md
					    , struct state *st);

/*
 *
 ***************************************************************
 *****                   PARENT_OUTI1                      *****
 ***************************************************************
 *
 * 
 * Initiate an Oakley Main Mode exchange.
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
    get_cookie(TRUE, st->st_icookie, COOKIE_SIZE, &c->spd.that.host_addr);
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
	whack_log(RC_NEW_STATE + STATE_PARENT_I1
	    , "%s: initiate, replacing #%lu"
	    , enum_name(&state_names, st->st_state)
	    , predecessor->st_serialno);
    }
    else
    {
	whack_log(RC_NEW_STATE + STATE_PARENT_I1
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
    sadb = st->st_sadb = sa_v2_convert(st->st_sadb);
    {
	unsigned int  pc_cnt;

	/* look at all the proposals */
	if(st->st_sadb->prop_disj!=NULL) {
	    for(pc_cnt=0; pc_cnt < st->st_sadb->prop_disj_cnt && groupnum==0;
		pc_cnt++)
	    {
		struct db_v2_prop *vp = &st->st_sadb->prop_disj[pc_cnt];
		unsigned int pr_cnt;	    
	    
		/* look at all the proposals */
		if(vp->props!=NULL) {
		    for(pr_cnt=0; pr_cnt < vp->prop_cnt && groupnum==0; pr_cnt++)
		    {
			unsigned int ts_cnt;	    
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
    st->st_oakley.groupnum=groupnum; 

    /* now. we need to go calculate the nonce, and the KE */
    {
	struct ke_continuation *ke = alloc_thing(struct ke_continuation
						 , "ikev2_outI1 KE");
	stf_status e;

	ke->md = alloc_md();
	ke->md->from_state = STATE_IKEv2_BASE;
	ke->md->svm = ikev2_parent_firststate();
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
	complete_v2_state_transition(&ke->md, e);
	if(ke->md) release_md(ke->md);
    }
    reset_cur_state();
    reset_globals();
    
    passert(GLOBALS_ARE_RESET());
}


/*
 * unpack the calculate KE value, store it in state.
 * used by IKEv2: parent, child (PFS)
 */
static int 
unpack_v2KE(struct state *st
	    , struct pluto_crypto_req *r
	    , chunk_t *g)
{
    struct pcr_kenonce *kn = &r->pcr_d.kn;

    unpack_KE(st, r, g);
    return kn->oakley_group;
}

/*
 * package up the calculate KE value, and emit it as a KE payload.
 * used by IKEv2: parent, child (PFS)
 */
static bool
justship_v2KE(struct state *st UNUSED
	      , chunk_t *g, unsigned int oakley_group
	      , pb_stream *outs, u_int8_t np)
{
    struct ikev2_ke v2ke;
    pb_stream kepbs;

    memset(&v2ke, 0, sizeof(v2ke));
    v2ke.isak_np      = np;
    v2ke.isak_group   = oakley_group;
    if(!out_struct(&v2ke, &ikev2_ke_desc, outs, &kepbs)) {
	return FALSE;
    }
    if(!out_chunk(*g, &kepbs, "ikev2 g^x")) {
	return FALSE;
    }
    close_output_pbs(&kepbs);
    return TRUE;
}

static bool
ship_v2KE(struct state *st
	  , struct pluto_crypto_req *r
	  , chunk_t *g
	  , pb_stream *outs, u_int8_t np)
{
    int oakley_group = unpack_v2KE(st, r, g);
    return justship_v2KE(st, g, oakley_group, outs, np);
}

static stf_status
ikev2_parent_outI1_tail(struct pluto_crypto_req_cont *pcrc
			      , struct pluto_crypto_req *r)
{
    struct ke_continuation *ke = (struct ke_continuation *)pcrc;
    struct msg_digest *md = ke->md;
    struct state *const st = md->st;

    unpack_v2KE(st, r, &st->st_gi);
    unpack_nonce(&st->st_ni, r);
    return ikev2_parent_outI1_common(md, st);
}


static stf_status
ikev2_parent_outI1_common(struct msg_digest *md
			  , struct state *st)
{
    /* struct connection *c = st->st_connection; */
    int numvidtosend = 1;  /* we always send Openswan VID */

    /* set up reply */
    init_pbs(&md->reply, reply_buffer, sizeof(reply_buffer), "reply packet");

    /* HDR out */
    {
	struct isakmp_hdr hdr;

	zero(&hdr);	/* default to 0 */
	hdr.isa_version = IKEv2_MAJOR_VERSION << ISA_MAJ_SHIFT | IKEv2_MINOR_VERSION;
	if(st->st_dcookie.ptr)
		hdr.isa_np   = ISAKMP_NEXT_v2N; 
	else 
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
    /* send an anti DOS cookie, 4306 2.6, if we have received one from the 
     * responder 
     */ 

	if(st->st_dcookie.ptr)
	{
		chunk_t child_spi;
		memset(&child_spi, 0, sizeof(child_spi));
		ship_v2N (ISAKMP_NEXT_v2SA, ISAKMP_PAYLOAD_CRITICAL, PROTO_ISAKMP,
				    &child_spi, 
					COOKIE, &st->st_dcookie, &md->rbody);
    }
    /* SA out */
    {
	u_char *sa_start = md->rbody.cur;

	/* if we  have an OpenPGP certificate we assume an
	 * OpenPGP peer and have to send the Vendor ID
	 */
	if(st->st_sadb->prop_disj_cnt == 0 || st->st_sadb->prop_disj) {
	    st->st_sadb = sa_v2_convert(st->st_sadb);
	}

	if (!ikev2_out_sa(&md->rbody
			  , PROTO_ISAKMP
			  , st->st_sadb
			  , st, TRUE /* parentSA */
			  , ISAKMP_NEXT_v2KE))
	{
	    openswan_log("outsa fail");
	    reset_cur_state();
	    return STF_INTERNAL_ERROR;
	}
	/* save initiator SA for later HASH */
	if(st->st_p1isa.ptr == NULL)	/* no leak!  (MUST be first time) */
	{
		clonetochunk(st->st_p1isa, sa_start, md->rbody.cur - sa_start
	    	, "sa in main_outI1");
	}
    }

    /* send KE */
    if(!justship_v2KE(st, &st->st_gi, st->st_oakley.groupnum,  &md->rbody, ISAKMP_NEXT_v2Ni))
	return STF_INTERNAL_ERROR;

    
    /* send NONCE */
    {
	int np = numvidtosend > 0 ? ISAKMP_NEXT_v2V : ISAKMP_NEXT_NONE;
	struct ikev2_generic in;
	pb_stream pb;
	
	memset(&in, 0, sizeof(in));
	in.isag_np = np;
	in.isag_critical = ISAKMP_PAYLOAD_CRITICAL;

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

    /* save packet for later signing */
    clonetochunk(st->st_firstpacket_me, md->reply.start
		 , pbs_offset(&md->reply), "saved first packet");

    /* Transmit */
    send_packet(st, __FUNCTION__, TRUE);

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

/*
 *
 ***************************************************************
 *                       PARENT_INI1                       *****
 ***************************************************************
 *  - 
 *  
 *
 */
static void ikev2_parent_inI1outR1_continue(struct pluto_crypto_req_cont *pcrc
					    , struct pluto_crypto_req *r
					    , err_t ugh);

static stf_status
ikev2_parent_inI1outR1_tail(struct pluto_crypto_req_cont *pcrc
			    , struct pluto_crypto_req *r);

stf_status ikev2parent_inI1outR1(struct msg_digest *md)
{
    struct state *st = md->st;
    lset_t policy = POLICY_IKEV2_ALLOW;
    struct connection *c = find_host_connection(&md->iface->ip_addr
						, md->iface->port
						, &md->sender
						, md->sender_port
						, POLICY_IKEV2_ALLOW);

    /* retrieve st->st_gi */

#if 0
    if(c==NULL) {
	/*
	 * make up a policy from the thing that was proposed, and see
	 * if we can find a connection with that policy.
	 */
	
 	pb_stream pre_sa_pbs = sa_pd->pbs;
 	policy = preparse_isakmp_sa_body(&pre_sa_pbs);
	c = find_host_connection(&md->iface->ip_addr, pluto_port
				 , (ip_address*)NULL, md->sender_port, policy);
	
	
    }
#endif

    if(c == NULL) {
	/*
	 * be careful about responding, or logging, since it may be that we
	 * are under DOS
	 */
	DBG_log("no connection found\n");
	//SEND_NOTIFICATION(NO_PROPOSAL_CHOSEN);
	return STF_FAIL;
    }
	

    DBG_log("found connection: %s\n", c ? c->name : "<none>");

    if(!st) {
	st = new_state();
	/* set up new state */
	memcpy(st->st_icookie, md->hdr.isa_icookie, COOKIE_SIZE);
	initialize_new_state(st, c, policy, 0, NULL_FD, pcim_stranger_crypto);
	st->st_ikev2 = TRUE;
	st->st_state = STATE_PARENT_R1;
	st->st_msgid_lastack = INVALID_MSGID;
	st->st_msgid_nextuse = 0;

	md->st = st;
	md->from_state = STATE_IKEv2_BASE;
    }

    /* check,as a responder, are we under dos attack or not 
	 * if yes go to 6 message exchange mode. it is a config option for now.
	 * TBD set force_busy dynamically
	 */ 
	if(force_busy == TRUE) 
	{ 
	    u_char dcookie[SHA1_DIGEST_SIZE];
		chunk_t dc;
		ikev2_get_dcookie( dcookie, st->st_ni, &md->sender, st->st_icookie);
		dc.ptr = dcookie;
		dc.len = SHA1_DIGEST_SIZE;

   		/* check if I1 packet contian KE and a v2N payload with type COOKIE */
       	if ( md->chain[ISAKMP_NEXT_v2KE] &&   md->chain[ISAKMP_NEXT_v2N] &&
       	     (md->chain[ISAKMP_NEXT_v2N]->payload.v2n.isan_type == COOKIE))
		{
			DBG(DBG_CONTROLMORE
	        	, DBG_log("received a DOS cookie in I1 verify it"));
	       	/* we received dcookie we send earlier verify it */
			u_int8_t spisize 
					= md->chain[ISAKMP_NEXT_v2N]->payload.v2n.isan_spisize;
	        const pb_stream *dc_pbs = &md->chain[ISAKMP_NEXT_v2N]->pbs;
			chunk_t blob; 
			blob.ptr = dc_pbs->cur + spisize;
			blob.len = pbs_left(dc_pbs) - spisize;
			DBG(DBG_CONTROLMORE
	            ,DBG_dump_chunk("dcookie received in I1 Packet", blob);
				DBG_dump("dcookie computed", dcookie, SHA1_DIGEST_SIZE)); 

			if(memcmp(blob.ptr, dcookie, SHA1_DIGEST_SIZE)!=0) {
				openswan_log("mismatch in DOS COOKIE,send a new one");
				SEND_NOTIFICATION_AA(COOKIE, &dc); 
				return STF_FAIL;
			}
			DBG(DBG_CONTROLMORE
	            ,DBG_log("dcookie received match with computed one"));
 		}
        else 
		{
			/* we are under DOS attack I1 contains no DOS COOKIE */
			DBG(DBG_CONTROLMORE
	            ,DBG_log("busy mode on. receieved I1 without a valid dcookie");
	            DBG_log("send a dcookie and forget this state"));
			SEND_NOTIFICATION_AA(COOKIE, &dc); 
			return STF_FAIL;
		}
	}
	else {
			DBG(DBG_CONTROLMORE ,DBG_log("will not send/process a dcookie"));

	}

    /*
     * We have to agree to the DH group before we actually know who
     * we are talking to.   If we support the group, we use it.
     *
     * It is really too hard here to go through all the possible policies
     * that might permit this group.  If we think we are being DOS'ed
     * then we should demand a cookie.
     */
    {
	struct ikev2_ke *ke;
	ke = &md->chain[ISAKMP_NEXT_v2KE]->payload.v2ke;

	st->st_oakley.group=lookup_group(ke->isak_group);
	if(st->st_oakley.group==NULL) {
	    char fromname[ADDRTOT_BUF];
	    
	    addrtot(&md->sender, 0, fromname, ADDRTOT_BUF);
	    openswan_log("rejecting I1 from %s:%u, invalid DH group=%u"
			 ,fromname, md->sender_port, ke->isak_group);
	    return INVALID_KE_PAYLOAD;
	}
    }

    /* now. we need to go calculate the nonce, and the KE */
    {
	struct ke_continuation *ke = alloc_thing(struct ke_continuation
						 , "ikev2_inI1outR1 KE");
	stf_status e;

	ke->md = md;
	set_suspended(st, ke->md);

	if (!st->st_sec_in_use) {
	    ke->ke_pcrc.pcrc_func = ikev2_parent_inI1outR1_continue;
	    e = build_ke(&ke->ke_pcrc, st, st->st_oakley.group, pcim_stranger_crypto);
	    if(e != STF_SUSPEND && e != STF_INLINE) {
	      loglog(RC_CRYPTOFAILED, "system too busy");
	      delete_state(st);
	    }
	} else {
	    e = ikev2_parent_inI1outR1_tail((struct pluto_crypto_req_cont *)ke
					    , NULL);
	}

	reset_globals();

	return e;
    }
}

static void
ikev2_parent_inI1outR1_continue(struct pluto_crypto_req_cont *pcrc
				, struct pluto_crypto_req *r
				, err_t ugh)
{
    struct ke_continuation *ke = (struct ke_continuation *)pcrc;
    struct msg_digest *md = ke->md;
    struct state *const st = md->st;
    stf_status e;
    
    DBG(DBG_CONTROLMORE
	, DBG_log("ikev2 parent inI1outR1: calculated ke+nonce, sending R1"));
  
    /* XXX should check out ugh */
    passert(ugh == NULL);
    passert(cur_state == NULL);
    passert(st != NULL);

    passert(st->st_suspended_md == ke->md);
    set_suspended(st,NULL);	/* no longer connected or suspended */
    
    set_cur_state(st);
    
    st->st_calculating = FALSE;

    e = ikev2_parent_inI1outR1_tail(pcrc, r);
  
    if(ke->md != NULL) {
	complete_v2_state_transition(&ke->md, e);
	if(ke->md) release_md(ke->md);
    }
    reset_globals();
    
    passert(GLOBALS_ARE_RESET());
}

static stf_status
ikev2_parent_inI1outR1_tail(struct pluto_crypto_req_cont *pcrc
			    , struct pluto_crypto_req *r)
{
    struct ke_continuation *ke = (struct ke_continuation *)pcrc;
    struct msg_digest *md = ke->md;
    struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
    struct state *const st = md->st;
    pb_stream *keyex_pbs;
    int    numvidtosend=1;

    /* note that we don't update the state here yet */
    memcpy(st->st_icookie, md->hdr.isa_icookie, COOKIE_SIZE);
    get_cookie(FALSE, st->st_rcookie, COOKIE_SIZE, &md->sender);

    /* record first packet for later checking of signature */
    clonetochunk(st->st_firstpacket_him, md->message_pbs.start
		 , pbs_offset(&md->message_pbs), "saved first received packet");

    
    /* HDR out */
    {
	struct isakmp_hdr r_hdr = md->hdr;

	memcpy(r_hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
	r_hdr.isa_np = ISAKMP_NEXT_v2SA;
	r_hdr.isa_flags &= ~ISAKMP_FLAGS_I;
	r_hdr.isa_flags |=  ISAKMP_FLAGS_R;
	if (!out_struct(&r_hdr, &isakmp_hdr_desc, &md->reply, &md->rbody))
	    return STF_INTERNAL_ERROR;
    }

    /* start of SA out */
    {
	struct isakmp_sa r_sa = sa_pd->payload.sa;
	notification_t rn;
	pb_stream r_sa_pbs;

	r_sa.isasa_np = ISAKMP_NEXT_v2KE;  /* XXX */
	if (!out_struct(&r_sa, &ikev2_sa_desc, &md->rbody, &r_sa_pbs))
	    return STF_INTERNAL_ERROR;

	/* SA body in and out */
	rn = ikev2_parse_parent_sa_body(&sa_pd->pbs, &sa_pd->payload.v2sa,
				 &r_sa_pbs, st, FALSE);
	
	if (rn != NOTHING_WRONG)
	    return STF_FAIL + rn;
    }

    keyex_pbs = &md->chain[ISAKMP_NEXT_v2KE]->pbs;
    /* KE in */
    RETURN_STF_FAILURE(accept_KE(&st->st_gi, "Gi", st->st_oakley.group, keyex_pbs));

    /* Ni in */
    RETURN_STF_FAILURE(accept_v2_nonce(md, &st->st_ni, "Ni"));

    /* send KE */
    if(!ship_v2KE(st, r, &st->st_gr, &md->rbody, ISAKMP_NEXT_v2Nr))
	return STF_INTERNAL_ERROR;
    
    /* send NONCE */
    unpack_nonce(&st->st_nr, r);
    {
	int np = numvidtosend > 0 ? ISAKMP_NEXT_v2V : ISAKMP_NEXT_NONE;
	struct ikev2_generic in;
	pb_stream pb;
	
	memset(&in, 0, sizeof(in));
	in.isag_np = np;
	in.isag_critical = ISAKMP_PAYLOAD_CRITICAL;

	if(!out_struct(&in, &ikev2_nonce_desc, &md->rbody, &pb) ||
	   !out_raw(st->st_nr.ptr, st->st_nr.len, &pb, "IKEv2 nonce"))
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

    /* let TCL hack it before we mark the length. */
    TCLCALLOUT("v2_avoidEmitting", st, st->st_connection, md);

    /* keep it for a retransmit if necessary */
    clonetochunk(st->st_tpacket, md->reply.start, pbs_offset(&md->reply)
		 , "reply packet for ikev2_parent_outI1");

    /* save packet for later signing */
    clonetochunk(st->st_firstpacket_me, md->reply.start
		 , pbs_offset(&md->reply), "saved first packet");

    /* note: retransimission is driven by initiator */

    return STF_OK;
    
}

/*
 *
 ***************************************************************
 *                       PARENT_inR1                       *****
 ***************************************************************
 *  - 
 *  
 *
 */
static void ikev2_parent_inR1outI2_continue(struct pluto_crypto_req_cont *pcrc
					    , struct pluto_crypto_req *r
					    , err_t ugh);

static stf_status
ikev2_parent_inR1outI2_tail(struct pluto_crypto_req_cont *pcrc
			    , struct pluto_crypto_req *r);

stf_status ikev2parent_inR1outI2(struct msg_digest *md)
{
    struct state *st = md->st;
    //struct connection *c = st->st_connection;
    pb_stream *keyex_pbs;
	
    /* check if the responder replied with v2N with DOS COOKIE */
    if( md->chain[ISAKMP_NEXT_v2N]
		&& md->chain[ISAKMP_NEXT_v2N]->payload.v2n.isan_type ==  COOKIE)
    {
		DBG(DBG_CONTROLMORE 
			,DBG_log("inR1OutI2 received a DOS COOKIE from the responder");
    	    DBG_log("resend the I1 with a cookie payload"));
		u_int8_t spisize = md->chain[ISAKMP_NEXT_v2N]->payload.v2n.isan_spisize;
	    const pb_stream *dc_pbs = &md->chain[ISAKMP_NEXT_v2N]->pbs;
    	clonetochunk(st->st_dcookie,  (dc_pbs->cur + spisize)
		 , (pbs_left(dc_pbs) - spisize), "saved received dcookie");

		DBG(DBG_CONTROLMORE
	        ,DBG_dump_chunk("dcookie received (instead of a R1):",
						    st->st_dcookie);
	        DBG_log("next STATE_PARENT_I1 resend I1 with the dcookie"));

		md->svm = ikev2_parent_firststate();

		st->st_state = STATE_PARENT_I1;
    	st->st_msgid_lastack = INVALID_MSGID;
	 	md->msgid_received = INVALID_MSGID;  //AAA hack 
    	st->st_msgid_nextuse = 0;

		return ikev2_parent_outI1_common(md, st);  
    }

    /*
     * the responder sent us back KE, Gr, Nr, and it's our time to calculate
     * the shared key values.
     */

    DBG(DBG_CONTROLMORE
	, DBG_log("ikev2 parent inR1: calculating g^{xy} in order to send I2"));
 
    /* KE in */
    keyex_pbs = &md->chain[ISAKMP_NEXT_v2KE]->pbs;
    RETURN_STF_FAILURE(accept_KE(&st->st_gr, "Gr", st->st_oakley.group, keyex_pbs));

    /* Ni in */
    RETURN_STF_FAILURE(accept_v2_nonce(md, &st->st_nr, "Ni"));

    if(md->chain[ISAKMP_NEXT_v2SA] == NULL) {
	openswan_log("No responder SA proposal found");
	return PAYLOAD_MALFORMED;
    }

    /* process and confirm the SA selected */
    {
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
	notification_t rn;

	/* SA body in and out */
	rn = ikev2_parse_parent_sa_body(&sa_pd->pbs, &sa_pd->payload.v2sa,
					NULL, st, FALSE);
	
	if (rn != NOTHING_WRONG)
	    return STF_FAIL + rn;
    }

    /* update state */
    ikev2_update_counters(md);

    /* now. we need to go calculate the g^xy */
    {
	struct dh_continuation *dh = alloc_thing(struct dh_continuation
						 , "ikev2_inR1outI2 KE");
	stf_status e;

	dh->md = md;
	set_suspended(st, dh->md);

	dh->dh_pcrc.pcrc_func = ikev2_parent_inR1outI2_continue;
	e = start_dh_v2(&dh->dh_pcrc, st, st->st_import, INITIATOR, st->st_oakley.groupnum);
	if(e != STF_SUSPEND && e != STF_INLINE) {
	    loglog(RC_CRYPTOFAILED, "system too busy");
	    delete_state(st);
	}

	reset_globals();

	return e;
    }
}

static void
ikev2_parent_inR1outI2_continue(struct pluto_crypto_req_cont *pcrc
				, struct pluto_crypto_req *r
				, err_t ugh)
{
    struct dh_continuation *dh = (struct dh_continuation *)pcrc;
    struct msg_digest *md = dh->md;
    struct state *const st = md->st;
    stf_status e;
    
    DBG(DBG_CONTROLMORE
	, DBG_log("ikev2 parent inR1outI1: calculating g^{xy}, sending I2"));
  
    /* XXX should check out ugh */
    passert(ugh == NULL);
    passert(cur_state == NULL);
    passert(st != NULL);

    passert(st->st_suspended_md == dh->md);
    set_suspended(st,NULL);	/* no longer connected or suspended */
    
    set_cur_state(st);
    
    st->st_calculating = FALSE;

    e = ikev2_parent_inR1outI2_tail(pcrc, r);
  
    if(dh->md != NULL) {
	complete_v2_state_transition(&dh->md, e);
	if(dh->md) release_md(dh->md);
    }
    reset_globals();
    
    passert(GLOBALS_ARE_RESET());
}

static void ikev2_padup_pre_encrypt(struct msg_digest *md
				    , pb_stream *e_pbs_cipher)
{
    struct state *st = md->st;
    struct state *pst= st;
    
    if(st->st_clonedfrom != 0) {
	pst = state_with_serialno(st->st_clonedfrom);
    }

    /* pads things up to message size boundary */
    {
	size_t blocksize = pst->st_oakley.encrypter->enc_blocksize;
	char  *b = alloca(blocksize);
	unsigned int    i;
	size_t padding =  pad_up(pbs_offset(e_pbs_cipher), blocksize);
	if (padding == 0) padding=blocksize;

	for(i=0; i<padding; i++) {
	    b[i]=i;
	}
	out_raw(b, padding, e_pbs_cipher, "padding and length");
    }
}

static unsigned char *ikev2_authloc(struct msg_digest *md UNUSED
				    , pb_stream *e_pbs)
{
    unsigned char *b12;
	
    b12 = e_pbs->cur;
    if(!out_zero(12, e_pbs, "96-bits of truncated HMAC"))
	return NULL;

    return b12;
}

static stf_status ikev2_encrypt_msg(struct msg_digest *md,
				    enum phase1_role init,
				    unsigned char *authstart,
				    unsigned char *iv,
				    unsigned char *encstart,
				    unsigned char *authloc,
				    pb_stream *e_pbs UNUSED,
				    pb_stream *e_pbs_cipher)
{
    struct state *st = md->st;
    struct state *pst = st;
    chunk_t *cipherkey, *authkey;

    if(st->st_clonedfrom != 0) {
	pst = state_with_serialno(st->st_clonedfrom);
    }

    if(init == INITIATOR) {
	cipherkey = &pst->st_skey_ei;
	authkey   = &pst->st_skey_ai;
    } else {
	cipherkey = &pst->st_skey_er;
	authkey   = &pst->st_skey_ar;
    }

    /* encrypt the block */
    {
	size_t  blocksize = pst->st_oakley.encrypter->enc_blocksize;
	unsigned char *savediv = alloca(blocksize);
	unsigned int   cipherlen = e_pbs_cipher->cur - encstart;
	
	DBG(DBG_CRYPT,
	    DBG_dump("data before encryption:", encstart, cipherlen));
	
	memcpy(savediv, iv, blocksize);
	
	/* now, encrypt */
	(st->st_oakley.encrypter->do_crypt)(encstart,
					    cipherlen,
					    cipherkey->ptr,
					    cipherkey->len,
					    savediv, TRUE);
	
	DBG(DBG_CRYPT,
	    DBG_dump("data after encryption:", encstart, cipherlen));
    }
    
    /* okay, authenticate from beginning of IV */
    {
	struct hmac_ctx ctx;
	
	hmac_init_chunk(&ctx, pst->st_oakley.integ_hasher, *authkey);
	hmac_update(&ctx, authstart, authloc-authstart);
	hmac_final(authloc, &ctx);
	
	if(DBGP(DBG_PARSING)) {
	    DBG_dump("data being hmac:", authstart, authloc-authstart);
	    DBG_dump("out calculated auth:", authloc, 12); 
	}
    }
    
    return STF_OK;
}

static
stf_status ikev2_decrypt_msg(struct msg_digest *md
			     , enum phase1_role init)
{
    struct state *st = md->st;
    unsigned char *encend;
    pb_stream     *e_pbs;
    unsigned int   np;
    unsigned char *iv;
    chunk_t       *cipherkey, *authkey;
    unsigned char *authstart;
    struct state *pst = st;

    if(st->st_clonedfrom != 0) {
	pst = state_with_serialno(st->st_clonedfrom);
    }

    if(init == INITIATOR) {
	cipherkey = &st->st_skey_er;
	authkey   = &st->st_skey_ar;
    } else {
	cipherkey = &st->st_skey_ei;
	authkey   = &st->st_skey_ai;
    }

    e_pbs = &md->chain[ISAKMP_NEXT_v2E]->pbs;
    np    = md->chain[ISAKMP_NEXT_v2E]->payload.generic.isag_np;

    authstart=md->packet_pbs.start;
    iv     = e_pbs->cur;
    encend = e_pbs->roof - 12;
    
    /* start by checking authenticator */
    {
	unsigned char  *b12 = alloca(pst->st_oakley.integ_hasher->hash_digest_len);
	struct hmac_ctx ctx;
	
	hmac_init_chunk(&ctx, pst->st_oakley.integ_hasher, *authkey);
	hmac_update(&ctx, authstart, encend-authstart);
	hmac_final(b12, &ctx);
	
	if(DBGP(DBG_PARSING)) {
	    DBG_dump("data being hmac:", authstart, encend-authstart);
	    DBG_dump("R2 calculated auth:", b12, 12); 
	    DBG_dump("R2  provided  auth:", encend, 12);
	}
	
	/* compare first 96 bits == 12 bytes */
	if(memcmp(b12, encend, 12)!=0) {
	    openswan_log("R2 failed to match authenticator");
	    return STF_FAIL;
	}
    }
    
    DBG(DBG_PARSING, DBG_log("authenticator matched"));
    
    /* decrypt */
    {
	size_t         blocksize = pst->st_oakley.encrypter->enc_blocksize;
	unsigned char *encstart  = iv + blocksize;
	unsigned int   enclen    = encend - encstart;
	unsigned int   padlen;
	
	DBG(DBG_CRYPT,
	    DBG_dump("data before decryption:", encstart, enclen));
	
	/* now, decrypt */
	(pst->st_oakley.encrypter->do_crypt)(encstart,
					    enclen,
					    cipherkey->ptr,
					    cipherkey->len,
					    iv, FALSE);
	
	padlen = encstart[enclen-1];
	encend = encend - padlen+1;
	
	if(encend < encstart) {
	    openswan_log("invalid pad length: %u", padlen);
	    return STF_FAIL;
	}
	
	if(DBGP(DBG_CRYPT)) {
	    DBG_dump("decrypted payload:", encstart, enclen);
	    DBG_log("striping %u bytes as pad", padlen+1);
	}
	
	init_pbs(&md->clr_pbs, encstart, enclen - (padlen+1), "cleartext");
    }
    
    ikev2_process_payloads(md, &md->clr_pbs, st->st_state, np);
    return STF_OK;
}

static stf_status ikev2_send_auth(struct connection *c
				  , struct state *st
				  , enum phase1_role role
				  , unsigned int np
				  , unsigned char *idhash_out
				  , pb_stream *outpbs)
{
    struct ikev2_a a;
    pb_stream      a_pbs;
    struct state *pst = st;

    if(st->st_clonedfrom != 0) {
	pst = state_with_serialno(st->st_clonedfrom);
    }

    
    a.isaa_critical = ISAKMP_PAYLOAD_CRITICAL;
    a.isaa_np = np;
    
    if(c->policy & POLICY_RSASIG) {
	a.isaa_type = v2_AUTH_RSA;
    } else if(c->policy & POLICY_PSK) {
	a.isaa_type = v2_AUTH_SHARED;
    } else {
	/* what else is there?... DSS not implemented. */
	return STF_FAIL;
    }
    
    if (!out_struct(&a
		    , &ikev2_a_desc
		    , outpbs
		    , &a_pbs))
	return STF_INTERNAL_ERROR;
    
    if(c->policy & POLICY_RSASIG) {
	if(!ikev2_calculate_rsa_sha1(pst, role, idhash_out, &a_pbs))
	    return STF_FATAL;
	
    } else if(c->policy & POLICY_PSK) {
	if(!ikev2_calculate_psk_auth(pst, role, idhash_out, &a_pbs))
	return STF_FAIL;
    } 
    
    close_output_pbs(&a_pbs);
    return STF_OK;
}

static stf_status
ikev2_parent_inR1outI2_tail(struct pluto_crypto_req_cont *pcrc
			    , struct pluto_crypto_req *r)
{
    struct dh_continuation *dh = (struct dh_continuation *)pcrc;
    struct msg_digest *md = dh->md;
    struct state *st      = md->st;
    struct connection *c  = st->st_connection;
    struct ikev2_generic e;
    unsigned char *encstart;
    pb_stream      e_pbs, e_pbs_cipher;
    unsigned char *iv;
    int            ivsize;
    stf_status     ret;
    unsigned char *idhash;
    unsigned char *authstart;
    struct state *pst = st;
    bool send_cert = FALSE;

    finish_dh_v2(st, r);

    if(DBGP(DBG_PRIVATE) && DBGP(DBG_CRYPT)) {
	ikev2_log_parentSA(st);
    }

    pst = st;
    st = duplicate_state(pst);
    st->st_msgid = htonl(pst->st_msgid_nextuse);
    insert_state(st);
    md->st = st;
    md->pst= pst;

    /* need to force parent state to I2 */
    pst->st_state = STATE_PARENT_I2;

    /* record first packet for later checking of signature */
    clonetochunk(pst->st_firstpacket_him, md->message_pbs.start
		 , pbs_offset(&md->message_pbs), "saved first received packet");

    /* beginning of data going out */
    authstart = md->reply.cur;

    /* HDR out */
    {
	struct isakmp_hdr r_hdr = md->hdr;

	r_hdr.isa_np    = ISAKMP_NEXT_v2E;
	r_hdr.isa_xchg  = ISAKMP_v2_AUTH;
	r_hdr.isa_flags = ISAKMP_FLAGS_I;
	r_hdr.isa_msgid = st->st_msgid;  
	memcpy(r_hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
	memcpy(r_hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
	if (!out_struct(&r_hdr, &isakmp_hdr_desc, &md->reply, &md->rbody))
	    return STF_INTERNAL_ERROR;
    }

    /* insert an Encryption payload header */
    e.isag_np = ISAKMP_NEXT_v2IDi;
    e.isag_critical = ISAKMP_PAYLOAD_CRITICAL;

    if(!out_struct(&e, &ikev2_e_desc, &md->rbody, &e_pbs)) {
	return STF_INTERNAL_ERROR;
    }

    /* insert IV */
    iv     = e_pbs.cur;
    ivsize = st->st_oakley.encrypter->iv_size;
    if(!out_zero(ivsize, &e_pbs, "iv")) {
	return STF_INTERNAL_ERROR;
    }
    get_rnd_bytes(iv, ivsize);

    /* note where cleartext starts */
    init_pbs(&e_pbs_cipher, e_pbs.cur, e_pbs.roof - e_pbs.cur, "cleartext");
    e_pbs_cipher.container = &e_pbs;
    e_pbs_cipher.desc = NULL;
    e_pbs_cipher.cur = e_pbs.cur;
    encstart = e_pbs_cipher.cur;

    /* send out the IDi payload */
    {
	struct ikev2_id r_id;
	pb_stream r_id_pbs;
	chunk_t         id_b;
	struct hmac_ctx id_ctx;
	unsigned char *id_start;
	unsigned int   id_len;

	/* XXX probably should be prf_hasher, not integ_hasher */
	hmac_init_chunk(&id_ctx, pst->st_oakley.integ_hasher, pst->st_skey_pi);
	build_id_payload((struct isakmp_ipsec_id *)&r_id, &id_b, &c->spd.this);
	r_id.isai_critical = ISAKMP_PAYLOAD_CRITICAL;
	{  /* decide to send CERT payload */
	    send_cert = doi_send_ikev2_cert_thinking(st);
	    
	    if(send_cert) 
		r_id.isai_np = ISAKMP_NEXT_v2CERT;
	    else  
		r_id.isai_np = ISAKMP_NEXT_v2AUTH; 
	}
	
	id_start = e_pbs_cipher.cur;
	if (!out_struct(&r_id
			, &ikev2_id_desc
			, &e_pbs_cipher
			, &r_id_pbs)
	    || !out_chunk(id_b, &r_id_pbs, "my identity"))
	    return STF_INTERNAL_ERROR;

	/* HASH of ID is not done over common header */
	id_start += 4;

	close_output_pbs(&r_id_pbs);

	/* calculate hash of IDi for AUTH below */
	id_len = e_pbs_cipher.cur - id_start;
	DBG(DBG_CRYPT, DBG_dump_chunk("idhash calc pi", pst->st_skey_pi));
	DBG(DBG_CRYPT, DBG_dump("idhash calc I2", id_start, id_len));
	hmac_update(&id_ctx, id_start, id_len);
	idhash = alloca(pst->st_oakley.integ_hasher->hash_digest_len);
	hmac_final(idhash, &id_ctx);
    } 

    /* send [CERT,] payload RFC 4306 3.6, 1.2) */
    {
	
	if(send_cert) {
	    stf_status certstat = ikev2_send_cert( st, md
	    					   , INITIATOR
						   ,ISAKMP_NEXT_v2AUTH
						   , &e_pbs_cipher);
	    if(certstat != STF_OK) return certstat;
	}
    } 

    /* send out the AUTH payload */
    {
	stf_status authstat = ikev2_send_auth(c, st
					      , INITIATOR, ISAKMP_NEXT_v2SA
					      , idhash, &e_pbs_cipher);
	if(authstat != STF_OK) return authstat;
    }

    /*
     * now, find an eligible child SA from the pending list, and emit
     * SA2i, TSi and TSr for it.
     */
    {
	lset_t policy;
	struct connection *c0 = first_pending(pst, &policy,&st->st_whack_sock);

	if(c0) {
	    st->st_connection = c0;
	    ikev2_emit_ipsec_sa(md,&e_pbs_cipher,ISAKMP_NEXT_v2TSi,c0, policy);
	    
	    st->st_ts_this = ikev2_subnettots(&c0->spd.this);
	    st->st_ts_that = ikev2_subnettots(&c0->spd.that);
	    
	    ikev2_calc_emit_ts(md, &e_pbs_cipher, INITIATOR, c0, policy);
	}
    }

    /*
     * need to extend the packet so that we will know how big it is
     * since the length is under the integrity check
     */
    ikev2_padup_pre_encrypt(md, &e_pbs_cipher);
    close_output_pbs(&e_pbs_cipher);

    {
	unsigned char *authloc = ikev2_authloc(md, &e_pbs);

	if(authloc == NULL) return STF_INTERNAL_ERROR;

	close_output_pbs(&e_pbs);
	close_output_pbs(&md->rbody);
	close_output_pbs(&md->reply);

	ret = ikev2_encrypt_msg(md, INITIATOR,
				authstart,
				iv, encstart, authloc,
				&e_pbs, &e_pbs_cipher);
	if(ret != STF_OK) return ret;
    }


    /* let TCL hack it before we mark the length. */
    TCLCALLOUT("v2_avoidEmitting", st, st->st_connection, md);

    /* keep it for a retransmit if necessary, but on initiator
     * we never do that, but send_packet() uses it.
     */
    clonetochunk(pst->st_tpacket, md->reply.start, pbs_offset(&md->reply)
		 , "reply packet for ikev2_parent_outI1");

    /* note: retransimission is driven by initiator */

    return STF_OK;
    
}

/*
 *
 ***************************************************************
 *                       PARENT_inI2                       *****
 ***************************************************************
 *  - 
 *  
 *
 */
static void ikev2_parent_inI2outR2_continue(struct pluto_crypto_req_cont *pcrc
					    , struct pluto_crypto_req *r
					    , err_t ugh);

static stf_status
ikev2_parent_inI2outR2_tail(struct pluto_crypto_req_cont *pcrc
			    , struct pluto_crypto_req *r);

stf_status ikev2parent_inI2outR2(struct msg_digest *md)
{
    struct state *st = md->st;
    //struct connection *c = st->st_connection;

    /*
     * the initiator sent us an encrypted payload. We need to calculate
     * our g^xy, and skeyseed values, and then decrypt the payload.
     */

    DBG(DBG_CONTROLMORE
	, DBG_log("ikev2 parent inI2outR2: calculating g^{xy} in order to decrypt I2"));
    
    /* verify that there is in fact an encrypted payload */
    if(!md->chain[ISAKMP_NEXT_v2E]) {
	openswan_log("R2 state should receive an encrypted payload");
	return STF_FATAL;
    }

    /* now. we need to go calculate the g^xy */
    {
	struct dh_continuation *dh = alloc_thing(struct dh_continuation
						 , "ikev2_inI2outR2 KE");
	stf_status e;

	dh->md = md;
	set_suspended(st, dh->md);

	dh->dh_pcrc.pcrc_func = ikev2_parent_inI2outR2_continue;
	e = start_dh_v2(&dh->dh_pcrc, st, st->st_import, RESPONDER, st->st_oakley.groupnum);
	if(e != STF_SUSPEND && e != STF_INLINE) {
	    loglog(RC_CRYPTOFAILED, "system too busy");
	    delete_state(st);
	}

	reset_globals();

	return e;
    }
}

static void
ikev2_parent_inI2outR2_continue(struct pluto_crypto_req_cont *pcrc
				, struct pluto_crypto_req *r
				, err_t ugh)
{
    struct dh_continuation *dh = (struct dh_continuation *)pcrc;
    struct msg_digest *md = dh->md;
    struct state *const st = md->st;
    stf_status e;
    
    DBG(DBG_CONTROLMORE
	, DBG_log("ikev2 parent inI2outR2: calculating g^{xy}, sending R2"));
  
    /* XXX should check out ugh */
    passert(ugh == NULL);
    passert(cur_state == NULL);
    passert(st != NULL);

    passert(st->st_suspended_md == dh->md);
    set_suspended(st,NULL);	/* no longer connected or suspended */
    
    set_cur_state(st);
    
    st->st_calculating = FALSE;

    e = ikev2_parent_inI2outR2_tail(pcrc, r);
  
    if(dh->md != NULL) {
	complete_v2_state_transition(&dh->md, e);
	if(dh->md) release_md(dh->md);
    }
    reset_globals();
    
    passert(GLOBALS_ARE_RESET());
}

static stf_status
ikev2_parent_inI2outR2_tail(struct pluto_crypto_req_cont *pcrc
			    , struct pluto_crypto_req *r)
{
    struct dh_continuation *dh = (struct dh_continuation *)pcrc;
    struct msg_digest *md  = dh->md;
    struct state *const st = md->st;
    struct connection *c   = st->st_connection;
    unsigned char *idhash_in, *idhash_out;
    unsigned char *authstart;
    unsigned int np;

    /* extract calculated values from r */
    finish_dh_v2(st, r);

    if(DBGP(DBG_PRIVATE) && DBGP(DBG_CRYPT)) {
	ikev2_log_parentSA(st);
    }

    /* decrypt things. */
    {
	stf_status ret; 
	ret = ikev2_decrypt_msg(md, RESPONDER);
	if(ret != STF_OK) return ret;
    }

    /* if it decrypted okay, then things are good, this packet is
     * well received, and we should change state.
     */
    rehash_state(st);

    if(!ikev2_decode_peer_id(md, RESPONDER)) {
	return STF_FAIL + INVALID_ID_INFORMATION;
    }

    {
	struct hmac_ctx id_ctx;
	const pb_stream *id_pbs = &md->chain[ISAKMP_NEXT_v2IDi]->pbs;
	unsigned char *idstart=id_pbs->start + 4;
	unsigned int   idlen  =pbs_room(id_pbs)-4;

	hmac_init_chunk(&id_ctx, st->st_oakley.integ_hasher, st->st_skey_pi);

	/* calculate hash of IDi for AUTH below */
	DBG(DBG_CRYPT, DBG_dump_chunk("idhash verify pi", st->st_skey_pi));
	DBG(DBG_CRYPT, DBG_dump("idhash verify I2", idstart, idlen));
	hmac_update(&id_ctx, idstart, idlen);
	idhash_in = alloca(st->st_oakley.integ_hasher->hash_digest_len);
	hmac_final(idhash_in, &id_ctx);
    }

    /* process CERT payload */
    {
	if(md->chain[ISAKMP_NEXT_v2CERT])
	{
	    /* should we check if we should accept a cert payload ?
	     *  has_preloaded_public_key(st)
	     */ 
	    DBG(DBG_CONTROLMORE
		, DBG_log("has a v2_CERT payload going to process it "));	  
	    ikev2_decode_cert(md); 
	}
    }

    /* process CERTREQ payload */
    if(md->chain[ISAKMP_NEXT_v2CERTREQ]) 
    {
	    DBG(DBG_CONTROLMORE
		,DBG_log("has a v2CERTREQ payload going to decode it"));
	    ikev2_decode_cr(md, &st->st_connection->requested_ca);
    }

    /* process AUTH payload */
    if(!md->chain[ISAKMP_NEXT_v2AUTH]) {
	openswan_log("no authentication payload found");
	return STF_FAIL;
    }

    /* now check signature from RSA key */
    switch(md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type)
    {
    case v2_AUTH_RSA:
    {
	stf_status authstat = ikev2_verify_rsa_sha1(st
						    , RESPONDER
						    , idhash_in
						    , NULL /* keys from DNS */
						    , NULL /* gateways from DNS */
						    , &md->chain[ISAKMP_NEXT_v2AUTH]->pbs);
	if(authstat != STF_OK) {
	    openswan_log("RSA authentication failed");
	    SEND_NOTIFICATION(AUTHENTICATION_FAILED);
	    return STF_FAIL;
	}
	break;
    }
    case v2_AUTH_SHARED:
    {
	stf_status authstat = ikev2_verify_psk_auth(st
						    , RESPONDER
						    , idhash_in
						    , &md->chain[ISAKMP_NEXT_v2AUTH]->pbs);
	if(authstat != STF_OK) {
	    openswan_log("PSK authentication failed AUTH mismatch!");
	    SEND_NOTIFICATION(AUTHENTICATION_FAILED);
	    return STF_FAIL;
	}
	break;
    }
    default:
	openswan_log("authentication method: %s not supported"
		     , enum_name(&ikev2_auth_names
				 ,md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type));
	return STF_FAIL;
    }

    /* good. now create child state */
    /* note: as we will switch to child state, we force the parent to the
     * new state now */
    st->st_state = STATE_PARENT_R2;
    c->newest_isakmp_sa = st->st_serialno;
    
    authstart = md->reply.cur;
    /* send response */
    {
	unsigned char *encstart;
	unsigned char *iv;
	unsigned int ivsize;
	struct ikev2_generic e;
	pb_stream      e_pbs, e_pbs_cipher;
	stf_status     ret;
	bool send_cert = FALSE;

	/* HDR out */
	{
	    struct isakmp_hdr r_hdr = md->hdr;
	    
	    r_hdr.isa_np    = ISAKMP_NEXT_v2E;
	    r_hdr.isa_xchg  = ISAKMP_v2_AUTH;
	    r_hdr.isa_flags = ISAKMP_FLAGS_R;
	    memcpy(r_hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
	    memcpy(r_hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
	    if (!out_struct(&r_hdr, &isakmp_hdr_desc, &md->reply, &md->rbody))
		return STF_INTERNAL_ERROR;
	}
	
	/* insert an Encryption payload header */
	e.isag_np = ISAKMP_NEXT_v2IDr;
	e.isag_critical = ISAKMP_PAYLOAD_CRITICAL;

	if(!out_struct(&e, &ikev2_e_desc, &md->rbody, &e_pbs)) {
	    return STF_INTERNAL_ERROR;
	}

	/* insert IV */
	iv     = e_pbs.cur;
	ivsize = st->st_oakley.encrypter->iv_size;
	if(!out_zero(ivsize, &e_pbs, "iv")) {
	    return STF_INTERNAL_ERROR;
	}
	get_rnd_bytes(iv, ivsize);
	
	/* note where cleartext starts */
	init_pbs(&e_pbs_cipher, e_pbs.cur, e_pbs.roof - e_pbs.cur, "cleartext");
	e_pbs_cipher.container = &e_pbs;
	e_pbs_cipher.desc = NULL;
	e_pbs_cipher.cur = e_pbs.cur;
	encstart = e_pbs_cipher.cur;
	
	/* decide to send CERT payload before we generate IDr */
	send_cert = doi_send_ikev2_cert_thinking(st);
	    
	/* send out the IDr payload */
	{
	    struct ikev2_id r_id;
	    pb_stream r_id_pbs;
	    chunk_t id_b;
	    struct hmac_ctx id_ctx;
	    unsigned char *id_start;
	    unsigned int   id_len;
	    
	    hmac_init_chunk(&id_ctx, st->st_oakley.integ_hasher
			    , st->st_skey_pr);
	    build_id_payload((struct isakmp_ipsec_id *)&r_id, &id_b,
			     &c->spd.this);
	    r_id.isai_critical = ISAKMP_PAYLOAD_CRITICAL;

	    if(send_cert) 
		r_id.isai_np = ISAKMP_NEXT_v2CERT;
	    else  
		r_id.isai_np = ISAKMP_NEXT_v2AUTH; 

	    id_start = e_pbs_cipher.cur;
	    
	    if (!out_struct(&r_id
			    , &ikev2_id_desc
			    , &e_pbs_cipher
			    , &r_id_pbs)
		|| !out_chunk(id_b, &r_id_pbs, "my identity"))
		return STF_INTERNAL_ERROR;
	    close_output_pbs(&r_id_pbs);

	    id_start += 4;

	    /* calculate hash of IDi for AUTH below */
	    id_len = e_pbs_cipher.cur - id_start;
	    DBG(DBG_CRYPT, DBG_dump_chunk("idhash calc pr", st->st_skey_pr));
	    DBG(DBG_CRYPT, DBG_dump("idhash calc R2",id_start, id_len));
	    hmac_update(&id_ctx, id_start, id_len);
	    idhash_out = alloca(st->st_oakley.integ_hasher->hash_digest_len);
	    hmac_final(idhash_out, &id_ctx);
	}

	DBG(DBG_CONTROLMORE
	    , DBG_log("assembled IDr payload -- CERT next"));	  

	/* send CERT payload RFC 4306 3.6, 1.2:([CERT,] ) */
	if(send_cert) {
	    stf_status certstat = ikev2_send_cert(st, md
						  , RESPONDER
						  , ISAKMP_NEXT_v2AUTH
						  , &e_pbs_cipher);
	    if(certstat != STF_OK) return certstat;
    	} 

	/* authentication good, see if there is a child SA available */
	if(md->chain[ISAKMP_NEXT_v2SA] == NULL
	   || md->chain[ISAKMP_NEXT_v2TSi] == NULL
	   || md->chain[ISAKMP_NEXT_v2TSr] == NULL) {
	    
	    /* initiator didn't propose anything. Weird. Try unpending out end. */
	    /* UNPEND XXX */
	    np = ISAKMP_NEXT_NONE;
	} else {
	    np = ISAKMP_NEXT_v2SA;
	}

	DBG(DBG_CONTROLMORE
	    , DBG_log("going to assemble AUTH payload"));	  

	/* now send AUTH payload */
	{
	    stf_status authstat = ikev2_send_auth(c, st
						  , RESPONDER, np
						  , idhash_out, &e_pbs_cipher);
	    if(authstat != STF_OK) return authstat;
	}

	if(np == ISAKMP_NEXT_v2SA) {
	    /* must have enough to build an CHILD_SA */
	    ret = ikev2_child_sa_respond(md, RESPONDER, &e_pbs_cipher);
	    if(ret != STF_OK) return ret;
	}

	ikev2_padup_pre_encrypt(md, &e_pbs_cipher);
	close_output_pbs(&e_pbs_cipher);

	{
	    unsigned char *authloc = ikev2_authloc(md, &e_pbs);

	    if(authloc == NULL) return STF_INTERNAL_ERROR;

	    close_output_pbs(&e_pbs);

	    close_output_pbs(&md->rbody);
	    close_output_pbs(&md->reply);

	    ret = ikev2_encrypt_msg(md, RESPONDER,
				    authstart, 
				    iv, encstart, authloc, 
				    &e_pbs, &e_pbs_cipher);
	    if(ret != STF_OK) return ret;
	}
    }


    /* let TCL hack it before we mark the length. */
    TCLCALLOUT("v2_avoidEmitting", st, st->st_connection, md);

    /* keep it for a retransmit if necessary */
    clonetochunk(st->st_tpacket, md->reply.start, pbs_offset(&md->reply)
		 , "reply packet for ikev2_parent_outI1");

    /* note: retransimission is driven by initiator */

    return STF_OK;
    
}

/*
 *
 ***************************************************************
 *                       PARENT_inR2    (I3 state)         *****
 ***************************************************************
 *  - there are no cryptographic continuations, but be certain
 *    that there will have to be DNS continuations, but they
 *    just aren't implemented yet.
 *
 */
stf_status ikev2parent_inR2(struct msg_digest *md)
{
    struct state *st = md->st;
    struct connection *c = st->st_connection;
    unsigned char *idhash_in;
    struct state *pst = st;

    if(st->st_clonedfrom != 0) {
	pst = state_with_serialno(st->st_clonedfrom);
    }

    /*
     * the initiator sent us an encrypted payload. We need to calculate
     * our g^xy, and skeyseed values, and then decrypt the payload.
     */

    DBG(DBG_CONTROLMORE
	, DBG_log("ikev2 parent inR2: calculating g^{xy} in order to decrypt I2"));

    /* verify that there is in fact an encrypted payload */
    if(!md->chain[ISAKMP_NEXT_v2E]) {
	openswan_log("R2 state should receive an encrypted payload");
	return STF_FATAL;
    }

    /* decrypt things. */
    {
	stf_status ret; 
	ret = ikev2_decrypt_msg(md, INITIATOR);
	if(ret != STF_OK) return ret;
    }

    if(!ikev2_decode_peer_id(md, INITIATOR)) {
	return STF_FAIL + INVALID_ID_INFORMATION;
    }

    {
	struct hmac_ctx id_ctx;
	const pb_stream *id_pbs = &md->chain[ISAKMP_NEXT_v2IDr]->pbs;
	unsigned char *idstart=id_pbs->start + 4;
	unsigned int   idlen  =pbs_room(id_pbs)-4;

	hmac_init_chunk(&id_ctx, pst->st_oakley.integ_hasher, pst->st_skey_pr);

	/* calculate hash of IDr for AUTH below */
	DBG(DBG_CRYPT, DBG_dump_chunk("idhash verify pr", pst->st_skey_pr));
	DBG(DBG_CRYPT, DBG_dump("idhash auth R2", idstart, idlen));
	hmac_update(&id_ctx, idstart, idlen);
	idhash_in = alloca(pst->st_oakley.integ_hasher->hash_digest_len);
	hmac_final(idhash_in, &id_ctx);
    }

    if(md->chain[ISAKMP_NEXT_v2CERT]) {
	/* should we check if we should accept a cert payload ?
	 *  has_preloaded_public_key(st)
	 */ 
	/* in v1 code it is  decode_cert(struct msg_digest *md) */
	DBG(DBG_CONTROLMORE
	    , DBG_log("has a v2_CERT payload going to decode it"));	  
	ikev2_decode_cert(md); 
    }

    /* process AUTH payload */
    if(!md->chain[ISAKMP_NEXT_v2AUTH]) {
	openswan_log("no authentication payload found");
	return STF_FAIL;
    }

    /* now check signature from RSA key */
    switch(md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type)
    {
    case v2_AUTH_RSA:
    {
	stf_status authstat = ikev2_verify_rsa_sha1(pst
						    , INITIATOR
						    , idhash_in
						    , NULL /* keys from DNS */
						    , NULL /* gateways from DNS */
						    , &md->chain[ISAKMP_NEXT_v2AUTH]->pbs);
	if(authstat != STF_OK) {
	    openswan_log("authentication failed");
	    SEND_NOTIFICATION(AUTHENTICATION_FAILED);
	    return STF_FAIL;
	}
	break;
    }
    case v2_AUTH_SHARED:
    {
	stf_status authstat = ikev2_verify_psk_auth(pst
						    , INITIATOR 
						    , idhash_in
						    , &md->chain[ISAKMP_NEXT_v2AUTH]->pbs);
	if(authstat != STF_OK) {
	    openswan_log("PSK authentication failed");
	    SEND_NOTIFICATION(AUTHENTICATION_FAILED);
	    return STF_FAIL;
	}
	break;
    }
    
    default:
	openswan_log("authentication method: %s not supported"
		     , enum_name(&ikev2_auth_names
				 ,md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type));
	return STF_FAIL;
    }

    /*
     * update the parent state to make sure that it knows we have
     * authenticated properly.
     */
    pst->st_state = STATE_PARENT_I3;
    c->newest_isakmp_sa = pst->st_serialno;
    
    /* authentication good, see if there is a child SA available */
    if(md->chain[ISAKMP_NEXT_v2SA] == NULL
	|| md->chain[ISAKMP_NEXT_v2TSi] == NULL
	|| md->chain[ISAKMP_NEXT_v2TSr] == NULL) {
	/* not really anything to here... but it would be worth unpending again */
	return STF_OK;
    }

    {
	notification_t rn;
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
	
	rn = ikev2_parse_child_sa_body(&sa_pd->pbs, &sa_pd->payload.v2sa,
				       NULL, st, FALSE);
	
	if(rn != NOTHING_WRONG)
	    return STF_FAIL + rn;
    }
	
    ikev2_derive_child_keys(st, md->role);

    c->newest_ipsec_sa = st->st_serialno;

    /* now install child SAs */
    if(!install_ipsec_sa(st, TRUE))
	return STF_FATAL;

    return STF_OK;
    
}

/*
 * Cookie = <VersionIDofSecret> | Hash(Ni | IPi | SPIi | <secret>)
 * where <secret> is a randomly generated secret known only to the
 * in OSW implementation <VersionIDofSecret> is not used.
 */
static bool ikev2_get_dcookie(u_char *dcookie,  chunk_t st_ni
	,ip_address *addr, u_int8_t *spiI)
{
    	size_t addr_length;
	SHA1_CTX	ctx_sha1;
	unsigned char addr_buff[
		sizeof(union {struct in_addr A; struct in6_addr B;})];
	

	addr_length = addrbytesof(addr, addr_buff, sizeof(addr_buff));
	SHA1Init(&ctx_sha1);
	SHA1Update(&ctx_sha1, st_ni.ptr, st_ni.len);
	SHA1Update(&ctx_sha1, addr_buff, addr_length);
	SHA1Update(&ctx_sha1, spiI, sizeof(spiI));
	SHA1Update(&ctx_sha1, ikev2_secret_of_the_day
		 , SHA1_DIGEST_SIZE);
	SHA1Final(dcookie, &ctx_sha1);
	DBG(DBG_PRIVATE
		,DBG_log("ikev2 secret_of_the_day used %s, length %d"
							               , ikev2_secret_of_the_day 
										   , SHA1_DIGEST_SIZE););

	DBG(DBG_CRYPT
		,DBG_dump("computed dcookie: HASH(Ni | IPi | SPIi | <secret>)"
				, dcookie, SHA1_DIGEST_SIZE));
#if 0
	ikev2_secrets_recycle++;
	if(ikev2_secrets_recycle >= 32768) {
		/* handed out too many cookies, cycle secrets */
		ikev2_secrets_recycle = 0;
		/* can we call init_secrets() without adding an EVENT? */
		init_secrets();
	}
#endif
	return TRUE;
}

/*
 *
 ***************************************************************
 *                       NOTIFICATION_OUT Complete packet  *****
 ***************************************************************
 *
 */

void
send_v2_notification(struct state *p1st, u_int16_t type
		     , struct state *encst
		     , u_char *icookie 
		     , u_char *rcookie 
		     , chunk_t *n_data)
{
    u_char buffer[1024];
    pb_stream reply;
    pb_stream rbody;
	/* this function is not generic enough yet just enough for 6msg 
	 * TBD accept HDR FLAGS as arg. default ISAKMP_FLAGS_R
	 * TBD when there is a child SA use that SPI in the notify paylod.
	 * TBD support encrypted notifications payloads.
	 * TBD accept Critical bit as an argument. default is set.
	 * TBD accept exchange type as an arg, default is ISAKMP_v2_SA_INIT
	 * do we need to send a notify with empty data?
	 * do we need to support more Protocol ID? more than PROTO_ISAKMP
	 */

    openswan_log("sending %snotification %s to %s:%u"
		 , encst ? "encrypted " : ""
		 , enum_name(&ikev2_notify_names, type)
		 , ip_str(&p1st->st_remoteaddr)
		 , p1st->st_remoteport);
    if(n_data == NULL) { 
    DBG(DBG_CONTROLMORE
    	,DBG_log("don't send packet when notification data empty"));  
		return; 
	}

    memset(buffer, 0, sizeof(buffer));
    init_pbs(&reply, buffer, sizeof(buffer), "notification msg");

    /* HDR out */
    {
	struct isakmp_hdr n_hdr ;
	zero(&n_hdr);     /* default to 0 */  /* AAA should we copy from MD? */
	n_hdr.isa_version = IKEv2_MAJOR_VERSION << ISA_MAJ_SHIFT | IKEv2_MINOR_VERSION;
	memcpy(n_hdr.isa_rcookie, rcookie, COOKIE_SIZE);
	memcpy(n_hdr.isa_icookie, icookie, COOKIE_SIZE);
	n_hdr.isa_xchg = ISAKMP_v2_SA_INIT;  
	n_hdr.isa_np = ISAKMP_NEXT_v2N;
	n_hdr.isa_flags &= ~ISAKMP_FLAGS_I;
	n_hdr.isa_flags  |=  ISAKMP_FLAGS_R;
	if (!out_struct(&n_hdr, &isakmp_hdr_desc, &reply, &rbody)) 
	{
    	    openswan_log("error initializing hdr for notify message");
	    return;
	}
		
    } 
	chunk_t child_spi;
	child_spi.ptr = NULL;
	child_spi.len = 0;

	/* build and add v2N payload to the packet */
	ship_v2N (ISAKMP_NEXT_NONE, ISAKMP_PAYLOAD_CRITICAL, PROTO_ISAKMP,
				    &child_spi, 
					type, n_data, &rbody);

   close_message(&rbody);
   close_output_pbs(&reply); 

   clonetochunk(p1st->st_tpacket, reply.start, pbs_offset(&reply)
		                    , "notification packet");

   send_packet(p1st, __FUNCTION__, TRUE);
}
/* add notify payload to the rbody */
bool ship_v2N (unsigned int np, u_int8_t  critical,
				    u_int8_t protoid, chunk_t *spi, 
					u_int16_t type, chunk_t *n_data, pb_stream *rbody)
{
	DBG(DBG_CONTROLMORE
   		,DBG_log("Adding a v2N Payload"));  
   	struct ikev2_notify n;
   	pb_stream n_pbs;
   	n.isan_np =  np;
   	n.isan_critical = critical;
   	n.isan_protoid =  protoid;
   	n.isan_spisize = spi->len;
   	n.isan_type = type;

    if (!out_struct(&n, &ikev2_notify_desc, rbody, &n_pbs))
    {
		openswan_log("error initializing notify payload for notify message");
   		return FALSE;
    }
	
	if(spi->len > 0)
	{
   		if (!out_raw(spi->ptr, spi->len, &n_pbs, "SPI "))
   		{
			openswan_log("error writing SPI to notify payload");
   			return FALSE;

   		}
    }
   	if (!out_raw(n_data->ptr, n_data->len, &n_pbs, "Notifiy data"))
   	{
		openswan_log("error writing notify payload for notify message");
   		return FALSE;
    }
    close_output_pbs(&n_pbs);
	return TRUE;
}
	     

/*
 *
 ***************************************************************
 *                       DELETE_OUT                        *****
 ***************************************************************
 *
 */
void ikev2_delete_out(struct state *st UNUSED)
{
    /* XXX */
}


/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
 
