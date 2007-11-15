/* demultiplex incoming IKE messages
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openswan.h>

#include "sysdep.h"
#include "constants.h"
#include "oswlog.h"

#include "defs.h"
#include "cookie.h"
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
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "ike_alg.h"
#include "log.h"
#include "demux.h"	/* needs packet.h */
#include "ikev2.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "timer.h"
#include "whack.h"	/* requires connections.h */
#include "server.h"
#ifdef XAUTH
#include "xauth.h"
#endif
#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif
#include "vendor.h"
#include "dpd.h"
#include "udpfromto.h"
#include "tpm/tpm.h"

struct state_v2_microcode {
    enum state_kind state, next_state;
    enum isakmp_xchg_types recv_type;
    lset_t flags;
    lset_t req_payloads;	/* required payloads (allows just one) */
    lset_t opt_payloads;	/* optional payloads (any mumber) */
    enum event_type timeout_event;
    state_transition_fn *processor;
};

enum smf2_flags {
    SMF2_INITIATOR = LELEM(1),
    SMF2_RESPONDER = 0,
    
    SMF2_STATENEEDED=LELEM(2),
    SMF2_NEWSTATE  = 0,

    SMF2_REPLY     = LELEM(3),
};

/*
 * IKEv2 has slightly different states than IKEv1.
 *
 * IKEv2 puts all the responsability for retransmission on the end that
 * wants to do something, usually, that the initiator. (But, not always
 * the original initiator, of the responder decides it needs to rekey first)
 *
 * Each exchange has a bit that indicates if it's a Initiator message,
 * or if it's a response.  The responder never retransmits it's messages
 * except because the initiator has retransmitted.
 *
 * The message ID is *NOT* used in the cryptographic state at all, but instead
 * serves the role of a sequence number.  This makes the state machine far
 * simpler, and there really are no exceptions.
 * 
 * The upper level state machine is therefore much simpler.
 * The lower level takes care of retransmissions, and the upper layer state
 * machine just has to worry about whether it needs to go into cookie mode,
 * etc.
 * 
 * Like IKEv1, IKEv2 can have multiple child SAs.  Like IKEv1, each one of
 * the child SAs ("Phase 2") will get their own state. Unlikely IKEv2,
 * an implementation may negotiate multiple CHILD_SAs at the same time
 * using different MessageIDs.  This is enabled by an option (a notify)
 * that the responder sends to the initiator.  The initiator may only
 * do concurrent negotiations if it sees the notify.
 *
 * XXX This implementation does not support concurrency, but it shouldn't be
 *     that hard to do.  The most difficult part will be to map the message IDs
 *     to the right state. Some CHILD_SAs may take multiple round trips,
 *     and each one will have to be mapped to the same state.
 *
 * The IKEv2 state values are chosen from the same state space as IKEv1.
 *
 */

/* it is not clear how the flags will be used yet, if at all */

static const struct state_v2_microcode state_microcode_table[] = {
    { .state      = STATE_UNDEFINED,
      .next_state = STATE_PARENT_I1,
      .flags      = SMF2_INITIATOR,
      .processor  = NULL,
    },

    { .state      = STATE_PARENT_I1,
      .next_state = STATE_PARENT_I2,
      .flags = SMF2_INITIATOR|SMF2_STATENEEDED,
      .processor  = ikev2parent_inR1outI2,
      .recv_type  = ISAKMP_v2_SA_INIT,
    },

    { .state      = STATE_UNDEFINED,
      .next_state = STATE_PARENT_R1,
      .flags = SMF2_RESPONDER|SMF2_NEWSTATE|SMF2_REPLY,
      .processor  = ikev2parent_inI1outR1,
      .recv_type  = ISAKMP_v2_SA_INIT,
    },
	
    /* last entry */
    { .state      = STATE_IKEv2_ROOF }
};


const struct state_v2_microcode *ikev2_parent_firststate()
{
    return &state_microcode_table[0];
}


/*
 * process an input packet, possibly generating a reply.
 *
 * If all goes well, this routine eventually calls a state-specific
 * transition function.
 */
void
process_v2_packet(struct msg_digest **mdp)
{
    struct msg_digest *md = *mdp;
    struct state *st = NULL;
    enum state_kind from_state = STATE_UNDEFINED; /* state we started in */
    const struct state_v2_microcode *svm;
    enum isakmp_xchg_types ix;
    bool rcookiezero;

#define SEND_NOTIFICATION(t) abort()

    /* Look for an state which matches the various things we know */
    /*
     * 1) exchange type received?
     * 2) is it initiator or not?
     *
     */

    st = find_state_ikev2(md->hdr.isa_icookie, md->hdr.isa_rcookie);
    if(st == NULL) {
	st = find_state_ikev2(md->hdr.isa_icookie, zero_cookie);
	
	rcookiezero = is_zero_cookie(md->hdr.isa_rcookie);
	if(st && !rcookiezero) {
	    unhash_state(st);
	    memcpy(st->st_rcookie, md->hdr.isa_rcookie, COOKIE_SIZE);
	    insert_state(st);
	}
    }
	
    ix = md->hdr.isa_xchg;
    if(st) {
	from_state = st->st_state;
    }

    for(svm = state_microcode_table; svm->state != STATE_IKEv2_ROOF; svm++) {
	if(svm->flags & SMF2_STATENEEDED) {
	    if(st==NULL) continue;
	}
	if((svm->flags&SMF2_STATENEEDED)==0) {
	    if(st!=NULL) continue;
	}
	if(svm->state != from_state) continue;
	if(svm->recv_type != ix) continue;
	
	/* must be the right state */
	break;
    }

    if(svm->state == STATE_IKEv2_ROOF) {
	/* no useful state */
	if(md->hdr.isa_flags & ISAKMP_FLAGS_I) {
	    /* must be an initiator message, so we are the responder */

	    /* XXX need to be more specific */
	    SEND_NOTIFICATION(INVALID_MESSAGE);
	}
	return;
    }

    {
	struct payload_digest *pd = md->digest;
	volatile int np = md->hdr.isa_np;
	err_t excuse = "notsure";

	//lset_t needed = smc->req_payloads;

	while (np != ISAKMP_NEXT_NONE)
	{
	    struct_desc *sd = np < ISAKMP_NEXT_ROOF? payload_descs[np] : NULL;

	    if (pd == &md->digest[PAYLIMIT])
	    {
		loglog(RC_LOG_SERIOUS, "more than %d payloads in message; ignored", PAYLIMIT);
		SEND_NOTIFICATION(PAYLOAD_MALFORMED);
		return;
	    }

	    if (sd == NULL)
	    {
		loglog(RC_LOG_SERIOUS, "%smessage ignored because it contains an unknown or"
		       " unexpected payload type (%s) at the outermost level"
		       , excuse, enum_show(&payload_names, np));
		SEND_NOTIFICATION(INVALID_PAYLOAD_TYPE);
		return;
	    }

#if 0
	    {
		lset_t s = LELEM(np);

		if (LDISJOINT(s
			      , needed | smc->opt_payloads|
			      LELEM(ISAKMP_NEXT_VID) |
			      LELEM(ISAKMP_NEXT_N) | LELEM(ISAKMP_NEXT_D)))
		{
		    loglog(RC_LOG_SERIOUS, "%smessage ignored because it "
			   "contains an unexpected payload type (%s)"
			, excuse, enum_show(&payload_names, np));
		    SEND_NOTIFICATION(INVALID_PAYLOAD_TYPE);
		    return;
		}
		
		DBG(DBG_PARSING
		    , DBG_log("got payload 0x%qx(%s) needed: 0x%qx opt: 0x%qx"
			      , s, enum_show(&payload_names, np)
			      , needed, smc->opt_payloads));
		needed &= ~s;
	    }
#endif

	    if (!in_struct(&pd->payload, sd, &md->message_pbs, &pd->pbs))
	    {
		loglog(RC_LOG_SERIOUS, "%smalformed payload in packet", excuse);
		SEND_NOTIFICATION(PAYLOAD_MALFORMED);
		return;
	    }

	    DBG(DBG_PARSING
		, DBG_log("processing payload: %s (len=%u)\n"
			  , enum_show(&payload_names, np)
			  , pd->payload.generic.isag_length));

	    /* do payload-type specific debugging */
	    switch(np) {
	    default:   /* nothing special */
		break;
	    }

	    /* place this payload at the end of the chain for this type */
	    {
		struct payload_digest **p;

		for (p = &md->chain[np]; *p != NULL; p = &(*p)->next)
		    ;
		*p = pd;
		pd->next = NULL;
	    }

	    np = pd->payload.generic.isag_np;
	    pd++;
	}

	md->digest_roof = pd;

	DBG(DBG_PARSING,
	    if (pbs_left(&md->message_pbs) != 0)
		DBG_log("removing %d bytes of padding", (int) pbs_left(&md->message_pbs)));

	md->message_pbs.roof = md->message_pbs.cur;

#if 0
	/* check that all mandatory payloads appeared */
	if (needed != 0)
	{
	    loglog(RC_LOG_SERIOUS, "message for %s is missing payloads %s"
		, enum_show(&state_names, from_state)
		, bitnamesof(payload_name, needed));
	    SEND_NOTIFICATION(PAYLOAD_MALFORMED);
	    return;
	}
#endif
    }

    md->svm = svm;
    md->from_state = from_state;
    md->st  = st;

    {
	stf_status stf;
	stf = (svm->processor)(md);
	complete_v2_state_transition(mdp, stf);
    }
}

static void success_v2_state_transition(struct msg_digest **mdp)
{
    struct msg_digest *md = *mdp;
    const struct state_v2_microcode *svm = md->svm;
    enum state_kind from_state = md->from_state;
    struct state *st = md->st;

    openswan_log("transition from state %s to state %s"
                 , enum_name(&state_names, from_state)
                 , enum_name(&state_names, svm->next_state));
	    
    st->st_state = svm->next_state;
    
    /* Delete previous retransmission event.
     * New event will be scheduled below.
     */
    delete_event(st);

    /* free previous transmit packet */
    freeanychunk(st->st_tpacket);

    /* if requested, send the new reply packet */
    if (svm->flags & SMF2_REPLY)
    {
	char buf[ADDRTOT_BUF];

	if(nat_traversal_enabled) {
	    /* adjust our destination port if necessary */
	    nat_traversal_change_port_lookup(md, st);
	}
	
	DBG(DBG_CONTROL
	    , DBG_log("sending reply packet to %s:%u (from port %u)"
		      , (addrtot(&st->st_remoteaddr
				 , 0, buf, sizeof(buf)), buf)
		      , st->st_remoteport
		      , st->st_interface->port));

	close_output_pbs(&md->reply);   /* good form, but actually a no-op */

	clonetochunk(st->st_tpacket, md->reply.start
		     , pbs_offset(&md->reply), "reply packet");

	/* actually send the packet
	 * Note: this is a great place to implement "impairments"
	 * for testing purposes.  Suppress or duplicate the
	 * send_packet call depending on st->st_state.
	 */

	TCLCALLOUT("avoidEmitting", st, st->st_connection, md);
	send_packet(st, enum_name(&state_names, from_state), TRUE);
    }

    TCLCALLOUT("adjustTimers", st, st->st_connection, md);


}

void complete_v2_state_transition(struct msg_digest **mdp
				  , stf_status result)
{
    struct msg_digest *md = *mdp;
    //const struct state_v2_microcode *svm=md->svm;
    struct state *st;
    enum state_kind from_state;

    cur_state = st = md->st;	/* might have changed */

    from_state   = st->st_state;

    md->result = result;
    TCLCALLOUT("v2AdjustFailure", st, (st ? st->st_connection : NULL), md);
    result = md->result;

    /* advance the state */
    DBG(DBG_CONTROL
	, DBG_log("complete v2 state transition with %s"
		  , enum_name(&stfstatus_name, result)));

    switch(result) {
    case STF_IGNORE:
	break;

    case STF_INLINE:         /* this is second time through complete
			      * state transition, so the MD has already
			      * been freed.
			      0				  */
	*mdp = NULL;
	break;

    case STF_SUSPEND:
	/* update the previous packet history */
	/* IKEv2 XXX */ /* update_retransmit_history(st, md); */
	
	/* the stf didn't complete its job: don't relase md */
	*mdp = NULL;
	break;

    case STF_OK:
	/* advance the state */
	success_v2_state_transition(mdp);
	break;
	
    case STF_INTERNAL_ERROR:
	abort();
	break;

    case STF_TOOMUCHCRYPTO:
	/* well, this should never happen during a whack, since
	 * a whack will always force crypto.
	 */
	set_suspended(st, NULL);
	pexpect(st->st_calculating == FALSE);
	openswan_log("message in state %s ignored due to cryptographic overload"
		     , enum_name(&state_names, from_state));
	break;

    case STF_FATAL:
	/* update the previous packet history */
	/* update_retransmit_history(st, md); */

	whack_log(RC_FATAL
		  , "encountered fatal error in state %s"
		  , enum_name(&state_names, st->st_state));
	delete_event(st);
	release_pending_whacks(st, "fatal error");
	delete_state(st);
	break;

    default:	/* a shortcut to STF_FAIL, setting md->note */
	passert(result > STF_FAIL);
	md->note = result - STF_FAIL;
	result = STF_FAIL;
	/* FALL THROUGH ... */

    case STF_FAIL:
	whack_log(RC_NOTIFICATION + md->note
		  , "%s: %s", enum_name(&state_names, st->st_state)
		  , enum_name(&ipsec_notification_names, md->note));

#if 0
	if(md->note > 0) {
	    SEND_NOTIFICATION(md->note);
	}
#endif
	
	DBG(DBG_CONTROL,
	    DBG_log("state transition function for %s failed: %s"
		    , enum_name(&state_names, from_state)
		    , enum_name(&ipsec_notification_names, md->note)));
    }
}

notification_t
accept_v2_nonce(struct msg_digest *md, chunk_t *dest, const char *name)
{
    return accept_nonce(md, dest, name, ISAKMP_NEXT_v2Ni);
}



/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
