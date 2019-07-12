/* demultiplex incoming IKE messages
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2010  D. Hugh Redelmeier.
 * Copyright (C) 2007-2015 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Simon Deziel <simon@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2011-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <pwouters@redhat.com>
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
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "pluto/connections.h"	/* needs id.h */
#include "cookie.h"
#include "pluto/state.h"
#include "packet.h"
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "ike_alg.h"
#include "log.h"
#include "demux.h"	/* needs packet.h */
#include "ikev2.h"
#include "ikev2_microcode.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "timer.h"
#include "whack.h"	/* requires connections.h */
#include "pluto/server.h"
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

enum smf2_flags {
    SMF2_INITIATOR      = LELEM(1),
    SMF2_STATENEEDED    = LELEM(2),
    SMF2_REPLY          = LELEM(3),     // microcode processor will generate a reply
    SMF2_MATCH_REQUEST  = LELEM(4),     // microcode will only match incoming request messages
    SMF2_MATCH_RESPONSE = LELEM(5),     // microcode will only match incoming request messages
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
 * the child SAs ("Phase 2") will get their own state. Unlike IKEv1,
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

#define PT(n) ISAKMP_NEXT_v2 ## n
#define P(n) LELEM(PT(n) - ISAKMP_v2PAYLOAD_TYPE_BASE)
static const lset_t everywhere_payloads = P(N) | P(V); /* can appear in any packet */
static const lset_t repeatable_payloads = P(N) | P(D) | P(CP) | P(V);  /* if one can appear, many can appear */

/* microcode to parent first initiator state: not associated with an input packet */
const struct state_v2_microcode ikev2_parent_firststate_microcode =
    { .svm_name   = "first_state",
      .state      = STATE_UNDEFINED,
      .next_state = STATE_PARENT_I1,
      .flags      = SMF2_INITIATOR,
      .processor  = NULL,
};

/* microcode to parent first child rekey state: not associated with an input packet */
const struct state_v2_microcode ikev2_childrekey_microcode =
    { .svm_name   = "rekey-child",
      .state      = STATE_UNDEFINED,
      .next_state = STATE_CHILD_C1_REKEY,
      .flags      =  SMF2_INITIATOR,
      .processor  = NULL,
    };

/* microcode for input packet processing */
struct state_v2_microcode v2_state_microcode_table[] = {
    /* state 0 */
    { .svm_name   = "initiator-V2_init",
      .state      = STATE_PARENT_I1,
      .next_state = STATE_PARENT_I2,
      .flags      = SMF2_MATCH_RESPONSE|SMF2_INITIATOR|SMF2_STATENEEDED|SMF2_REPLY,
      .req_clear_payloads = P(SA) | P(KE) | P(Nr),
      .opt_clear_payloads = P(CERTREQ),
      .processor  = ikev2parent_inR1outI2,
      .recv_type  = ISAKMP_v2_SA_INIT,
    },

    /* state 1 */
    { .svm_name   = "initiator-failure",
      .state      = STATE_PARENT_I1,
      .next_state = STATE_IKESA_DEL,
      .flags      = SMF2_MATCH_RESPONSE|SMF2_STATENEEDED,
      .req_clear_payloads = P(N),
      .opt_clear_payloads = P(N),
      .processor  = ikev2parent_ntf_inR1,
      .recv_type  = ISAKMP_v2_SA_INIT,
    },

    /* state 2 */
    { .svm_name   = "initiator-auth-process",
      .state      = STATE_CHILD_C0_KEYING,
      .next_state = STATE_CHILD_C1_KEYED,
      .flags      = SMF2_MATCH_RESPONSE|SMF2_INITIATOR|SMF2_STATENEEDED,
      .req_clear_payloads = P(E),
      .req_enc_payloads = P(IDr) | P(AUTH) | P(SA) | P(TSi) | P(TSr),
      .opt_enc_payloads = P(CERT),
      .processor  = ikev2parent_inR2,
      .recv_type  = ISAKMP_v2_AUTH,
      .timeout_event = EVENT_SA_REPLACE,
    },

    /* state 3 */
    { .svm_name   = "responder-V2_init",
      .state      = STATE_UNDEFINED,
      .next_state = STATE_PARENT_R1,
      .flags      = SMF2_MATCH_REQUEST | /* not SMF2_INITIATOR, not SMF2_STATENEEDED */ SMF2_REPLY,
      .req_clear_payloads = P(SA) | P(KE) | P(Ni),
      .processor  = ikev2parent_inI1outR1,
      .recv_type  = ISAKMP_v2_SA_INIT,
    },

    /* state 4 */
    { .svm_name   = "responder-auth-process",
      .state      = STATE_PARENT_R1,
      .next_state = STATE_PARENT_R2,
      .flags      = SMF2_MATCH_REQUEST | /* not SMF2_INITIATOR */ SMF2_STATENEEDED | SMF2_REPLY,
      .req_clear_payloads = P(E),
      .req_enc_payloads = P(IDi) | P(AUTH) | P(SA) | P(TSi) | P(TSr),
      .opt_enc_payloads = P(CERT) | P(CERTREQ) | P(IDr),
      .processor  = ikev2parent_inI2outR2,
      .recv_type  = ISAKMP_v2_AUTH,
      .timeout_event = EVENT_SA_REPLACE,
    },

    /* state 5: empty */
    { .svm_name   = "none",
      .state      = STATE_CHILD_C1_REKEY,
      .next_state = STATE_CHILD_C1_KEYED,
      .flags      = SMF2_INITIATOR | SMF2_STATENEEDED,
      .req_clear_payloads = P(E),
      .req_enc_payloads = P(SA) | P(TSi) | P(TSr) | P(KE) | P(Nr),
      .opt_enc_payloads = 0,
      .processor  = NULL,
      .recv_type  = ISAKMP_v2_CHILD_SA,
      .timeout_event = EVENT_SA_REPLACE,
    },

    /* state 6 */
    { .svm_name   = "rekey-childSA-ack",
      .state      = STATE_CHILD_C1_REKEY,
      .next_state = STATE_CHILD_C1_KEYED,
      .flags      = SMF2_MATCH_RESPONSE | SMF2_INITIATOR | SMF2_STATENEEDED,
      .req_clear_payloads = P(E),
      .req_enc_payloads = P(SA) | P(TSi) | P(TSr) | P(Nr),
      .opt_enc_payloads = 0,
      .processor  = ikev2child_inCR1,
      .ntf_processor = ikev2child_inCR1_ntf,
      .recv_type  = ISAKMP_v2_CHILD_SA,
      .timeout_event = EVENT_SA_REPLACE,
    },

    /* state 7 */
    { .svm_name   = "rekey-child-SA-responder",
      .state      = STATE_PARENT_R2,
      .next_state = STATE_CHILD_C1_KEYED,
      .flags      = SMF2_MATCH_REQUEST | /* not SMF2_INITIATOR */ SMF2_STATENEEDED | SMF2_REPLY,
      .req_clear_payloads = P(E),
      .req_enc_payloads = P(SA) | P(TSi) | P(TSr) | P(Ni),
      .opt_enc_payloads = P(KE),
      .processor  = ikev2child_inCI1,
      .recv_type  = ISAKMP_v2_CHILD_SA,
      .timeout_event = EVENT_SA_REPLACE,
    },

    /* state 8 -- EMPTY for now*/
    { .svm_name   = "none",
      .state      = 0,
      .next_state = 0,
      .flags      = /* not SMF2_INITIATOR */ SMF2_STATENEEDED | SMF2_REPLY,
      .req_clear_payloads = 0,
      .req_enc_payloads = 0,
      .opt_enc_payloads = 0,
      .processor  = NULL,
      .recv_type  = ISAKMP_v2_CHILD_SA,
      .timeout_event = EVENT_NULL
    },


    /* state 9: Informational Exchange*/
    { .svm_name   = "initiator-insecure-informational",
      .state      = STATE_PARENT_I2,
      .next_state = STATE_PARENT_I2,
      .flags      = SMF2_STATENEEDED,
      .req_clear_payloads = P(E),
      .opt_enc_payloads = P(N) | P(D) | P(CP),
      .processor  = process_informational_ikev2,
      .recv_type  = ISAKMP_v2_INFORMATIONAL,
    },


    /* state 10: Informational Exchange*/
    { .svm_name   = "responder-insecure-informational",
      .state      = STATE_PARENT_R1,
      .next_state = STATE_PARENT_R1,
      .flags      = SMF2_STATENEEDED,
      .req_clear_payloads = P(E),
      .opt_enc_payloads = P(N) | P(D) | P(CP),
      .processor  = process_informational_ikev2,
      .recv_type  = ISAKMP_v2_INFORMATIONAL,
    },

    /* state 11: Informational Exchange*/
    { .svm_name   = "initiator-informational",
      .state      = STATE_PARENT_I3,
      .next_state = STATE_PARENT_I3,
      .flags      = SMF2_STATENEEDED,
      .req_clear_payloads = P(E),
      .opt_enc_payloads = P(N) | P(D) | P(CP),
      .processor  = process_informational_ikev2,
      .recv_type  = ISAKMP_v2_INFORMATIONAL,
    },

    /* state 12: Informational Exchange*/
    { .svm_name   = "responder-authenticated-informational",
      .state      = STATE_PARENT_R2,
      .next_state = STATE_PARENT_R2,
      .flags      = SMF2_STATENEEDED,
      .req_clear_payloads = P(E),
      .opt_enc_payloads = P(N) | P(D) | P(CP),
      .processor  = process_informational_ikev2,
      .recv_type  = ISAKMP_v2_INFORMATIONAL,
    },

    /* state 13: Informational Exchange*/
    { .svm_name   = "delete-ike-sa",
      .state      = STATE_IKESA_DEL,
      .next_state = STATE_IKESA_DEL,
      .flags      = SMF2_STATENEEDED,
      .req_clear_payloads = P(E),
      .opt_enc_payloads = P(N) | P(D) | P(CP),
      .processor  = process_informational_ikev2,
      .recv_type  = ISAKMP_v2_INFORMATIONAL,
    },

    /* state 14 */
    { .svm_name   = "rekey-child-SA-initiator",
      .state      = STATE_PARENT_I3,
      .next_state = STATE_CHILD_C1_KEYED,
      .flags      = SMF2_MATCH_REQUEST | SMF2_INITIATOR | SMF2_STATENEEDED | SMF2_REPLY,
      .req_clear_payloads = P(E),
      .req_enc_payloads = P(SA) | P(TSi) | P(TSr) | P(Ni),
      .opt_enc_payloads = P(KE),
      .processor  = ikev2child_inI3,
      .recv_type  = ISAKMP_v2_CHILD_SA,
      .timeout_event = EVENT_SA_REPLACE,
    },

    /* state 15 */
    { .svm_name   = "delete-child-SA-req",
      .state      = STATE_CHILD_C1_KEYED,
      .next_state = STATE_CHILDSA_DEL,
      .flags      = SMF2_STATENEEDED | SMF2_REPLY,
      .req_clear_payloads = P(E),
      .opt_enc_payloads = P(N) | P(D),
      .processor  =  process_informational_ikev2,
      .recv_type  = ISAKMP_v2_INFORMATIONAL,
      .timeout_event = EVENT_NULL
    },

    /* state 16 */
    { .svm_name   = "delete-child-SA-ack",
      .state      = STATE_CHILDSA_DEL,
      .next_state = STATE_CHILDSA_DEL,
      .flags      =  SMF2_INITIATOR | SMF2_STATENEEDED | SMF2_REPLY,
      .req_clear_payloads = P(E),
      .opt_enc_payloads = P(N) | P(D),
      .processor  = process_informational_ikev2,
      .recv_type  = ISAKMP_v2_INFORMATIONAL,
      .timeout_event = EVENT_NULL,
    },

    /* state 17 */
    { .svm_name   = "rekey-child-SA-initiator-2",
      .state      = STATE_CHILD_C1_KEYED,
      .next_state = STATE_CHILD_C1_KEYED,
      .flags      = SMF2_MATCH_REQUEST | SMF2_INITIATOR | SMF2_STATENEEDED | SMF2_REPLY,
      .req_clear_payloads = P(E),
      .req_enc_payloads = P(SA) | P(TSi) | P(TSr) | P(Ni),
      .opt_enc_payloads = P(KE),
      .processor  = ikev2child_inI3,
      .recv_type  = ISAKMP_v2_CHILD_SA,
      .timeout_event = EVENT_SA_REPLACE,
    },

    /* state 18 */
    { .svm_name   = "initiator-auth-failure",
      .state      = STATE_CHILD_C0_KEYING,
      .next_state = STATE_IKESA_DEL,
      .flags      = SMF2_MATCH_RESPONSE | SMF2_STATENEEDED,
      .req_clear_payloads = P(N),
      .opt_clear_payloads = P(N),
      .processor  = ikev2parent_ntf_inR2,
      .recv_type  = ISAKMP_v2_AUTH,
    },

    /* state 19 */
    { .svm_name   = "rekey-childSA-ack-R2",
      .state      = STATE_PARENT_R2,
      .next_state = STATE_CHILD_C1_KEYED,
      .flags      = SMF2_MATCH_RESPONSE | /* not SMF2_INITIATOR */ SMF2_STATENEEDED,
      .req_clear_payloads = P(E),
      .req_enc_payloads = P(SA) | P(TSi) | P(TSr) | P(Nr),
      .opt_enc_payloads = 0,
      .processor  = ikev2child_inCR1,
      .ntf_processor = ikev2child_inCR1_ntf,
      .recv_type  = ISAKMP_v2_CHILD_SA,
      .timeout_event = EVENT_SA_REPLACE,
    },

    /* state 20: Informational Response */
    { .svm_name   = "deleting-ack",
      .state      = STATE_DELETING,
      .next_state = STATE_PARENT_R2,
      /* TODO: we should use flags|=SMF2_REPLY here, and remove send_packet
       *       from process_informational_ikev2() */
      .flags      = SMF2_MATCH_RESPONSE | SMF2_STATENEEDED,
      .req_clear_payloads = P(E),
      .opt_enc_payloads = P(N) | P(D) | P(CP),
      .processor  = process_informational_ikev2,
      .recv_type  = ISAKMP_v2_INFORMATIONAL,
    },

    /* last entry */
    { .svm_name   = "invalid-transition",
      .state      = STATE_IKEv2_ROOF }
};

#undef P
#undef PT

/*
 * split up an incoming message into payloads
 */
static stf_status
ikev2_collect_payloads(struct msg_digest *md,
                       pb_stream    *in_pbs,
                       lset_t       *seen_payloads, /* results */
                       unsigned int np)
{
    struct payload_digest *pd = md->digest_roof;
    lset_t seen = LEMPTY;

    while (np != ISAKMP_NEXT_NONE)
    {
        struct_desc *sd = payload_desc(np);
	memset(pd, 0, sizeof(*pd));

	if (pd == &md->digest[PAYLIMIT])
	{
	    loglog(RC_LOG_SERIOUS, "more than %d payloads in message; ignored", PAYLIMIT);
            return STF_FAIL + v2N_INVALID_SYNTAX;
	}

        if (sd == NULL || np < ISAKMP_v2PAYLOAD_TYPE_BASE) {
            /* This payload is unknown to us.
             * RFCs 4306 and 5996 2.5 say that if the payload
             * has the Critical Bit, we should be upset
             * but if it does not, we should just ignore it.
             */

            if (!in_struct(&pd->payload, &ikev2_generic_desc, in_pbs, &pd->pbs)) {
                loglog(RC_LOG_SERIOUS, "malformed payload in packet");
                return STF_FAIL + v2N_INVALID_SYNTAX;
            }

            if (pd->payload.v2gen.isag_critical & ISAKMP_PAYLOAD_CRITICAL) {
                /* It was critical.
                 * See RFC 5996 1.5 "Version Numbers and Forward Compatibility"
                 * ??? we are supposed to send the offending np byte
                 * back in the notify payload.
                 */
                loglog(RC_LOG_SERIOUS,
                       "critical payload (%s) was not understood. Message dropped.",
                       enum_show(&payload_names_ikev2, np));
                return STF_FAIL + v2N_UNSUPPORTED_CRITICAL_PAYLOAD;
            }

            loglog(RC_COMMENT, "non-critical payload ignored because it contains an unknown or"
                   " unexpected payload type (%s) at the outermost level",
                   enum_show(&payload_names_ikev2, np));
            np = pd->payload.generic.isag_np;
            continue;
	}

        passert(np - ISAKMP_v2PAYLOAD_TYPE_BASE < LELEM_ROOF);

        {
            lset_t s = LELEM(np - ISAKMP_v2PAYLOAD_TYPE_BASE);
            if (s & seen & ~repeatable_payloads) {
                /* improperly repeated payload */
                loglog(RC_LOG_SERIOUS,
                       "payload (%s) unexpectedly repeated. Message dropped.",
                       enum_show(&payload_names_ikev2, np));
                return STF_FAIL + v2N_INVALID_SYNTAX;
            }

            /* mark this payload as seen */
            seen |= s;
	}

	if (!in_struct(&pd->payload, sd, in_pbs, &pd->pbs))
            {
                loglog(RC_LOG_SERIOUS, "malformed payload in packet");
                return STF_FAIL + v2N_INVALID_SYNTAX;
            }


	DBG(DBG_PARSING
	    , DBG_log("processing payload: %s (len=%u)\n"
                      , enum_show(&payload_names, np)
		      , pd->payload.generic.isag_length));

	/* place this payload at the end of the chain for this type */
	{
	    struct payload_digest **p;

            for (p = &md->chain[np]; *p != NULL; p = &(*p)->next)
		;
	    *p = pd;
	    pd->next = NULL;
	}

        switch(np) {
	case ISAKMP_NEXT_v2E:
	    np = ISAKMP_NEXT_NONE;
	    break;
        default:
            np = pd->payload.generic.isag_np;
	    break;
	}

	pd++;
    }
    *seen_payloads  = seen;
    md->digest_roof = pd;
    return STF_OK;
}


/*
 * see see if collected payloads match required ones
 */
static stf_status
ikev2_process_payloads(struct msg_digest *md UNUSED,
                       lset_t seen,
                       lset_t req_payloads,
                       lset_t opt_payloads)
{
    lset_t extra_payloads;

    if (req_payloads & ~seen) {
        /* improperly repeated payload */
        loglog(RC_LOG_SERIOUS,
               "missing payload(s) (%s). Message dropped.",
               bitnamesof(payload_name_ikev2_main, req_payloads & ~seen));
        return STF_FAIL + v2N_INVALID_SYNTAX;
    }

    extra_payloads = (seen & ~(req_payloads | opt_payloads | everywhere_payloads));
    if(extra_payloads!=LEMPTY) {
        /* unexpected payload */
        loglog(RC_LOG_SERIOUS,
               "payload (%s) unexpected. Message dropped.",
               bitnamesof(payload_name_ikev2_main, extra_payloads));

        return STF_FAIL + v2N_INVALID_SYNTAX;
    }
    return STF_OK;
}

/* this stub is needed because struct state_v2_microcode is local to this file */
stf_status ikev2_process_encrypted_payloads(struct msg_digest *md,
            pb_stream   *in_pbs,
            unsigned int np)
{
    stf_status stf;
    lset_t seen = LEMPTY;
    const struct state_v2_microcode *svm = md->svm;
    stf = ikev2_collect_payloads(md, in_pbs, &seen, np);

    /* decryption error, stop now */
    if(stf != STF_OK)
        return stf;

    if (svm->req_enc_payloads & ~seen) {
        /* missing payloads in encryption part */

        if (md->chain[ISAKMP_NEXT_v2N] && svm->ntf_processor) {
            /* we had en encrypted notification, and there is
             * a handler set to process the notification */

            DBG(DBG_CONTROL, DBG_log(
                    "missing payloads (within encryption) for v2_state: %s. "
                    "Handling encrypted notification.", svm->svm_name));

            stf = (svm->ntf_processor)(md);

            /* we have to return an error to let the caller know that something
             * went wrong */
            if (stf == STF_OK) {
                DBG(DBG_CONTROL, DBG_log(
                        "notification handler returned OK; "
                        "maybe FAIL/STOLEN/IGNORE is more appropriate"));

                stf = STF_FAIL; /* XXX or STF_IGNORE or STF_STOLEN XXX */
            }

        } else {
            /* we have no other recourse, but to drop the packet */

            loglog(RC_LOG_SERIOUS,
                   "missing payloads (within encryption) for v2_state: %s: %s. "
                   "Message dropped."
                   , svm->svm_name
                   , bitnamesof(payload_name_ikev2_main
                                , svm->req_enc_payloads & ~seen));
            return STF_FAIL + v2N_INVALID_SYNTAX;
        }
    }
    return stf;
}

/* allocate_msgid_from_parent takes two stats, a parent (pst) and a child state.
 *
 * As all retransmissions are in some sense managed by the parent (because that is where
 * the msgid window and retransmitters are), the parent must multiplex between different
 * CHILD SAs that want to use the state.
 *
 * Since Openswan only supports a window of 1, only one message may be outstanding, any
 * subsequent users of the state must therefore wait for the parent to be available.
 * Even once windowed IKEv2 is implemented, that won't change things because there may be
 * more children than available windows.  (Of course, you can negotiate multiple SAs
 * in a single exchange, but that is going to be very difficult to architect)
 *
 * return STF_SUSPEND if the window will not let the child negotiate now.
 * nothing is done in that case, the state has to be retried later.
 *
 * note that this is not related to IKEv1's reserve msgid, although conceptually there
 * are similarities.
 *
 */
stf_status allocate_msgid_from_parent(struct state *pst, msgid_t *newid_p)
{
    msgid_t msgid = pst->st_msgid_nextuse;

    /* XXX haha, you thought fun things were going to happen in this routine..
     * but not yet.. takes some unit testing. */
    if(newid_p) {
        *newid_p = msgid;
        pst->st_msgid_nextuse++;
    }
    return STF_OK;
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
    struct state *st  = NULL;
    struct state *pst = NULL;
    enum state_kind from_state = STATE_UNDEFINED; /* state we started in */
    const struct state_v2_microcode *svm;
    enum isakmp_xchg_types ike_xchg_type;
    unsigned int svm_num;
    lset_t seen = LEMPTY;
    int ret;

    /* Look for an state which matches the various things we know */
    /*
     * 1) exchange type received?
     * 2) is it initiator or not?
     *
     */

    /* NOTE: in_struct() did not change the byte order, so make a copy in local order */
    md->msgid_received = ntohl(md->hdr.isa_msgid);

    if(IKEv2_ORIGINAL_INITIATOR(md->hdr.isa_flags)) {
        /* message from the original initiator, that makes me the original responder */
	DBG(DBG_CONTROL, DBG_log("I am the IKE SA Responder"));
    } else {
        /* message from the original responder, that makes me the original initiator */
	DBG(DBG_CONTROL, DBG_log("I am the IKE SA Initiator"));
    }

    if(IKEv2_MSG_FROM_INITIATOR(md->hdr.isa_flags)) {
	/* then I am the responder, to this request */

	md->role = RESPONDER;

	DBG(DBG_CONTROL, DBG_log("I am this exchange's Responder"));

        st = find_state_ikev2_child(md->hdr.isa_icookie
                                    , md->hdr.isa_rcookie
                                    , md->msgid_received);

	if(st == NULL && md->msgid_received == MAINMODE_MSGID) {
	    /* first time for this cookie, it's a new state! */
	    st = find_state_ikev2_parent_init(md->hdr.isa_icookie);

	} else if(st == NULL && md->msgid_received != MAINMODE_MSGID) {
	    /* first time for this message.  Could be a new child? */
            /* look up the parent state here */
            st = find_state_ikev2_parent(md->hdr.isa_icookie
                                         , md->hdr.isa_rcookie);
	}

        pst = st;
        if(st && st->st_clonedfrom) {
            /* find parent state for retransmission counters */
            pst = state_with_serialno(st->st_clonedfrom);
        }

	if(pst) {
	    if(pst->st_msgid_lastrecv != INVALID_MSGID
	       && pst->st_msgid_lastrecv >  md->msgid_received){
		/* this is an OLD retransmit. we can't do anything */
		openswan_log("received too old retransmit: %u < %u"
			     , md->msgid_received, pst->st_msgid_lastrecv);
		return;
	    }
	    if(pst->st_msgid_lastrecv != INVALID_MSGID
	       && pst->st_msgid_lastrecv == md->msgid_received){
		/* this is a recent retransmit, resend our reply */
                /* is it ever the case that *st* is the wrong child? No, looked it up by msgid */
		send_packet(st, "ikev2-responder-retransmit", FALSE);
		return;
            }
            /* this must be a packet that is newer, so we process it */
	    /* we will update lastrecv later on, after we do crypto */
	}

    } else {
        /* then I am the initiator, and this is a reply */

	md->role = INITIATOR;

	DBG(DBG_CONTROL, DBG_log("I am this exchange's Initiator"));

	st = find_state_ikev2_child(md->hdr.isa_icookie
				    , md->hdr.isa_rcookie
				    , md->msgid_received);
	if (!st) {
            /* try again, as parent state */
            st = find_state_ikev2_parent(md->hdr.isa_icookie
                                         , md->hdr.isa_rcookie);
	}
        if (!st) {
            /* last attempt, parent, with zero cookie */
            st = find_state_ikev2_parent(md->hdr.isa_icookie, zero_cookie);
            if(st) {
                /* responder inserted its cookie, record it */
                unhash_state(st);
                memcpy(st->st_rcookie, md->hdr.isa_rcookie, COOKIE_SIZE);
                insert_state(st);
            }
        }
        if (!st) {
            /*
             * response is from some weird place. It probably does not
             * not belong.  It might be a sign that we have rebooted,
             * and we should rekey?
             * This logging should be rate limited by remote IP address,
             * and we need to find/make a library for rate-limited by remote.
             */
            openswan_log("ignored received packet with unknown cookies");
            /* cookies will have been dumped by state_hash() during lookup */
            return;
        }

        pst = st;

        /* find parent, if there is one */
        if(st && st->st_clonedfrom != 0) {
            pst = state_with_serialno(st->st_clonedfrom);
        }

	if(pst) {
	    /*
	     * then if there is something wrong with the msgid,
	     * maybe they retransmitted for some reason.
	     * Check if it's an old packet being returned, and
	     * if so, drop it.
	     */
	    if(pst->st_msgid_lastack != INVALID_MSGID
	       && md->msgid_received <= pst->st_msgid_lastack) {
		/* it's fine, it's just a retransmit as a result of our retransmit.
                 * Log it with some small frequency.
                 * Logging of retransmitted is done on child SA!
                 */
                st->st_msg_retransmitted++;
                if((st->st_msg_retransmitted % 512) == 1 || DBGP(DBG_CONTROL)) {
                    DBG_log("responding peer retransmitted msgid %u (retransmission count: %u)"
                            , md->msgid_received, st->st_msg_retransmitted);
                }
		return;
            }

            /*
             * we currently only support a window of 1, but by using nextuse,
             * we anticipate having a window > 1
             */
            if(md->msgid_received != MAINMODE_MSGID
               && md->msgid_received > pst->st_msgid_nextuse) {
                /*
                 * here, the reply packet is newer than one we last received an ACK for,
                 * which is a problem, because we didn't send it, so we drop it and ignore it
                 */
                pst->st_msg_badmsgid_recv++;
                if((pst->st_msg_badmsgid_recv % 512) == 1 || DBGP(DBG_CONTROL)) {
                    loglog(RC_LOG_SERIOUS, "dropping reply: expecting [%u,%u> received: %u"
                                 , pst->st_msgid_lastack+1, pst->st_msgid_nextuse
                                 , md->msgid_received);
                    return;
                }
            }
	}
    }
    /* probably done with pst */

    ike_xchg_type = md->hdr.isa_xchg;
    if(st) {
	from_state = st->st_state;
	DBG(DBG_CONTROL, DBG_log("state found and its state is:%s msgid: %05u"
                                 , enum_show(&state_names, from_state)
                                 , md->msgid_received));
    }

    stf_status stf = ikev2_collect_payloads(md, &md->message_pbs,
                                            &seen, md->hdr.isa_np);
    if(stf != STF_OK) {
        complete_v2_state_transition(mdp, stf);
        return;
    }

    svm_num=0;
    for(svm = v2_state_microcode_table; svm->state != STATE_IKEv2_ROOF; svm_num++,svm++) {
        DBG(DBG_CONTROLMORE, DBG_log("considering state entry: %u", svm_num));
        if(svm->processor == NULL) continue;  /* let there be empty states for historical reasons */

	if(svm->flags & SMF2_MATCH_REQUEST) {
            /* microcode matches request messages */
            if(md->role == INITIATOR) {
                /* message is a response */
                DBG(DBG_CONTROLMORE,DBG_log("  reject: received response, needs request message"));
                continue;
            }
        }
	if(svm->flags & SMF2_MATCH_RESPONSE) {
            /* microcode matches reply messages */
            if(md->role == RESPONDER) {
                /* message is a request */
                DBG(DBG_CONTROLMORE,DBG_log("  reject: received request, needs response message"));
                continue;
            }
        }

	if(svm->flags & SMF2_STATENEEDED) {
	    if(st==NULL) {
                DBG(DBG_CONTROLMORE,DBG_log("  reject:state needed and state unavailable"));
                continue;
            }
	}
	if((svm->flags&SMF2_STATENEEDED)==0) {
	    if(st!=NULL) {
                DBG(DBG_CONTROLMORE,DBG_log("  reject:state unneeded and state available"));
                continue;
            }
	}
	if(svm->state != from_state) {
            DBG(DBG_CONTROLMORE,DBG_log("  reject: in state: %s, needs %s"
                                        , enum_name(&state_names, from_state)
                                        , enum_name(&state_names, svm->state)));
            continue;
        }
	if(svm->recv_type != ike_xchg_type) {
            DBG(DBG_CONTROLMORE,DBG_log("  reject: recv_type: %s, needs %s"
                                        , enum_name(&exchange_names, ike_xchg_type)
                                        , enum_name(&exchange_names, svm->recv_type)));
            continue;
        }

        if((seen & svm->req_clear_payloads)==0) {
            DBG(DBG_CONTROLMORE
                ,DBG_log("  reject: needed clear text payloads missing: %s",
                         bitnamesof(payload_name_ikev2_main
                                    , seen & svm->req_clear_payloads)));
            continue;
        }

	break;
    }

    md->st = st;

    if(svm->state == STATE_IKEv2_ROOF) {
	DBG(DBG_CONTROL, DBG_log("did not find valid state; giving up"));

	/* no useful state */
	if(IKEv2_MSG_FROM_INITIATOR(md->hdr.isa_flags)) {
	    /* must be an initiator message, so we are the responder */

	    bool was_encrypted = !!(md->chain[ISAKMP_NEXT_v2E]);

	    if (was_encrypted) {
		/* our notification will encrypt messages */
		send_v2_notification_enc(md,
					 ike_xchg_type,
					 INVALID_MESSAGE_ID,
					 NULL);
	    } else {
		/* our notification will be in the clear */
                SEND_V2_NOTIFICATION_XCHG_DATA(md, st, ike_xchg_type,
                                               INVALID_MESSAGE_ID, NULL);

	    }
	}
	return;
    }

    md->svm = svm;
    md->from_state = from_state;

    {
	stf_status stf;
        stf = ikev2_process_payloads(md, seen,
                                     svm->req_clear_payloads, svm->opt_clear_payloads);

	if(stf != STF_OK) {
		complete_v2_state_transition(mdp, stf);
		return;
	}
    }

    DBG(DBG_CONTROL, DBG_log("now proceed with state specific processing using state #%u %s", svm_num, svm->svm_name));
    DBG(DBG_PARSING,
	if (pbs_left(&md->message_pbs) != 0)
	    DBG_log("removing %d bytes of padding", (int) pbs_left(&md->message_pbs)));

    md->message_pbs.roof = md->message_pbs.cur;

    ret = (svm->processor)(md);

    DBG(DBG_CONTROLMORE, DBG_log("processor '%s' returned %s (%d)",
				 svm->svm_name, stf_status_name(ret), ret));

    complete_v2_state_transition(mdp, ret);
}

bool
ikev2_decode_peer_id(struct msg_digest *md, enum phase1_role init)
{
    struct state *const st = md->st;
    unsigned int hisID = (init==INITIATOR) ?
	ISAKMP_NEXT_v2IDr : ISAKMP_NEXT_v2IDi;
    /* unsigned int myID  = initiator ? ISAKMP_NEXT_v2IDi: ISAKMP_NEXT_v2IDr;
     * struct payload_digest *const id_me  = md->chain[myID];
     */
    struct payload_digest *const id_him = md->chain[hisID];
    const pb_stream * id_pbs;
    struct ikev2_id * id;

    if(!id_him) {
	openswan_log("IKEv2 mode no peer ID (hisID)");
	return FALSE;
    }

    id_pbs = &id_him->pbs;
    id = &id_him->payload.v2id;
    st->ikev2.st_peer_id.kind = id->isai_type;

    if(!extract_peer_id(&st->ikev2.st_peer_id, id_pbs)) {
	openswan_log("IKEv2 mode peer ID extraction failed");
	return FALSE;
    }

    idtoa(&st->ikev2.st_peer_id, st->ikev2.st_peer_buf, sizeof(st->ikev2.st_peer_buf));
    openswan_log("IKEv2 mode peer ID is %s: '%s'"
                 , enum_show(&ident_names, id->isai_type), st->ikev2.st_peer_buf);

    return TRUE;
}


/*
 * this routine looks for an appropriate ID that was specified
 * by the peer as the name for this side.  This is not always present
 * in the I2/R2, but when it is, it permits us to distinguish what
 * ID the peer expects us to respond with, and also helps us to find
 * the correct policy to enforce.
 */
bool
ikev2_decode_local_id(struct msg_digest *md, enum phase1_role init)
{
    struct state *const st = md->st;
    unsigned int localID = (init==INITIATOR) ?
	ISAKMP_NEXT_v2IDi : ISAKMP_NEXT_v2IDr;
    struct payload_digest *const id_me  = md->chain[localID];
    const pb_stream * id_pbs;
    struct ikev2_id * id;

    if(!id_me) {
        return FALSE;
    }

    id_pbs = &id_me->pbs;
    id = &id_me->payload.v2id;
    st->ikev2.st_local_id.kind = id->isai_type;

    if(!extract_peer_id(&st->ikev2.st_local_id, id_pbs)) {
	openswan_log("IKEv2 mode me ID extraction failed");
	return FALSE;
    }

    idtoa(&st->ikev2.st_local_id, st->ikev2.st_local_buf, sizeof(st->ikev2.st_local_buf));
    openswan_log("IKEv2 mode me ID is %s: '%s'"
		     , enum_show(&ident_names, id->isai_type), st->ikev2.st_local_buf);

    return TRUE;
}


/*
 * this logs to the main log (including peerlog!) the authentication
 * and encryption keys for an IKEv2 SA.  This is done in a format that
 * is compatible with tcpdump 4.0's -E option.
 *
 * this is probably uninteresting to anyone who isn't a developer.
 *
 * The peerlog will be perfect, the syslog will require that a cut
 * command is used to remove the initial text.
 *
 */
#ifdef EMBEDDED
void ikev2_log_parentSA(struct state *st)
{
}
#else
void ikev2_log_parentSA(struct state *st)
{
    const char *authalgo;
    char authkeybuf[256];
    char encalgo[128];
    char enckeybuf[256];

    if(st->st_oakley.integ_hasher==NULL ||
       st->st_oakley.encrypter==NULL) {
	return;
    }

    authalgo = st->st_oakley.integ_hasher->common.officname;

    if(st->st_oakley.enckeylen != 0) {
	/* 3des will use '3des', while aes becomes 'aes128' */
	snprintf(encalgo, sizeof(encalgo), "%s%u", st->st_oakley.encrypter->common.officname
		, st->st_oakley.enckeylen);
    } else {
	strncpy(encalgo, st->st_oakley.encrypter->common.officname, sizeof(encalgo));
    }


    if(DBGP(DBG_CRYPT)) {
        DBG_log("ikev2 parent SA details");
	datatot(st->st_skey_ei.ptr, st->st_skey_ei.len, 'x', enckeybuf, 256);
	datatot(st->st_skey_ai.ptr, st->st_skey_ai.len, 'x', authkeybuf, 256);
	DBG_log("ikev2 I 0x%02x%02x%02x%02x%02x%02x%02x%02x 0x%02x%02x%02x%02x%02x%02x%02x%02x %s:%s %s:%s"
		, st->st_icookie[0], st->st_icookie[1]
		, st->st_icookie[2], st->st_icookie[3]
		, st->st_icookie[4], st->st_icookie[5]
		, st->st_icookie[6], st->st_icookie[7]
		, st->st_rcookie[0], st->st_rcookie[1]
		, st->st_rcookie[2], st->st_rcookie[3]
		, st->st_rcookie[4], st->st_rcookie[5]
		, st->st_rcookie[6], st->st_rcookie[7]
		, authalgo
		, authkeybuf
		, encalgo
		, enckeybuf);

	datatot(st->st_skey_er.ptr, st->st_skey_er.len, 'x', enckeybuf, 256);
	datatot(st->st_skey_ar.ptr, st->st_skey_ar.len, 'x', authkeybuf, 256);
	DBG_log("ikev2 R 0x%02x%02x%02x%02x%02x%02x%02x%02x 0x%02x%02x%02x%02x%02x%02x%02x%02x %s:%s %s:%s"
		, st->st_icookie[0], st->st_icookie[1]
		, st->st_icookie[2], st->st_icookie[3]
		, st->st_icookie[4], st->st_icookie[5]
		, st->st_icookie[6], st->st_icookie[7]
		, st->st_rcookie[0], st->st_rcookie[1]
		, st->st_rcookie[2], st->st_rcookie[3]
		, st->st_rcookie[4], st->st_rcookie[5]
		, st->st_rcookie[6], st->st_rcookie[7]
		, authalgo
		, authkeybuf
		, encalgo
		, enckeybuf);
    }
}
#endif

void
send_v2_notification_from_state(struct state *st, enum isakmp_xchg_types xchg,
				u_int16_t ntf_type, chunk_t *data)
{
    passert(st);

    if (xchg == ISAKMP_XCHG_NONE)
	xchg = ISAKMP_v2_SA_INIT;

    send_v2_notification(st, xchg, ntf_type,
			 st->st_icookie, st->st_rcookie, data);
}

void
send_v2_notification_from_md(struct msg_digest *md UNUSED,
			     enum isakmp_xchg_types xchg, u_int16_t ntf_type,
			     chunk_t *data)
{
    struct state st;
    struct connection cnx;

    /**
     * Create a dummy state to be able to use send_packet in
     * send_notification
     *
     * we need to set:
     *   st_connection->that.host_addr
     *   st_connection->that.host_port
     *   st_connection->interface
     */
    passert(md);

    memset(&st, 0, sizeof(st));
    memset(&cnx, 0, sizeof(cnx));
    st.st_connection = &cnx;
    st.st_remoteaddr = md->sender;
    st.st_remoteport = md->sender_port;
    st.st_localaddr  = md->iface->ip_addr;
    st.st_localport  = md->iface->port;
    cnx.interface = md->iface;
    st.st_interface = md->iface;

    if (xchg == ISAKMP_XCHG_NONE)
	xchg = ISAKMP_v2_SA_INIT;

    send_v2_notification(&st, xchg, ntf_type,
			 md->hdr.isa_icookie, md->hdr.isa_rcookie, data);
}

void ikev2_update_counters(struct msg_digest *md)
{
    struct state *pst= md->pst;
    struct state *st = md->st;

    if(pst==NULL) {
	if(st->st_clonedfrom != 0) {
	    pst = state_with_serialno(st->st_clonedfrom);
	}
	if(pst == NULL) pst = st;
    }

    switch(md->role) {
    case INITIATOR:
	/* update lastuse values */
	pst->st_msgid_lastack = md->msgid_received;
	break;

    case RESPONDER:
	pst->st_msgid_lastrecv= md->msgid_received;
	break;
    }
}

static void success_v2_state_transition(struct msg_digest **mdp)
{
    struct msg_digest *md = *mdp;
    const struct state_v2_microcode *svm = md->svm;
    enum state_kind from_state = md->from_state;
    enum state_kind to_state;
    struct state *pst = md->pst;
    struct state *st  = md->st;
    enum rc_type w;

    to_state = svm->next_state;
    openswan_log("transition from state %s to state %s"
                 , enum_name(&state_names, from_state)
                 , enum_name(&state_names, to_state));

    DBG(DBG_CONTROL,
        DBG_log("v2_state_transition: st is #%lu; pst is #%lu; transition_st is #%lu"
                , st ? st->st_serialno : 0
                , pst ? pst->st_serialno : 0
                , md->transition_state ? md->transition_state->st_serialno : 0));


    if(md->transition_state) {
        change_state(md->transition_state, to_state);
    }
    if(pst == NULL) {
        if(IS_CHILD_SA(st)) {
            pst = state_with_serialno(st->st_clonedfrom);
        } else {
            pst = st;
        }
    }

    w = RC_NEW_STATE + pst->st_state;

    ikev2_update_counters(md);


    /* tell whack and log of progress */
    {
	const char *story = enum_name(&state_stories, to_state);
	char sadetails[128];

	passert(pst->st_state >= STATE_IKEv2_BASE);
	passert(pst->st_state <  STATE_IKEv2_ROOF);

	sadetails[0]='\0';

	if (IS_CHILD_SA_ESTABLISHED(st))
	{
	    /* log our success */
	    w = RC_SUCCESS;
	}

	/* document Parent SA details for admin's pleasure if first message */
        if(IS_PARENT_SA_ESTABLISHED(pst->st_state)
           && pst->st_sa_logged == FALSE) {
            pst->st_sa_logged = TRUE;
	    fmt_isakmp_sa_established(pst, sadetails,sizeof(sadetails));
	}

	/* tell whack and logs our progress */
	loglog(w
	       , "%s: %s%s (msgid: %08u/%08u)"
	       , enum_name(&state_names, to_state)
	       , story
	       , sadetails, md->msgid_received, pst->st_msgid_lastrecv);

	if(st!=pst && IS_CHILD_SA(st) && IS_CHILD_SA_ESTABLISHED(st))
	{
	    char usubl[128], usubh[128];
	    char tsubl[128], tsubh[128];
            const char *story = enum_name(&state_stories, st->st_state);
            struct state *saved_state;

	    addrtot(&st->st_ts_this.low,  0, usubl, sizeof(usubl));
	    addrtot(&st->st_ts_this.high, 0, usubh, sizeof(usubh));
	    addrtot(&st->st_ts_that.low,  0, tsubl, sizeof(tsubl));
	    addrtot(&st->st_ts_that.high, 0, tsubh, sizeof(tsubh));

	    /* but if this is the parent st, this information is not set! you need to check the child sa! */
	    openswan_log("negotiated tunnel [%s,%s proto:%u port:%u-%u] -> [%s,%s proto:%u port:%u-%u]"
                         , usubl, usubh, st->st_ts_this.ipprotoid, st->st_ts_this.startport, st->st_ts_this.endport
                         , tsubl, tsubh, st->st_ts_that.ipprotoid, st->st_ts_that.startport, st->st_ts_that.endport);

	    fmt_ipsec_sa_established(st,  sadetails,sizeof(sadetails));

            /* join with child state for logging: slightly messy global */
            saved_state = cur_state;
            cur_state = st;

            /* tell whack and logs our progress */
            loglog(w
                   , "%s: %s%s "
                   , enum_name(&state_names, st->st_state)
                   , story
                   , sadetails);
            cur_state = saved_state;
	}
    }

    /* if requested, send the new reply packet */
    if (svm->flags & SMF2_REPLY)
    {

	/* free previously transmitted packet */
	freeanychunk(st->st_tpacket);
	DBG(DBG_CONTROL,
	    char buf[ADDRTOT_BUF];
	    DBG_log("sending reply packet to %s:%u (from port %u)"
		      , (addrtot(&st->st_remoteaddr
				 , 0, buf, sizeof(buf)), buf)
		      , st->st_remoteport
		      , st->st_interface->port));

	close_output_pbs(&reply_stream);   /* good form, but actually a no-op */

	clonetochunk(st->st_tpacket, reply_stream.start
		     , pbs_offset(&reply_stream), "reply packet");

	/* actually send the packet
	 * Note: this is a great place to implement "impairments"
	 * for testing purposes.  Suppress or duplicate the
	 * send_packet call depending on st->st_state.
	 */

	TCLCALLOUT("avoidEmitting", st, st->st_connection, md);
	send_packet(st, enum_name(&state_names, from_state), TRUE);
    }

    TCLCALLOUT("adjustTimers", st, st->st_connection, md);

    if (w == RC_SUCCESS) {
	struct state *pst;

	DBG_log("releasing whack for #%lu (sock=%d)"
		, st->st_serialno, st->st_whack_sock);
	release_whack(st);

	/* XXX should call unpend again on parent SA */
	if(st->st_clonedfrom != 0) {
	    pst = state_with_serialno(st->st_clonedfrom); /* with failed child sa, we end up here with an orphan?? */
	    DBG_log("releasing whack for #%lu (sock=%d)"
		    , pst->st_serialno, pst->st_whack_sock);
	    release_whack(pst);
	}
    }

    /* Schedule for whatever timeout is specified */
    {
	time_t delay;
	enum event_type kind = svm->timeout_event;
	struct connection *c = st->st_connection;

	switch (kind)
	{
	case EVENT_SA_REPLACE:	/* SA replacement event */
	    if (IS_PARENT_SA(st))
	    {
		/* Note: we will defer to the "negotiated" (dictated)
		 * lifetime if we are POLICY_DONT_REKEY.
		 * This allows the other side to dictate
		 * a time we would not otherwise accept
		 * but it prevents us from having to initiate
		 * rekeying.  The negative consequences seem
		 * minor.
		 */
		delay = c->sa_ike_life_seconds;
	    }
	    else
	    {
		/* Delay is what the user said, no negotiation.
		 */
		delay = c->sa_ipsec_life_seconds;
	    }

	    /* By default, we plan to rekey.
	     *
	     * If there isn't enough time to rekey, plan to
	     * expire.
	     *
	     * If we are --dontrekey, a lot more rules apply.
	     * If we are the Initiator, use REPLACE_IF_USED.
	     * If we are the Responder, and the dictated time
	     * was unacceptable (too large), plan to REPLACE
	     * (the only way to ratchet down the time).
	     * If we are the Responder, and the dictated time
	     * is acceptable, plan to EXPIRE.
	     *
	     * Important policy lies buried here.
	     * For example, we favour the initiator over the
	     * responder by making the initiator start rekeying
	     * sooner.  Also, fuzz is only added to the
	     * initiator's margin.
	     *
	     * Note: for ISAKMP SA, we let the negotiated
	     * time stand (implemented by earlier logic).
	     */
	    if (kind != EVENT_SA_EXPIRE)
	    {
		unsigned long marg = c->sa_rekey_margin;

		if (svm->flags & SMF2_INITIATOR)
		    marg += marg
			* c->sa_rekey_fuzz / 100.E0
			* (rand() / (RAND_MAX + 1.E0));
		else
		    marg /= 2;

		if ((unsigned long)delay > marg)
		{
			    delay -= marg;
			    st->st_margin = marg;
		}
		else
		{
		    kind = EVENT_SA_EXPIRE;
		}
	    }
	    delete_event(st);
	    event_schedule(kind, delay, st);
	    break;

	case EVENT_NULL:
	    /* XXX: Is there really no case where we want to set no timer? */
	    /* dos_cookie is one 'valid' event, but it is used more? */
	    break;

	case EVENT_REINIT_SECRET:	/* Refresh cookie secret */
	default:
	    bad_case(kind);
	}
    }
}

void complete_v2_state_transition(struct msg_digest **mdp
				  , stf_status result)
{
    struct msg_digest *md = *mdp;
    /* const struct state_v2_microcode *svm=md->svm; */
    struct state *st;
    enum state_kind from_state = STATE_UNDEFINED;
    const char *from_state_name;

    cur_state = st = md->st;	/* might have changed */

    /* passert(st);  // apparently on STF_TOOMUCH_CRYPTO we have no state? Needs fixing */
    /*
     * XXX/SML:  There is no need to abort here in all cases if state is
     * null, so moved this precondition to where it's needed.  Some previous
     * logic appears to have been tooled to handle null state, and state might
     * be null legitimately in certain failure cases (STF_FAIL + xxx).
     *
     * One condition for null state is when a new connection request packet
     * arrives and there is no suitable matching configuration.  For example,
     * ikev2parent_inI1outR1() will return (STF_FAIL + NO_PROPOSAL_CHOSEN) but
     * no state in this case.  While other failures may be better caught before
     * this function is called, we should be graceful here.  And for this
     * particular case, and similar failure cases, we want SEND_NOTIFICATION
     * (below) to let the peer know why we've rejected the request.
     */
    if(st) {
        from_state   = st->st_state;
        from_state_name = enum_name(&state_names, from_state);
    } else {
        from_state_name = "no-state";
    }

    md->result = result;
    TCLCALLOUT("v2AdjustFailure", st, (st ? st->st_connection : NULL), md);
    result = md->result;

    /* advance the state */
    DBG(DBG_CONTROL
	, DBG_log("#%lu complete v2 state transition with %s"
                  , st ? st->st_serialno : 0
		  , stf_status_name(result)));

    switch(result) {
    case STF_IGNORE:
	break;

    case STF_SUSPEND:
	/* update the previous packet history */
	/* IKEv2 XXX */ /* update_retransmit_history(st, md); */

	/* the stf didn't complete its job: don't relase md */
	*mdp = NULL;
	break;

    case STF_INLINE:
        /* mcr: this is second time through complete
         * state transition: the MD was processed by the
         * appropriate _tail() function, and released.
         */
        *mdp = NULL;
        break;

    case STF_OK:
	/* advance the state */
	passert(st);
	success_v2_state_transition(mdp);
	break;

    case STF_INTERNAL_ERROR:
	osw_abort();
	break;

    case STF_TOOMUCHCRYPTO:
	/* well, this should never happen during a whack, since
	 * a whack will always force crypto.
	 *
	 * There is a good chance we don't have a st here. In IKEv2 I1/R1
	 * we have already deleted the state when we saw STF_TOOMUCHCRYPTO
	 * returned by build_ke() or build_nonce().
	 */
	if (st) {
		if (st->st_suspended_md == md)
                    set_suspended(st, NULL);
		pexpect(st->st_calculating == FALSE);
	}
	openswan_log("message in state %s ignored due to "
	             "cryptographic overload"
	             , from_state_name);
	break;

    case STF_FATAL:
	/* update the previous packet history */
	/* update_retransmit_history(st, md); */

	passert(st);
	loglog(RC_FATAL
		  , "encountered fatal error in state %s"
		  , from_state_name);
#ifdef DEBUG_WITH_PAUSE
        pause();
#endif
	delete_event(st);
	{
	    struct state *pst;
	    release_whack(st);
	    if(st->st_clonedfrom != 0) {
		pst = state_with_serialno(st->st_clonedfrom);
		release_whack(pst);
	    }
	}
	release_pending_whacks(st, "fatal error");
	delete_state(st);
	break;

    default:	/* a shortcut to STF_FAIL, setting md->note */
	passert(result > STF_FAIL);
	md->note = result - STF_FAIL;
	result = STF_FAIL;
	/* FALL THROUGH ... */

    case STF_FAIL:
	loglog(RC_NOTIFICATION + md->note
		  , "%s: %s"
		  , from_state_name
		  , enum_name(&ipsec_notification_names, md->note));

	if(md->note > 0) {
		/* only send a notify is this packet was a question, not if it was an answer */
            if(IKEv2_MSG_FROM_INITIATOR(md->hdr.isa_flags)) {
                SEND_V2_NOTIFICATION(md, st, md->note);
            }
	}

	DBG(DBG_CONTROL,
	    DBG_log("state transition function for %s failed: %s"
		    , from_state_name
		    , (md->note) ? enum_name(&ipsec_notification_names, md->note) : "<no reason given>" ));
    }
}

stf_status
accept_v2_KE(struct msg_digest *md, struct state *st, chunk_t *ke, const char *name)
{
    struct ikev2_ke *v2ke;
    pb_stream *keyex_pbs;
    notification_t rn;
    u_int16_t group_number;
    chunk_t dc;

    if (md->chain[ISAKMP_NEXT_v2KE] == NULL)
        return STF_FAIL;

    /* validate the v2KE group */

    v2ke = &md->chain[ISAKMP_NEXT_v2KE]->payload.v2ke;

    if (st->st_oakley.group->group != v2ke->isak_group) {
	loglog(RC_LOG_SERIOUS, "KE has DH group %u, but we selected %u",
               v2ke->isak_group, st->st_oakley.group->group);
        goto send_invalid_ke_ntf;
    }

    keyex_pbs = &md->chain[ISAKMP_NEXT_v2KE]->pbs;

    /* KE in */
    rn = accept_KE(ke, name, st->st_oakley.group, keyex_pbs);
    if (rn == NOTHING_WRONG)
        return STF_OK;

    if (rn == INVALID_KEY_INFORMATION)
        /* special case, we want to send a notification here */
        goto send_invalid_ke_ntf;

    /* pass any other failure up to caller */
    return STF_FAIL+rn;

send_invalid_ke_ntf:
    group_number = htons(st->st_oakley.group->group);
    dc.ptr = (unsigned char *)&group_number;
    dc.len = 2;
    SEND_V2_NOTIFICATION_DATA(md, st, v2N_INVALID_KE_PAYLOAD, &dc);
    /* notification sent, return failure, but prevent another
     * notification from complete_v2_state_transition(). */
    md->note = 0;
    return STF_FAIL;
}

v2_notification_t
accept_v2_nonce(struct msg_digest *md, chunk_t *dest, const char *name)
{
	pb_stream *nonce_pbs;
	size_t len;

	if(md->chain[ISAKMP_NEXT_v2Ni] == NULL) {
		loglog(RC_LOG_SERIOUS, "missing nonce Ni");
		return v2N_INVALID_SYNTAX;
	}

	nonce_pbs = &md->chain[ISAKMP_NEXT_v2Ni]->pbs;
	len = pbs_left(nonce_pbs);

	if (len < MINIMUM_NONCE_SIZE || MAXIMUM_NONCE_SIZE < len) {
		loglog(RC_LOG_SERIOUS, "%s length not between %d and %d",
			name, MINIMUM_NONCE_SIZE, MAXIMUM_NONCE_SIZE);
		return v2N_INVALID_SYNTAX; /* ??? */
	}
	clonereplacechunk(*dest, nonce_pbs->cur, len, "nonce");
	return NOTHING_WRONG;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
