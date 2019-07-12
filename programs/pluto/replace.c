/* timer event handling
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2005-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2019 Bart Trojanowski <bart@xelerance.com>
 *
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
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openswan.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "id.h"
#include "pluto/connections.h"	/* needs id.h */
#include "pluto/state.h"
#include "packet.h"
#include "demux.h"  /* needs packet.h */
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "timer.h"
#include "dpd.h"
#include "replace.h"

#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

void
sa_replace(struct state *st, int type)
{
    struct connection *c;
    so_serial_t newest;
    time_t tm = now();

    passert(st != NULL);
    c = st->st_connection;
    newest = IS_PARENT_SA(st)
	? c->newest_isakmp_sa : c->newest_ipsec_sa;

    DBG(DBG_LIFECYCLE,openswan_log(
	"SA REPLACE: #%ld parent=%s orig_init=%s nat_bhnd_{me=%s peer=%s} (%08x)",
		st->st_serialno,
		IS_PARENT_SA(st) ? "Y" : "N",
		st->st_orig_initiator ? "Y" : "N",
		(st->hidden_variables.st_nat_traversal & LELEM(NAT_TRAVERSAL_NAT_BHND_ME))  ? "Y" : "N",
		(st->hidden_variables.st_nat_traversal & LELEM(NAT_TRAVERSAL_NAT_BHND_PEER))  ? "Y" : "N",
		st->hidden_variables.st_nat_traversal));

    if (newest != st->st_serialno
    && newest != SOS_NOBODY)
    {
	/* not very interesting: no need to replace */
	DBG(DBG_LIFECYCLE
	    , openswan_log("not replacing stale %s SA: #%lu will do"
		, (IS_PHASE1(st->st_state) || IS_PHASE15(st->st_state ))? "ISAKMP" : "IPsec"
		, newest));
    }
    else if (type == EVENT_SA_REPLACE_IF_USED
    && st->st_outbound_time <= tm - c->sa_rekey_margin)
    {
	/* we observed no recent use: no need to replace
	 *
	 * The sampling effects mean that st_outbound_time
	 * could be up to SHUNT_SCAN_INTERVAL more recent
	 * than actual traffic because the sampler looks at change
	 * over that interval.
	 * st_outbound_time could also not yet reflect traffic
	 * in the last SHUNT_SCAN_INTERVAL.
	 * We expect that SHUNT_SCAN_INTERVAL is smaller than
	 * c->sa_rekey_margin so that the effects of this will
	 * be unimportant.
	 * This is just an optimization: correctness is not
	 * at stake.
	 *
	 * Note: we are abusing the DBG mechanism to control
	 * normal log output.
	 */
	DBG(DBG_LIFECYCLE
	    , openswan_log("not replacing stale %s SA: inactive for %lus"
		, (IS_PHASE1(st->st_state) || IS_PHASE15(st->st_state ))? "ISAKMP" : "IPsec"
		, (unsigned long)(tm - st->st_outbound_time)));
    }
#ifdef NAT_TRAVERSAL
    else if (IS_PARENT_SA(st)  /* this is the parent SA */
    && !st->st_orig_initiator  /* we are original responder */
    && st->hidden_variables.st_nat_traversal & LELEM(NAT_TRAVERSAL_NAT_BHND_PEER))
    {
	/* this is a parent SA, we are the original responder, and
	 * our peer is behind NAT-T.
	 *
	 * if we initiate the replace, we may not be unable to
	 * negotiate a new parent SA with the peer.
	 *
	 * we ignore the event, and hope that the peer will
	 * renegotiate soon.
	 */
	DBG(DBG_LIFECYCLE,
	    openswan_log("not initiating rekey on parent SA #%lu: "
			 "peer is behind NAT-T", st->st_serialno));
	st->st_margin = EVENT_NATT_DELAY_REKEY_EXPIRE;
    }
#endif
    else
    {
	lset_t policy_add = LEMPTY;
	DBG(DBG_LIFECYCLE
	    , openswan_log("replacing stale %s %s SA"
		, (IS_PHASE1(st->st_state)||IS_PHASE15(st->st_state)) ? "ISAKMP" : "IPsec"
		, (IS_PARENT_SA(st)) ? "PARENT" : "CHILD"));
	if (IS_PARENT_SA(st)) {
		DBG(DBG_LIFECYCLE, openswan_log("parent SA, "
						"adding connection policy: %s",
						prettypolicy(c->policy)));
		policy_add = c->policy;
	}
	ipsecdoi_replace(st, policy_add, LEMPTY, 1);
	if (IS_PARENT_SA(st)) {
		/* a parent SA will not be expired immediately, but after
		 * it's replaced */
		st->st_margin = EVENT_REAUTH_IKE_SA_TIMEOUT;
	}
    }
    delete_dpd_event(st);
    event_schedule(EVENT_SA_EXPIRE, st->st_margin, st);
}

void
sa_expire(struct state *st)
{
    const char *satype;
    so_serial_t latest;
    struct connection *c;

    passert(st != NULL);
    c = st->st_connection;

    if (IS_PHASE1(st->st_state)|| IS_PHASE15(st->st_state ))
    {
	satype = "ISAKMP";
	latest = c->newest_isakmp_sa;
    }
    else
    {
	satype = "IPsec";
	latest = c->newest_ipsec_sa;
    }

    if (st->st_serialno != latest)
    {
	/* not very interesting: already superseded */
	DBG(DBG_LIFECYCLE
	    , openswan_log("%s SA expired (superseded by #%lu)"
		, satype, latest));
    }
    else
    {
	openswan_log("%s SA expired (%s)", satype
	    , (c->policy & POLICY_DONT_REKEY)
		? "--dontrekey"
		: "LATEST!"
	    );
    }
    delete_state(st);
}
