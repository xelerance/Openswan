/* timer event handling
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2005-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
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
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "pluto/connections.h"	/* needs id.h */
#include "state.h"
#include "packet.h"
#include "demux.h"  /* needs packet.h */
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "kernel.h"	/* needs connections.h */
#include "pluto/server.h"
#include "log.h"
#include "rnd.h"
#include "timer.h"
#include "whack.h"
#include "dpd.h"
#include "oswtime.h"

#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

/* This file has the event handling routines. Events are
 * kept as a linked list of event structures. These structures
 * have information like event type, expiration time and a pointer
 * to event specific data (for example, to a state structure).
 */

static struct event *evlist = (struct event *) NULL;

unsigned int event_retransmit_delay_0 = EVENT_RETRANSMIT_DELAY_0;
unsigned int maximum_retransmissions  = MAXIMUM_RETRANSMISSIONS;
unsigned int maximum_retransmissions_initial =MAXIMUM_RETRANSMISSIONS_INITIAL;
unsigned int maximum_retransmissions_quick_r1=MAXIMUM_RETRANSMISSIONS_QUICK_R1;

/*
 * This routine places an event in the event list.
 */
void
event_schedule(enum event_type type, time_t tm, struct state *st)
{
    struct event *ev = alloc_thing(struct event, "struct event in event_schedule()");
    const char *headqueue;

    passert(tm >= 0);
    ev->ev_type = type;
    ev->ev_time = tm + now();
    ev->ev_state = st;

    /* If the event is associated with a state, put a backpointer to the
     * event in the state object, so we can find and delete the event
     * if we need to (for example, if we receive a reply).
     */
    if (st != NULL)
    {
            if(type == EVENT_DPD || type == EVENT_DPD_TIMEOUT)
            {
                    passert(st->st_dpd_event == NULL);
                    st->st_dpd_event = ev;
            } else {
		passert(st->st_event == NULL);
		st->st_event = ev;
	    }
    }

    headqueue = "";
    if (evlist == (struct event *) NULL
	|| evlist->ev_time >= ev->ev_time) {
        headqueue = "(head of queue)";
    }

    DBG(DBG_CONTROL,
	if (st == NULL)
	    DBG_log("inserting event %s, timeout in %lu seconds %s"
                    , enum_show(&timer_event_names, type), (unsigned long)tm, headqueue);
	else
	    DBG_log("inserting event %s, timeout in %lu seconds for #%lu %s"
                    , enum_show(&timer_event_names, type), (unsigned long)tm
                    , ev->ev_state->st_serialno, headqueue));

    if (evlist == (struct event *) NULL
	|| evlist->ev_time >= ev->ev_time)
    {
	ev->ev_next = evlist;
	evlist = ev;
    }
    else
    {
	struct event *evt;

	for (evt = evlist; evt->ev_next != NULL; evt = evt->ev_next)
	    if (evt->ev_next->ev_time >= ev->ev_time)
		break;

	DBG(DBG_CONTROLMORE,
	    if (evt->ev_state == NULL)
		DBG_log("event added after event %s"
		    , enum_show(&timer_event_names, evt->ev_type));
	    else
		DBG_log("event added after event %s for #%lu"
		    , enum_show(&timer_event_names, evt->ev_type)
		    , evt->ev_state->st_serialno));

	ev->ev_next = evt->ev_next;
	evt->ev_next = ev;
    }
}


/* Time to retransmit, or give up.
 *
 * Generally, we'll only try to send the message
 * MAXIMUM_RETRANSMISSIONS times.  Each time we double
 * our patience.
 *
 * As a special case, if this is the first initiating message
 * of a Main Mode exchange, and we have been directed to try
 * forever, we'll extend the number of retransmissions to
 * MAXIMUM_RETRANSMISSIONS_INITIAL times, with all these
 * extended attempts having the same patience.  The intention
 * is to reduce the bother when nobody is home.
 *
 * Since IKEv1 is not reliable for the Quick Mode responder,
 * we'll extend the number of retransmissions as well to
 * improve the reliability.
 */
static void
retransmit_v1_msg(struct state *st)
{
    time_t delay = 0;
    struct connection *c;
    unsigned long try;
    unsigned long try_limit;

    passert(st != NULL);
    c = st->st_connection;

    try       = st->st_try;
    try_limit = c->sa_keying_tries;

    DBG(DBG_CONTROL,
	    DBG_log("handling event EVENT_RETRANSMIT for %s \"%s\" #%lu"
	    , ip_str(&c->spd.that.host_addr), c->name, st->st_serialno));

    if (st->st_retransmit < maximum_retransmissions)
	delay = event_retransmit_delay_0 << (st->st_retransmit + 1);
    else if ((st->st_state == STATE_MAIN_I1 || st->st_state == STATE_AGGR_I1)
	     && c->sa_keying_tries == 0
	     && st->st_retransmit < maximum_retransmissions_initial)
	delay = event_retransmit_delay_0 << maximum_retransmissions;
    else if (st->st_state == STATE_QUICK_R1
	     && st->st_retransmit < maximum_retransmissions_quick_r1)
	delay = event_retransmit_delay_0 << maximum_retransmissions;

    if(DBGP(IMPAIR_RETRANSMITS)) {
	openswan_log("supressing retransmit because IMPAIR_RETRANSMITS is set");
        delay = 0;
	try   = 0;
    }

    if (delay != 0)
    {
	st->st_retransmit++;
	whack_log(RC_RETRANSMISSION
		  , "%s: retransmission; will wait %lus for response"
		  , enum_name(&state_names, st->st_state)
		  , (unsigned long)delay);
	send_packet(st, "EVENT_RETRANSMIT", TRUE);
	event_schedule(EVENT_RETRANSMIT, delay, st);
    }
    else
    {
	/* check if we've tried rekeying enough times.
	 * st->st_try == 0 means that this should be the only try.
	 * c->sa_keying_tries == 0 means that there is no limit.
	 */
	const char *details = "";

	switch (st->st_state)
	{
	case STATE_MAIN_I3:
	    details = ".  Possible authentication failure:"
		" no acceptable response to our"
		" first encrypted message";
	    break;
	case STATE_MAIN_I1:
	    details = ".  No response (or no acceptable response) to our"
		" first IKE message";
	    break;
	case STATE_QUICK_I1:
	    if (c->newest_ipsec_sa == SOS_NOBODY)
		details = ".  No acceptable response to our"
		    " first Quick Mode message:"
		    " perhaps peer likes no proposal";
	    break;
	default:
	    break;
	}
	loglog(RC_NORETRANSMISSION
	       , "max number of retransmissions (%d) reached %s%s"
	       , st->st_retransmit
	       , enum_show(&state_names, st->st_state), details);
	if (try != 0 && try != try_limit)
	{
	    /* A lot like EVENT_SA_REPLACE, but over again.
	     * Since we know that st cannot be in use,
	     * we can delete it right away.
	     */
	    char story[80];	/* arbitrary limit */

	    try++;
	    snprintf(story, sizeof(story), try_limit == 0
		     ? "starting keying attempt %ld of an unlimited number"
		     : "starting keying attempt %ld of at most %ld"
		     , try, try_limit);

	    if(!DBGP(DBG_WHACKWATCH)) {
		if (st->st_whack_sock != NULL_FD)
		{
		    /* Release whack because the observer will get bored. */
		    loglog(RC_COMMENT, "%s, but releasing whack"
			   , story);
		    release_pending_whacks(st, story);
		}
		else
		{
		    /* no whack: just log to syslog */
		    openswan_log("%s", story);
		}
	    } else {
		loglog(RC_COMMENT, "%s", story);
	    }

	    if((try % 3)==0
		&& ((c->policy & (POLICY_IKEV2_ALLOW | POLICY_IKEV2_PROPOSE))
		     == (POLICY_IKEV2_ALLOW | POLICY_IKEV2_PROPOSE)) ) {
		/* so, let's retry with IKEv2, alternating every three messages */
		c->failed_ikev2 = FALSE;
		loglog(RC_COMMENT, "next attempt will be IKEv2");
	    }
	    ipsecdoi_replace(st, LEMPTY, LEMPTY, try);
	}
	delete_state(st);
    }
}

static void
retransmit_v2_msg(struct state *st)
{
    time_t delay = 0;
    struct connection *c;
    unsigned long try;
    unsigned long try_limit;
    const char *details = "";

    passert(st != NULL);
    c = st->st_connection;
    try_limit = c->sa_keying_tries;
    try = st->st_try;
    try++;

    DBG(DBG_CONTROL,
	DBG_log("handling event EVENT_RETRANSMIT for %s \"%s\" #%lu"
	    , ip_str(&c->spd.that.host_addr), c->name, st->st_serialno));

    if (st->st_retransmit < maximum_retransmissions)
	delay = event_retransmit_delay_0 << (st->st_retransmit + 1);

    else if (st->st_state == STATE_PARENT_I1
	     && c->sa_keying_tries == 0
	     && st->st_retransmit < maximum_retransmissions_initial) {
	delay = event_retransmit_delay_0 << maximum_retransmissions;
    }
    else if ((st->st_state == STATE_PARENT_I2
	      || st->st_state == STATE_PARENT_I3)
	     && st->st_retransmit < maximum_retransmissions_quick_r1)
	delay = event_retransmit_delay_0 << maximum_retransmissions;

    if(DBGP(IMPAIR_RETRANSMITS)) {
	openswan_log("supressing retransmit because IMPAIR_RETRANSMITS is set");
        delay = 0;
	try   = 0;
    }

    if (delay != 0)
    {
	st->st_retransmit++;

	whack_log(RC_RETRANSMISSION
		  , "%s: retransmission; will wait %lus for response"
		  , enum_name(&state_names, st->st_state)
		  , (unsigned long)delay);
	send_packet(st, "EVENT_v2_RETRANSMIT", TRUE);
	event_schedule(EVENT_v2_RETRANSMIT, delay, st);
	return;
    }

    /* check if we've tried rekeying enough times.
     * st->st_try == 0 means that this should be the only try.
     * c->sa_keying_tries == 0 means that there is no limit.
     */
    switch (st->st_state)
    {
    case STATE_PARENT_I2:
	details = ".  Possible authentication failure:"
	    " no acceptable response to our"
	    " first encrypted message";
	break;
    case STATE_PARENT_I1:
	details = ".  No response (or no acceptable response) to our"
	    " first IKE message";
	break;
    default:
	break;
    }

    loglog(RC_NORETRANSMISSION
	   , "max number of retransmissions (%d) reached %s%s"
	   , st->st_retransmit
	   , enum_show(&state_names, st->st_state), details);

    if (try != 0 && try != try_limit)
    {
	/* A lot like EVENT_SA_REPLACE, but over again.
	 * Since we know that st cannot be in use,
	 * we can delete it right away.
	 */
	char story[80];	/* arbitrary limit */

	snprintf(story, sizeof(story), try_limit == 0
		 ? "starting keying attempt %ld of an unlimited number"
		 : "starting keying attempt %ld of at most %ld"
		 , try, try_limit);

	if(!DBGP(DBG_WHACKWATCH)) {
	    if (st->st_whack_sock != NULL_FD)
	    {
		/* Release whack because the observer will get bored. */
		loglog(RC_COMMENT, "%s, but releasing whack"
		       , story);
		release_pending_whacks(st, story);
	    }
	    else
	    {
		/* no whack: just log to syslog */
		openswan_log("%s", story);
	    }
	} else {
	    loglog(RC_COMMENT, "%s", story);
	}

	if((try % 3)==0
	   && (c->policy & POLICY_IKEV1_DISABLE)==0) {

	    /* so, let's retry with IKEv1, alternating every three messages */
	    c->failed_ikev2 = TRUE;
	    loglog(RC_COMMENT, "next attempt will be IKEv1");
	}
	ipsecdoi_replace(st, LEMPTY, LEMPTY, try);
    }

    delete_state(st);
}


/*
 * Handle the first event on the list.
 */
void
handle_timer_event(void)
{
    time_t tm;
    struct event *ev = evlist;
    int type;

    if (ev == (struct event *) NULL)    /* Just paranoid */
    {
	DBG(DBG_CONTROL, DBG_log("empty event list, yet we're called"));
	return;
    }

    type = ev->ev_type;
    tm = now();

    if (tm < ev->ev_time)
    {
	DBG(DBG_CONTROL, DBG_log("called while no event expired (%lu/%lu, %s)"
	    , (unsigned long)tm, (unsigned long)ev->ev_time
	    , enum_show(&timer_event_names, type)));

	/* This will happen if the most close-to-expire event was
	 * a retransmission or cleanup, and we received a packet
	 * at the same time as the event expired. Due to the processing
	 * order in call_server(), the packet processing will happen first,
	 * and the event will be removed.
	 */
	return;
    }

    /*
     * we can get behind, try and catch up all expired events
     */
    while (ev && tm >= ev->ev_time) {

	handle_next_timer_event();

	tm = now();
    	ev = evlist;
    }
}

void
handle_next_timer_event(void)
{
    struct event *ev = evlist;
    time_t tm;
    int type;
    struct state *st;

    tm = now();

    if (ev == (struct event *) NULL)
    {
	return;
    }

    evlist = evlist->ev_next;		/* Ok, we'll handle this event */
    type = ev->ev_type;
    st = ev->ev_state;

    if(DBGP(DBG_CONTROL)) {
        DBG_log("at %s handling event %s", oswtimestr()
                , enum_show(&timer_event_names, type));
    }

    if(DBGP(DBG_CONTROL)) {
	if (evlist != (struct event *) NULL) {
	    DBG_log("event after this is %s in %ld seconds"
		    , enum_show(&timer_event_names, evlist->ev_type)
		    , (long) (evlist->ev_time - tm));
	}
	else {
	    DBG_log("no more events are scheduled");
	}

    }

    /* for state-associated events, pick up the state pointer
     * and remove the backpointer from the state object.
     * We'll eventually either schedule a new event, or delete the state.
     */
    passert(GLOBALS_ARE_RESET());
    if (st != NULL)
    {
        if( type  == EVENT_DPD || type == EVENT_DPD_TIMEOUT)
        {
            passert(st->st_dpd_event == ev);
            st->st_dpd_event = NULL;
        } else {
	    passert(st->st_event == ev);
	    st->st_event = NULL;
        }
	set_cur_state(st);
    }

    switch (type)
    {
	case EVENT_REINIT_SECRET:
	    passert(st == NULL);
	    DBG(DBG_CONTROL, DBG_log("event EVENT_REINIT_SECRET handled"));
	    init_secret();
	    break;

#ifdef KLIPS
	case EVENT_SHUNT_SCAN:
	    passert(st == NULL);
	    scan_proc_shunts();
	    break;
#endif

        case EVENT_PENDING_DDNS:
	    passert(st == NULL);
	    connection_check_ddns();
	    break;

        case EVENT_PENDING_PHASE2:
	    passert(st == NULL);
	    connection_check_phase2();
	    break;


	case EVENT_LOG_DAILY:
	    daily_log_event();
	    break;

	case EVENT_RETRANSMIT:
	    retransmit_v1_msg(st);
	    break;

	case EVENT_v2_RETRANSMIT:
	    retransmit_v2_msg(st);
	    break;

	case EVENT_SA_REPLACE:
	case EVENT_SA_REPLACE_IF_USED:
	    {
		struct connection *c;
		so_serial_t newest;

		passert(st != NULL);
		c = st->st_connection;
		newest = (IS_PHASE1(st->st_state) || IS_PHASE15(st->st_state ))
		    ? c->newest_isakmp_sa : c->newest_ipsec_sa;

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
		else
		{
		    DBG(DBG_LIFECYCLE
			, openswan_log("replacing stale %s SA"
			    , (IS_PHASE1(st->st_state)|| IS_PHASE15(st->st_state ))? "ISAKMP" : "IPsec"));
		    ipsecdoi_replace(st, LEMPTY, LEMPTY, 1);
		}
		delete_dpd_event(st);
		event_schedule(EVENT_SA_EXPIRE, st->st_margin, st);
	    }
	    break;

	case EVENT_SA_EXPIRE:
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
	    }
	    /* FALLTHROUGH */
	case EVENT_SO_DISCARD:
	    /* Delete this state object.  It must be in the hash table. */
#if 0 /* delete_state will take care of this better ? */
	    if(st->st_suspended_md) {
		release_md(st->st_suspended_md);
		set_suspended(st, NULL);
	    }
#endif
	    delete_state(st);
	    break;

        case EVENT_DPD:
            dpd_event(st);
            break;

        case EVENT_DPD_TIMEOUT:
            dpd_timeout(st);
            break;


#ifdef NAT_TRAVERSAL
	case EVENT_NAT_T_KEEPALIVE:
	    nat_traversal_ka_event();
	    break;
#endif

        case EVENT_CRYPTO_FAILED:
	    DBG(DBG_CONTROL
		, DBG_log("event crypto_failed on state #%lu, aborting"
			  , st->st_serialno));
	    delete_state(st);
	    break;

        case EVENT_SA_DELETE:
            if(st != NULL) {
                DBG(DBG_CONTROL, DBG_log("event EVENT_SA_DELETE --- no reply to delete"));
                delete_state(st);
            } else {
                DBG(DBG_CONTROL, DBG_log("event EVENT_SA_DELETE for state already NULL"));
            }
	    break;

	default:
	    loglog(RC_LOG_SERIOUS, "INTERNAL ERROR: ignoring unknown expiring event %s"
		, enum_show(&timer_event_names, type));
    }

    pfree(ev);
    reset_cur_state();
}

/*
 * Return the time until the next event in the queue
 * expires (never negative = 0 if one has expired), or -1 if no jobs in queue.
 */
long
next_event(void)
{
    time_t tm;

    if (evlist == (struct event *) NULL) {
	DBG(DBG_CONTROLMORE, DBG_log("no pending events"));
	return -1;
    }

    tm = now();

    DBG(DBG_CONTROL,
	if (evlist->ev_state == NULL)
	    DBG_log("next event %s in %ld seconds"
		, enum_show(&timer_event_names, evlist->ev_type)
		, (long)evlist->ev_time - (long)tm);
	else {
	    DBG_log("next event %s in %ld seconds for #%lu (%s)"
		, enum_show(&timer_event_names, evlist->ev_type)
		, (long)evlist->ev_time - (long)tm
                    , evlist->ev_state->st_serialno, oswtimestr()));
        }

    if (evlist->ev_time - tm <= 0)
	return 0;
    else
	return evlist->ev_time - tm;
}

/*
 * Delete an event.
 */
void
delete_event(struct state *st)
{
    DBG(DBG_CONTROLMORE, DBG_log("deleting event for #%ld", st->st_serialno));
    if (st->st_event != (struct event *) NULL)
    {
	struct event **ev;

	for (ev = &evlist; ; ev = &(*ev)->ev_next)
	{
	    if (*ev == NULL)
	    {
		DBG(DBG_CONTROL, DBG_log("event %s to be deleted not found",
		    enum_show(&timer_event_names, st->st_event->ev_type)));
		break;
	    }
	    if ((*ev) == st->st_event)
	    {
		*ev = (*ev)->ev_next;

		if (st->st_event->ev_type == EVENT_RETRANSMIT)
		    st->st_retransmit = 0;
		pfree(st->st_event);
		st->st_event = (struct event *) NULL;

		break;
	    }
	}
    }
}


/*
 * Delete a DPD event.
 */
void
_delete_dpd_event(struct state *st, const char *file, int lineno)
{
    DBG(DBG_DPD|DBG_CONTROL
	, DBG_log("state: %ld requesting event %s to be deleted by %s:%d"
		  , st->st_serialno
		  , (st->st_dpd_event!=NULL
		   ? enum_show(&timer_event_names, st->st_dpd_event->ev_type)
		   : "none")
		  , file, lineno));

    if (st->st_dpd_event != (struct event *) NULL)
    {
        struct event **ev;

        for (ev = &evlist; ; ev = &(*ev)->ev_next)
        {
            if (*ev == NULL)
            {
                DBG(DBG_DPD|DBG_CONTROL
		    , DBG_log("event %s to be deleted not found",
			      enum_show(&timer_event_names
					, st->st_dpd_event->ev_type)));
                break;
            }
            if ((*ev) == st->st_dpd_event)
            {
                *ev = (*ev)->ev_next;
                pfree(st->st_dpd_event);
                st->st_dpd_event = (struct event *) NULL;
                break;
            }
        }
    }
}

/*
 * dump list of events to whacklog
 */
void
timer_list(void)
{
    time_t tm;
    struct event *ev = evlist;
    int type;
    struct state *st;

    if (ev == (struct event *) NULL)    /* Just paranoid */
    {
	whack_log(RC_LOG, "no events are queued");
	return;
    }

    tm = now();

    whack_log(RC_LOG, "It is now: %ld seconds since epoch", (unsigned long)tm);

    while(ev) {
	type = ev->ev_type;
	st = ev->ev_state;

	whack_log(RC_LOG, "event %s is schd: %ld (in %lds) state:%ld"
		  , enum_show(&timer_event_names, type)
		  , (unsigned long)ev->ev_time
		  , (unsigned long)(ev->ev_time - tm)
		  , st != NULL ? (long signed)st->st_serialno : -1);

	if(st && st->st_connection) {
	    whack_log(RC_LOG, "    connection: \"%s\"", st->st_connection->name);
	}

	ev = ev->ev_next;
    }
}

/*
 * XXX --- hack alert, but I want to avoid adding new pluto-level
 *   command line arguments for now --- they need to all be whack
 * level items, and all command line arguments go away.
*/
void
init_timer(void)
{
    char *valstr;

    valstr = getenv("PLUTO_EVENT_RETRANSMIT_DELAY");
    if(valstr) {
	event_retransmit_delay_0 = atoi(valstr);
	DBG(DBG_CONTROL, DBG_log("PLUTO_EVENT_RETRANSMIT_DELAY set to '%d'"
		, event_retransmit_delay_0));
    }

    valstr = getenv("PLUTO_MAXIMUM_RETRANSMISSIONS");
    if(valstr) {
	maximum_retransmissions  = atoi(valstr);
	DBG(DBG_CONTROL, DBG_log("PLUTO_MAXIMUM_RETRANSMISSIONS set to '%d'"
		, maximum_retransmissions));
    }

    valstr = getenv("PLUTO_MAXIMUM_RETRANSMISSIONS_INITIAL");
    if(valstr) {
	maximum_retransmissions_initial = atoi(valstr);
	DBG(DBG_CONTROL, DBG_log("PLUTO_MAXIMUM_RETRANSMISSIONS_INITIAL set to '%d'"
		, maximum_retransmissions_initial));
    }

    valstr = getenv("PLUTO_MAXIMUM_RETRANSMISSIONS_QUICK_R1");
    if(valstr) {
	maximum_retransmissions_quick_r1= atoi(valstr);
	DBG(DBG_CONTROL, DBG_log("PLUTO_MAXIMUM_RETRANSMISSIONS_QUICK_R1 set to '%d'"
		, maximum_retransmissions_quick_r1));
    }
}


/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
