/* IKEv2 - CHILD SA - calculations
 *
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
#include "libopenswan.h"

#include "defs.h"
#include "cookie.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "smartcard.h"
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
#include "vendor.h"
#include "dpd.h"
#include "udpfromto.h"
#include "tpm/tpm.h"
#include "kernel.h"
#include "virtual.h"
#include "hostpair.h"

void ikev2_derive_child_keys(struct state *st UNUSED)
{
}
 

/* rewrite me with addrbytesptr() */
struct traffic_selector ikev2_subnettots(struct end *e)
{
    struct traffic_selector ts;
    struct in6_addr v6mask;

    memset(&ts, 0, sizeof(ts));
    
    switch(e->client.addr.u.v4.sin_family) {
    case AF_INET:
	ts.sin_family = AF_INET;
	ts.low   = e->client.addr;
	ts.low.u.v4.sin_addr.s_addr  &= bitstomask(e->client.maskbits).s_addr;
	ts.high  = e->client.addr;
	ts.high.u.v4.sin_addr.s_addr |= ~bitstomask(e->client.maskbits).s_addr;
	break;

    case AF_INET6:
	ts.sin_family = AF_INET6;
	v6mask = bitstomask6(e->client.maskbits);

	ts.low   = e->client.addr;
	ts.low.u.v6.sin6_addr.s6_addr32[0] &= v6mask.s6_addr32[0];
	ts.low.u.v6.sin6_addr.s6_addr32[1] &= v6mask.s6_addr32[1];
	ts.low.u.v6.sin6_addr.s6_addr32[2] &= v6mask.s6_addr32[2];
	ts.low.u.v6.sin6_addr.s6_addr32[3] &= v6mask.s6_addr32[3];

	ts.high  = e->client.addr;
	ts.high.u.v6.sin6_addr.s6_addr32[0]|= ~v6mask.s6_addr32[0];
	ts.high.u.v6.sin6_addr.s6_addr32[1]|= ~v6mask.s6_addr32[1];
	ts.high.u.v6.sin6_addr.s6_addr32[2]|= ~v6mask.s6_addr32[2];
	ts.high.u.v6.sin6_addr.s6_addr32[3]|= ~v6mask.s6_addr32[3];
	break;
    }

    return ts;
}

stf_status ikev2_emit_ts(struct msg_digest *md   UNUSED
			 , pb_stream *outpbs   
			 , unsigned int np
			 , struct traffic_selector *ts
			 , enum phase1_role role UNUSED)
{
    struct ikev2_ts its;
    struct ikev2_ts1 its1;
    pb_stream ts_pbs;
    pb_stream ts_pbs2;

    its.isat_np = np;
    its.isat_critical = ISAKMP_PAYLOAD_CRITICAL;
    its.isat_num = 1;

    if(!out_struct(&its, &ikev2_ts_desc, outpbs, &ts_pbs))
	return STF_INTERNAL_ERROR;

    switch(ts->sin_family) {
    case AF_INET:
	its1.isat1_type = ID_IPV4_ADDR_RANGE;
	break;
    case AF_INET6:
	its1.isat1_type = ID_IPV6_ADDR_RANGE;
	break;
    }
    its1.isat1_ipprotoid = 0;      /* all protocols */
    its1.isat1_sellen = 16;        /* for IPv4 */
    its1.isat1_startport = 0;      /* all ports */
    its1.isat1_endport = 65535;  
    if(!out_struct(&its1, &ikev2_ts1_desc, &ts_pbs, &ts_pbs2))
	return STF_INTERNAL_ERROR;
    
    /* now do IP addresses */
    switch(ts->sin_family) {
    case AF_INET:
	if(!out_raw(&ts->low.u.v4.sin_addr.s_addr, 4, &ts_pbs2, "ipv4 low")
	   ||!out_raw(&ts->high.u.v4.sin_addr.s_addr, 4,&ts_pbs2,"ipv4 high"))
	    return STF_INTERNAL_ERROR;
	break;
    case AF_INET6:
	if(!out_raw(&ts->low.u.v6.sin6_addr.s6_addr, 16, &ts_pbs2, "ipv6 low")
	   ||!out_raw(&ts->high.u.v6.sin6_addr.s6_addr,16,&ts_pbs2,"ipv6 high"))
	    return STF_INTERNAL_ERROR;
	break;
    }

    close_output_pbs(&ts_pbs2);
    close_output_pbs(&ts_pbs);
    
    return STF_OK;
}


stf_status ikev2_calc_emit_ts(struct msg_digest *md
			      , pb_stream *outpbs
			      , enum phase1_role role 
			      , struct connection *c0
			      , lset_t policy UNUSED)
{
    struct state *st = md->st;
    struct traffic_selector *ts_i, *ts_r;
    struct spd_route *sr;
    stf_status ret;
    
    ikev2_derive_child_keys(st);
    install_inbound_ipsec_sa(st);
    st->st_childsa = c0;

    if(role == INITIATOR) {
	ts_i = &st->st_ts_this;
	ts_r = &st->st_ts_that;
    } else {
	ts_i = &st->st_ts_that;
	ts_r = &st->st_ts_this;
    }

    for(sr=&c0->spd; sr != NULL; sr = sr->next) {
	ret = ikev2_emit_ts(md, outpbs, ISAKMP_NEXT_v2TSr
			    , ts_i, INITIATOR);
	if(ret!=STF_OK) return ret;
	ret = ikev2_emit_ts(md, outpbs, ISAKMP_NEXT_NONE
			    , ts_r, RESPONDER);
	if(ret!=STF_OK) return ret;
    }

    return STF_OK;
}

/* return number of traffic selectors found */
static int 
ikev2_parse_ts(struct payload_digest *const ts_pd
	       , struct traffic_selector *array
	       , unsigned int array_max)
{
    struct ikev2_ts1 ts1;
    unsigned int i;

    for(i=0; i<ts_pd->payload.v2ts.isat_num; i++) {
	pb_stream addr;
	if(!in_struct(&ts1, &ikev2_ts1_desc, &ts_pd->pbs, &addr))
	    return -1;
	
	if(i < array_max) {
	    memset(&array[i], 0, sizeof(*array));
	    switch(ts1.isat1_type) {
	    case ID_IPV4_ADDR_RANGE:
		array[i].sin_family = AF_INET;
		array[i].low.u.v4.sin_family  = AF_INET;
		if(!in_raw(&array[i].low.u.v4.sin_addr.s_addr, 4, &addr, "ipv4 ts"))
		    return -1;
		
		array[i].high.u.v4.sin_family = AF_INET;
		if(!in_raw(&array[i].high.u.v4.sin_addr.s_addr, 4, &addr, "ipv4 ts"))
		    return -1;
		break;

	    case ID_IPV6_ADDR_RANGE:
		array[i].sin_family = AF_INET;
		array[i].low.u.v6.sin6_family  = AF_INET6;
		if(!in_raw(&array[i].low.u.v6.sin6_addr.s6_addr, 16, &addr, "ipv6 ts"))
		    return -1;
		
		array[i].high.u.v6.sin6_family = AF_INET6;
		if(!in_raw(&array[i].high.u.v6.sin6_addr.s6_addr,16, &addr, "ipv6 ts"))
		    return -1;
		break;
		
	    default:
		return -1;
	    }

	    array[i].ipprotoid = ts1.isat1_ipprotoid;
	    array[i].startport = ts1.isat1_startport;
	    array[i].endport   = ts1.isat1_startport;
	}
    }
    
    return i;
}


static int ikev2_evaluate_connection_fit(struct connection *d
				  , struct spd_route *sr
				  , enum phase1_role role
				  , struct traffic_selector *tsi
				  , struct traffic_selector *tsr
				  , unsigned int tsi_n
				  , unsigned int tsr_n)
{
    unsigned int tsi_ni, tsr_ni;
    int bestfit = -1;
    int best_tsr, best_tsi; 
    struct end *ei, *er;
#ifdef DEBUG
    char ei3[SUBNETTOT_BUF],er3[SUBNETTOT_BUF];
    
    if(role == INITIATOR) {
	ei = &sr->this;
	er = &sr->that;
    } else {
	ei = &sr->that;
	er = &sr->this;
    }
	
    if (DBGP(DBG_CONTROLMORE))
    {
	subnettot(&ei->client,  0, ei3, sizeof(ei3));
	subnettot(&er->client,  0, er3, sizeof(er3));
	DBG_log("  ikev2_eval_conn evaluating "
		"I=%s:%s:%d/%d R=%s:%d/%d %s"
		, d->name, ei3, ei->protocol, ei->port
		, er3, er->protocol, er->port
		, is_virtual_connection(d) ? "(virt)" : "");
    }
#endif /* DEBUG */
   
    /* compare tsi/r array to this/that, evaluating how well it fits */
    for(tsi_ni = 0; tsi_ni < tsi_n; tsi_ni++) {
	for(tsr_ni=0; tsr_ni<tsr_n; tsr_ni++) {
	    /* does it fit at all? */

	    if (DBGP(DBG_CONTROLMORE))
	    {
		char lbi[ADDRTOT_BUF], hbi[ADDRTOT_BUF];
		char lbr[ADDRTOT_BUF], hbr[ADDRTOT_BUF];
		addrtot(&tsi[tsi_ni].low,  0, lbi, sizeof(lbi));
		addrtot(&tsi[tsi_ni].high, 0, hbi, sizeof(hbi));
		addrtot(&tsr[tsr_ni].low,  0, lbr, sizeof(lbr));
		addrtot(&tsr[tsr_ni].high, 0, hbr, sizeof(hbr));
		
		DBG_log("    tsi[%u]=%s/%s tsr[%u]=%s/%s "
			, tsi_ni, lbi, hbi
			, tsr_ni, lbr, hbr);
	    }

	    /* do addresses fit into the policy? */
	    if(addrinsubnet(&tsi[tsi_ni].low, &ei->client)
	       && addrinsubnet(&tsi[tsi_ni].high, &ei->client)
	       && addrinsubnet(&tsr[tsr_ni].low,  &er->client)
	       && addrinsubnet(&tsr[tsr_ni].high, &er->client))
	    {
		/*
		 * now, how good a fit is it? --- sum of bits gives
		 * how good a fit this is.
		 */
		int ts_range1 = ikev2_calc_iprangediff(tsi[tsi_ni].low
						      , tsi[tsi_ni].high);
		int maskbits1 = ei->client.maskbits;
		int fitbits1  = maskbits1 + ts_range1;

		int ts_range2 = ikev2_calc_iprangediff(tsr[tsr_ni].low
						      , tsr[tsr_ni].high);
		int maskbits2 = er->client.maskbits;
		int fitbits2  = maskbits2 + ts_range2;
		int fitbits = (fitbits1 << 8) + fitbits2;

		if (DBGP(DBG_CONTROLMORE))
		{
		    DBG_log("      has ts_range1=%u maskbits1=%u ts_range2=%u maskbits2=%u fitbits=%d <> %d"
			    , ts_range1, maskbits1, ts_range2, maskbits2
			    , fitbits, bestfit);
		}

		if(fitbits > bestfit) {
		    best_tsi = tsi_ni;
		    best_tsr = tsr_ni;
		    bestfit = fitbits;
		}
	    }
	}
    }

    return bestfit;
}

stf_status ikev2_child_sa_respond(struct msg_digest *md
				  , enum phase1_role role
				  , pb_stream *outpbs)
{
    struct state      *st = md->st;
    struct state      *st1;
    struct connection *c  = st->st_connection;
    //struct connection *cb;
    struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
    stf_status ret;
    struct payload_digest *const tsi_pd = md->chain[ISAKMP_NEXT_v2TSi];
    struct payload_digest *const tsr_pd = md->chain[ISAKMP_NEXT_v2TSr];
    struct traffic_selector tsi[16], tsr[16];
    unsigned int tsi_n, tsr_n;

    st1 = duplicate_state(st);
    md->st = st1;

    /* start of SA out */
    {
	struct isakmp_sa r_sa = sa_pd->payload.sa;
	notification_t rn;
	pb_stream r_sa_pbs;

	r_sa.isasa_np = ISAKMP_NEXT_v2TSi;  
	if (!out_struct(&r_sa, &ikev2_sa_desc, outpbs, &r_sa_pbs))
	    return STF_INTERNAL_ERROR;

	/* SA body in and out */
	rn = ikev2_parse_child_sa_body(&sa_pd->pbs, &sa_pd->payload.v2sa,
				       &r_sa_pbs, st1, FALSE);
	
	if (rn != NOTHING_WRONG)
	    return STF_FAIL + rn;
    }

    /*
     * now look at provided TSx, and see if these fit the connection
     * that we have, and narrow them if necessary.
     */
    tsi_n = ikev2_parse_ts(tsi_pd, tsi, 16);
    tsr_n = ikev2_parse_ts(tsr_pd, tsr, 16);

    /*
     * now walk through all connections and see if this connection
     * was in fact the best.
     *
     * similar to find_client_connection/fc_try.
     */
    {
	struct connection *b = c;
	struct connection *d;
	int bestfit, newfit;
	struct spd_route *sra, *bsr;
	struct host_pair *hp = NULL;

	bsr = NULL;
	bestfit = -1;
	for (sra = &c->spd; sra != NULL; sra = sra->next)
	{
	    int bfit=ikev2_evaluate_connection_fit(c,sra,role
						   ,tsi,tsr,tsi_n,tsr_n);
	    if(bfit > bestfit) {
		bestfit = bfit;
		b = c;
		bsr = sra;
	    }
	}

	for (sra = &c->spd; hp==NULL && sra != NULL; sra = sra->next)
	{
	    hp = find_host_pair(&sra->this.host_addr
				, sra->this.host_port
				, NULL
				, sra->that.host_port);

#ifdef DEBUG
	    if (DBGP(DBG_CONTROLMORE))
	    {
		char s2[SUBNETTOT_BUF],d2[SUBNETTOT_BUF];

		subnettot(&sra->this.client, 0, s2, sizeof(s2));
		subnettot(&sra->that.client, 0, d2, sizeof(d2));

		DBG_log("  checking hostpair %s -> %s is %s"
			, s2, d2
			, (hp ? "found" : "not found"));
	    }
#endif /* DEBUG */

	    if(!hp) continue;

	    for (d = hp->connections; d != NULL; d = d->hp_next)
	    {
		struct spd_route *sr;
		int wildcards, pathlen;  /* XXX */
		
		if (d->policy & POLICY_GROUP)
		    continue;
		
		if (!(same_id(&c->spd.this.id, &d->spd.this.id)
		      && match_id(&c->spd.that.id, &d->spd.that.id, &wildcards)
		      && trusted_ca(c->spd.that.ca, d->spd.that.ca, &pathlen)))
		    continue;

		
		for (sr = &d->spd; sr != NULL; sr = sr->next) {
		    newfit=ikev2_evaluate_connection_fit(d,sr,role
							 ,tsi,tsr,tsi_n,tsr_n);
		    if(newfit > bestfit) {
			bestfit = newfit;
			b=d;
			bsr = sr;
		    }
		}
	    }
	}
	
	/*
	 * now that we have found the best connection, copy the data into
	 * the state structure as the tsi/tsr
	 *
	 */
	st1->st_ts_this = ikev2_subnettots(&bsr->this);
	st1->st_ts_that = ikev2_subnettots(&bsr->that);
    }
    ret = ikev2_calc_emit_ts(md, outpbs, role
			     , c, c->policy);
    if(ret != STF_OK) return ret;

    /* install inbound and outbound test case */
    if(!install_ipsec_sa(st, TRUE))
	return STF_FATAL;

    return STF_OK;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
 
