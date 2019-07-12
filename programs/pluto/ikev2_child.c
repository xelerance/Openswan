/* IKEv2 - CHILD SA - calculations
 *
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009-2010 Paul Wouters <paul@xelerance.com>
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
#include "libopenswan.h"

#include "defs.h"
#include "cookie.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "pluto/connections.h"        /* needs id.h */
#include "pluto/state.h"
#include "packet.h"
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "ike_alg.h"
#include "log.h"
#include "demux.h"        /* needs packet.h */
#include "ikev2.h"
#include "pluto_crypt.h"
#include "ipsec_doi.h"        /* needs demux.h and state.h */
#include "ike_continuations.h"
#include "timer.h"
#include "whack.h"        /* requires connections.h */
#include "pluto/server.h"
#include "vendor.h"
#include "dpd.h"
#include "rnd.h"
#include "udpfromto.h"
#include "tpm/tpm.h"
#include "kernel.h"
#include "pluto/virtual.h"
#include "hostpair.h"

void ikev2_print_ts(struct traffic_selector *ts){
	char lbx[ADDRTOT_BUF];
	char hbx[ADDRTOT_BUF];

	DBG_log("printing contents struct traffic_selector");
	DBG_log("  ts_type: %s", enum_name(&ikev2_ts_type_names, ts->ts_type));
	DBG_log("  ipprotoid: %d", ts->ipprotoid);
	DBG_log("  startport: %d", ts->startport);
	DBG_log("  endport: %d", ts->endport);
	addrtot(&ts->low,  0, lbx, sizeof(lbx));
	addrtot(&ts->high, 0, hbx, sizeof(hbx));
	DBG_log("  ip low: %s", lbx);
	DBG_log("  ip high: %s", hbx);
}


/* rewrite me with addrbytesptr() */
struct traffic_selector ikev2_end_to_ts(struct end *e, ip_address endpoint)
{
    struct traffic_selector ts;
    struct in6_addr v6mask;
    ip_subnet clientnet;

    memset(&ts, 0, sizeof(ts));

    clientnet = e->client;

    if(!e->has_client) {
        /* we propose the IP address of the interface that we are using. */
        /*
         * we could instead propose 0.0.0.0->255.255.255.255 and let the other
         * end narrow the TS, but if one wants that, it is easy to just specify
         * in the configuration file: rightsubnet=0.0.0.0/0.
         *
         * When there is NAT involved, we may really want a tunnel to the
         * address that this end point thinks it is.  That works only when
         * virtual_ip includes the IP involved.
         *
         */
        addrtosubnet(&endpoint, &clientnet);
    }

    switch(clientnet.addr.u.v4.sin_family) {
    case AF_INET:
        ts.ts_type = IKEv2_TS_IPV4_ADDR_RANGE;
        ts.low   = clientnet.addr;
        ts.low.u.v4.sin_addr.s_addr  &= bitstomask(clientnet.maskbits).s_addr;
        ts.high  = clientnet.addr;
        ts.high.u.v4.sin_addr.s_addr |= ~bitstomask(clientnet.maskbits).s_addr;
        break;

    case AF_INET6:
        ts.ts_type = IKEv2_TS_IPV6_ADDR_RANGE;
        v6mask = bitstomask6(clientnet.maskbits);

        ts.low   = clientnet.addr;
        ts.low.u.v6.sin6_addr.s6_addr32[0] &= v6mask.s6_addr32[0];
        ts.low.u.v6.sin6_addr.s6_addr32[1] &= v6mask.s6_addr32[1];
        ts.low.u.v6.sin6_addr.s6_addr32[2] &= v6mask.s6_addr32[2];
        ts.low.u.v6.sin6_addr.s6_addr32[3] &= v6mask.s6_addr32[3];

        ts.high  = clientnet.addr;
        ts.high.u.v6.sin6_addr.s6_addr32[0]|= ~v6mask.s6_addr32[0];
        ts.high.u.v6.sin6_addr.s6_addr32[1]|= ~v6mask.s6_addr32[1];
        ts.high.u.v6.sin6_addr.s6_addr32[2]|= ~v6mask.s6_addr32[2];
        ts.high.u.v6.sin6_addr.s6_addr32[3]|= ~v6mask.s6_addr32[3];
        break;

        /* Setting ts_type IKEv2_TS_FC_ADDR_RANGE (RFC-4595) not yet supproted */
    }

    ts.ipprotoid = e->protocol;

    /*
     * if port is %any or 0 we mean all ports (or all iccmp/icmpv6
     * See RFC-5996 Section 3.13.1 handling for ICMP(1) and ICMPv6(58)
     *   we only support providing Type, not Code, eg protoport=1/1
     */
    if(e->port == 0 || e->has_port_wildcard) {
        ts.startport = 0;
        ts.endport = 65535;
    } else {
        ts.startport = e->port;
        ts.endport = e->port;
    }

    return ts;
}

stf_status ikev2_emit_ts(struct msg_digest *md   UNUSED
			 , pb_stream *outpbs
			 , unsigned int np
			 , struct traffic_selector *ts)
{
    struct ikev2_ts its;
    struct ikev2_ts1 its1;
    pb_stream ts_pbs;
    pb_stream ts_pbs2;

    its.isat_np = np;
    its.isat_critical = ISAKMP_PAYLOAD_NONCRITICAL;
    its.isat_num = 1;

    if(!out_struct(&its, &ikev2_ts_desc, outpbs, &ts_pbs))
        return STF_INTERNAL_ERROR;

    switch(ts->ts_type) {
    case IKEv2_TS_IPV4_ADDR_RANGE:
	its1.isat1_type = IKEv2_TS_IPV4_ADDR_RANGE;
	its1.isat1_sellen = 2*4 + 8; /* See RFC 5669 SEction 13.3.1, 8 octet header plus 2 ip addresses */
	break;
    case IKEv2_TS_IPV6_ADDR_RANGE:
	its1.isat1_type = IKEv2_TS_IPV6_ADDR_RANGE;
	its1.isat1_sellen = 2*16 + 8; /* See RFC 5669 SEction 13.3.1, 8 octet header plus 2 ip addresses */
	break;
    case IKEv2_TS_FC_ADDR_RANGE:
        DBG_log("IKEv2 Traffic Selector IKEv2_TS_FC_ADDR_RANGE not yet supported");
        return STF_INTERNAL_ERROR;
    default:
        DBG_log("IKEv2 Traffic Selector type '%d' not supported", ts->ts_type);
    }

    its1.isat1_ipprotoid = ts->ipprotoid;      /* protocol as per local policy*/
    its1.isat1_startport = ts->startport;      /* ports as per local policy*/
    its1.isat1_endport = ts->endport;
    if(!out_struct(&its1, &ikev2_ts1_desc, &ts_pbs, &ts_pbs2))
        return STF_INTERNAL_ERROR;

    /* now do IP addresses */
    switch(ts->ts_type) {
    case IKEv2_TS_IPV4_ADDR_RANGE:
        if(!out_raw(&ts->low.u.v4.sin_addr.s_addr, 4, &ts_pbs2, "ipv4 low")
           ||!out_raw(&ts->high.u.v4.sin_addr.s_addr, 4,&ts_pbs2,"ipv4 high"))
            return STF_INTERNAL_ERROR;
        break;
    case IKEv2_TS_IPV6_ADDR_RANGE:
        if(!out_raw(&ts->low.u.v6.sin6_addr.s6_addr, 16, &ts_pbs2, "ipv6 low")
           ||!out_raw(&ts->high.u.v6.sin6_addr.s6_addr,16,&ts_pbs2,"ipv6 high"))
            return STF_INTERNAL_ERROR;
        break;
    case IKEv2_TS_FC_ADDR_RANGE:
        DBG_log("Traffic Selector IKEv2_TS_FC_ADDR_RANGE not supported");
        return STF_FAIL;
    default:
        DBG_log("Failed to create unknown IKEv2 Traffic Selector payload '%d'", ts->ts_type);
        return STF_FAIL;
    }

    close_output_pbs(&ts_pbs2);
    close_output_pbs(&ts_pbs);

    return STF_OK;
}


stf_status ikev2_calc_emit_ts(struct msg_digest *md
			      , pb_stream *outpbs
			      , enum phase1_role role
                              , unsigned int next_payload UNUSED
			      , struct connection *c0
			      , lset_t policy UNUSED)
{
    struct state *st = md->st;
    struct traffic_selector *ts_i, *ts_r;
    struct spd_route *sr;
    stf_status ret;

    st->st_childsa = c0;

    if(role == INITIATOR) {
        ts_i = &st->st_ts_this;
        ts_r = &st->st_ts_that;
    } else {
        ts_i = &st->st_ts_that;
        ts_r = &st->st_ts_this;
    }

    for(sr=&c0->spd; sr != NULL; sr = sr->next) {
        pbs_set_np(outpbs, ISAKMP_NEXT_v2TSi);
	ret = ikev2_emit_ts(md, outpbs, 0, ts_i);
	if(ret!=STF_OK) return ret;

        pbs_set_np(outpbs, ISAKMP_NEXT_v2TSr);
        ret = ikev2_emit_ts(md, outpbs, 0, ts_r);
	if(ret!=STF_OK) return ret;
    }

    return STF_OK;
}

#ifdef NEED_SIN_LEN
#define SET_SIN_LEN(x)  (x).u.v4.sin_len = sizeof(struct sockaddr_in)
#define SET_SIN6_LEN(x) (x).u.v6.sin_len = sizeof(struct sockaddr_in6)
#else
#define SET_SIN_LEN(x) do{}while(0)
#define SET_SIN6_LEN(x) do{}while(0)
#endif

/* return number of traffic selectors found */
int
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
	    case IKEv2_TS_IPV4_ADDR_RANGE:
		array[i].ts_type = IKEv2_TS_IPV4_ADDR_RANGE;
		array[i].low.u.v4.sin_family  = AF_INET;
                SET_SIN_LEN(array[i].low);
                if(!in_raw(&array[i].low.u.v4.sin_addr.s_addr, 4, &addr, "ipv4 ts"))
                    return -1;

                array[i].high.u.v4.sin_family = AF_INET;
                SET_SIN_LEN(array[i].high);

                if(!in_raw(&array[i].high.u.v4.sin_addr.s_addr, 4, &addr, "ipv4 ts"))
                    return -1;
                break;

            case IKEv2_TS_IPV6_ADDR_RANGE:
                array[i].ts_type = IKEv2_TS_IPV6_ADDR_RANGE;
                array[i].low.u.v6.sin6_family  = AF_INET6;
                SET_SIN6_LEN(array[i].low);

                if(!in_raw(&array[i].low.u.v6.sin6_addr.s6_addr, 16, &addr, "ipv6 ts"))
                    return -1;

                array[i].high.u.v6.sin6_family = AF_INET6;
                SET_SIN6_LEN(array[i].high);

                if(!in_raw(&array[i].high.u.v6.sin6_addr.s6_addr,16, &addr, "ipv6 ts"))
                    return -1;
                break;

            default:
                return -1;
            }

            array[i].ipprotoid = ts1.isat1_ipprotoid;
            /*should be converted to host byte order for local processing*/
            array[i].startport = ts1.isat1_startport;
            array[i].endport   = ts1.isat1_endport;
        }
    }

    return i;
}

/*
 * Check if our policy's protocol (proto) matches
 * the Traffic Selector protocol (ts_proto).
 * If superset_ok, narrowing ts_proto 0 to our proto is OK (responder narrowing)
 * If subset_ok, narrowing our proto 0 to ts_proto is OK (initiator narrowing).
 * Returns 0 for no match, 1 for narrowed match, 255 for exact match.
 */
static int ikev2_match_protocol(u_int8_t proto, u_int8_t ts_proto
                                , bool superset_ok
                                , bool subset_ok, const char *which, int index)
{
    int f = 0;	/* strength of match */
    const char *m = "no";

    if (proto == ts_proto) {
        f = 255;	/* ??? odd value */
        m = "exact";
    } else if (superset_ok && ts_proto == 0) {
        f = 1;
        m = "superset";
    } else if (subset_ok && proto == 0) {
        f = 1;
        m = "subset";
    }
    DBG(DBG_CONTROL,
        DBG_log("protocol %d and %s[%d].ipprotoid %d: %s match",
                proto,
                which, index,
                ts_proto,
                m));
    return f;
}

/*
 * returns -1 on no match; otherwise a weight of how great the match was.
 * *best_tsi_i and *best_tsr_i are set if there was a match.
 */
int ikev2_evaluate_connection_protocol_fit(const struct connection *d,
					   const struct spd_route *sr,
					   enum phase1_role role,
					   const struct traffic_selector *tsi,
					   const struct traffic_selector *tsr,
					   int tsi_n,
					   int tsr_n,
					   int *best_tsi_i,
					   int *best_tsr_i)
{
    int tsi_ni;
    int bestfit_pr = -1;
    const struct end *ei, *er;
    int narrowing = (d->policy & POLICY_IKEV2_ALLOW_NARROWING);

    if (role == INITIATOR) {
        ei = &sr->this;
        er = &sr->that;
    } else {
        ei = &sr->that;
        er = &sr->this;
    }
    /* compare tsi/r array to this/that, evaluating protocol how well it fits */
    /* ??? stupid n**2 algorithm */
    for (tsi_ni = 0; tsi_ni < tsi_n; tsi_ni++) {
        int tsr_ni;

        int fitrange_i = ikev2_match_protocol(ei->protocol, tsi[tsi_ni].ipprotoid,
                                              role == RESPONDER && narrowing,
                                              role == INITIATOR && narrowing,
                                              "tsi", tsi_ni);

        if (fitrange_i == 0)
            continue;	/* save effort! */

        for (tsr_ni = 0; tsr_ni < tsr_n; tsr_ni++) {
            int fitrange_r = ikev2_match_protocol(er->protocol, tsr[tsr_ni].ipprotoid,
                                                  role == RESPONDER && narrowing,
                                                  role == INITIATOR && narrowing,
                                                  "tsr", tsr_ni);

            int matchiness;

            if (fitrange_r == 0)
                continue;	/* save effort! */

            matchiness = fitrange_i + fitrange_r;	/* ??? arbitrary objective function */

            if (matchiness > bestfit_pr) {
                *best_tsi_i = tsi_ni;
                *best_tsr_i = tsr_ni;
                bestfit_pr = matchiness;
                DBG(DBG_CONTROL,
                    DBG_log("    best protocol fit so far: tsi[%d] fitrange_i %d, tsr[%d] fitrange_r %d, matchiness %d",
                            *best_tsi_i, fitrange_i,
                            *best_tsr_i, fitrange_r,
                            matchiness));
            }
        }
    }
    DBG(DBG_CONTROL, DBG_log("    protocol_fitness %d", bestfit_pr));
    return bestfit_pr;
}

/*
 * Check if our policy's port (port) matches
 * the Traffic Selector port range (ts.startport to ts.endport)
 * Note port == 0 means port range 0 to 65535.
 * If superset_ok, narrowing ts port range to our port range is OK (responder narrowing)
 * If subset_ok, narrowing our port range to ts port range is OK (initiator narrowing).
 * Returns 0 if no match; otherwise number of ports within match
 */
static int ikev2_match_port_range(u_int16_t port, struct traffic_selector ts,
	bool superset_ok, bool subset_ok, const char *which, int index)
{
    u_int16_t low = port;
    u_int16_t high = port == 0 ? 65535 : port;
    int f = 0;	/* strength of match */
    const char *m = "no";

    if (ts.startport > ts.endport) {
        m = "invalid range in";
    } else if (ts.startport == low && ts.endport == high) {
        f = 1 + (high - low);
        m = "exact";
    } else if (superset_ok && ts.startport <= low && high <= ts.endport) {
        f = 1 + (high - low);
        m = "superset";
    } else if (subset_ok && low <= ts.startport && ts.endport <= high) {
        f = 1 + (ts.endport - ts.startport);
        m = "subset";
    }
    DBG(DBG_CONTROL,
        DBG_log("   %s[%d] %u-%u: %s port match with %u.  fitness %d",
                which, index,
                ts.startport, ts.endport,
                m,
                port,
                f));
    return f;
}

/*
 * returns -1 on no match; otherwise a weight of how great the match was.
 * *best_tsi_i and *best_tsr_i are set if there was a match.
 */
int ikev2_evaluate_connection_port_fit(const struct connection *d,
				       const struct spd_route *sr,
				       enum phase1_role role,
				       const struct traffic_selector *tsi,
				       const struct traffic_selector *tsr,
				       int tsi_n,
				       int tsr_n,
				       int *best_tsi_i,
				       int *best_tsr_i)
{
    int tsi_ni;
    int bestfit_p = -1;
    const struct end *ei, *er;
    int narrowing = (d->policy & POLICY_IKEV2_ALLOW_NARROWING);

    if (role == INITIATOR) {
        ei = &sr->this;
        er = &sr->that;
    } else {
        ei = &sr->that;
        er = &sr->this;
    }

    DBG(DBG_CONTROL,
        DBG_log("    evaluate_connection_port_fit tsi_n[%d], best=%d"
                , tsi_n, bestfit_p));
    // so far: tsi[%d] fitrange_i %d, tsr[%d] fitrange_r %d, matchiness %d",
    //                *best_tsi_i, fitrange_i,
    //                *best_tsr_i, fitrange_r,
    //matchiness));

    /* compare tsi/r array to this/that, evaluating how well each port range fits */
    /* ??? stupid n**2 algorithm */
    for (tsi_ni = 0; tsi_ni < tsi_n; tsi_ni++) {
        int tsr_ni;
        int fitrange_i = ikev2_match_port_range(ei->port, tsi[tsi_ni],
                                                role == RESPONDER && narrowing,
                                                role == INITIATOR && narrowing,
                                                "tsi", tsi_ni);

        DBG(DBG_CONTROL,
            DBG_log("      evaluating_connection_port_fit tsi_n[%d], range_i=%d best=%d"
                    , tsi_ni, fitrange_i, bestfit_p));

        if (fitrange_i == 0)
            continue;	/* save effort! */

        for (tsr_ni = 0; tsr_ni < tsr_n; tsr_ni++) {
            int fitrange_r = ikev2_match_port_range(er->port, tsr[tsr_ni],
                                                    role == RESPONDER && narrowing,
                                                    role == INITIATOR && narrowing,
                                                    "tsr", tsr_ni);

            int matchiness;

            DBG(DBG_CONTROL,
                DBG_log("      evaluating_connection_port_fit tsi_n[%d] tsr_n[%d], range=%d/%d best=%d"
                        , tsi_ni, tsr_ni, fitrange_i, fitrange_r, bestfit_p));

            if (fitrange_r == 0)
                continue;	/* no match */

            matchiness = fitrange_i + fitrange_r;	/* ??? arbitrary objective function */

            if (matchiness > bestfit_p) {
                *best_tsi_i = tsi_ni;
                *best_tsr_i = tsr_ni;
                bestfit_p = matchiness;
                DBG(DBG_CONTROL,
                    DBG_log("    best ports fit so far: tsi[%d] fitrange_i %d, tsr[%d] fitrange_r %d, matchiness %d",
                            *best_tsi_i, fitrange_i,
                            *best_tsr_i, fitrange_r,
                            matchiness));
            }
        }
    }
    DBG(DBG_CONTROL, DBG_log("    port_fitness %d", bestfit_p));
    return bestfit_p;
}

/* checks the TSi/TSr selectors to make sure they are valid,
 * returns v2N_NOTHING_WRONG on success, or v2N_ error code otherwise */
static int ikev2_validate_transport_proposal(struct connection *d
					     , struct state *st
					     , enum phase1_role role
					     , struct traffic_selector *tsi
					     , struct traffic_selector *tsr
					     , unsigned int tsi_n
					     , unsigned int tsr_n)
{
    unsigned int tsi_ni, tsr_ni;
    char a0[SUBNETTOT_BUF];
    char a1[SUBNETTOT_BUF];

    (void)d;
    (void)st;
    (void)role;

    for(tsi_ni = 0; tsi_ni < tsi_n; tsi_ni++) {

	if (sameaddr(&tsi[tsi_ni].low, &tsi[tsi_ni].high))
	    continue;

	/* proposal contains an address range, which is not compatible
	 * with a transport mode connection */

	addrtot(&tsi[tsi_ni].low, 0, a0, sizeof(a0));
	addrtot(&tsi[tsi_ni].high, 0, a1, sizeof(a1));

	loglog(RC_LOG_SERIOUS, "received TSi[%d] selector with range %s~%s, "
	       "incompatible with TRANSPORT mode -- refusing",
	       tsi_ni, a0, a1);
	return v2N_TS_UNACCEPTABLE;
    }

    for(tsr_ni=0; tsr_ni<tsr_n; tsr_ni++) {

	if (sameaddr(&tsr[tsr_ni].low, &tsr[tsr_ni].high))
	    continue;

	/* proposal contains an address range, which is not compatible
	 * with a transport mode connection */

	addrtot(&tsr[tsr_ni].low, 0, a0, sizeof(a0));
	addrtot(&tsr[tsr_ni].high, 0, a1, sizeof(a1));

	loglog(RC_LOG_SERIOUS, "received TSr[%d] selector with %s~%s, "
	       "incompatible with TRANSPORT mode -- refusing",
	       tsr_ni, a0, a1);
	return v2N_TS_UNACCEPTABLE;
    }

    return v2N_NOTHING_WRONG; // 0
}

int ikev2_evaluate_connection_fit(struct connection *d
                                  , struct state *st
				  , struct spd_route *sr
				  , enum phase1_role role
				  , struct traffic_selector *tsi
				  , struct traffic_selector *tsr
				  , unsigned int tsi_n
				  , unsigned int tsr_n)
{
    unsigned int tsi_ni, tsr_ni;
    int bestfit = -1;
    /* int best_tsr, best_tsi;  */
    struct end *ei, *er;
    struct end fei, fer;

    if(role == INITIATOR) {
	ei = &sr->this;
	er = &sr->that;
    } else {
	ei = &sr->that;
	er = &sr->this;
    }

    if(!ei->has_client && ei->host_type == KH_ANY) {
	/* here, fill in new end with actual client info from the state */
	fei = *ei;
	ei  = &fei;
	addrtosubnet(&st->st_remoteaddr, &fei.client);
    }

    if(!er->has_client && er->host_type == KH_ANY) {
	/* here, fill in new end with actual client info from the state */
	fer = *er;
	er  = &fer;
	addrtosubnet(&st->st_remoteaddr, &fer.client);
    }

    DBG(DBG_CONTROLMORE,
    {
	char ei3[SUBNETTOT_BUF];
	char er3[SUBNETTOT_BUF];
        if(ei->has_client) {
            subnettot(&ei->client,  0, ei3, sizeof(ei3));
	} else if(ei->host_type == KH_ANY) {
	    strcpy(ei3, "<self>");
        } else {
            strcpy(ei3, "<noclient>");
        }

        if(er->has_client) {
            subnettot(&er->client,  0, er3, sizeof(er3));
	} else if(er->host_type == KH_ANY) {
            strcpy(er3, "<self>");
        } else {
            strcpy(er3, "<noclient>");
        }
	DBG_log("  ikev2_evaluate_connection_fit evaluating our "
		"I=%s:%s:%d/%d R=%s:%d/%d %s to their:"
		, d->name, ei3, ei->protocol, ei->port
		, er3, er->protocol, er->port
		, is_virtual_connection(d) ? "(virt)" : "");
    }
    );

    /* compare tsi/r array to this/that, evaluating how well it fits */
    for(tsi_ni = 0; tsi_ni < tsi_n; tsi_ni++) {
	for(tsr_ni=0; tsr_ni<tsr_n; tsr_ni++) {
	    /* does it fit at all? */

	    DBG(DBG_CONTROLMORE,
	    {
		char lbi[ADDRTOT_BUF];
		char hbi[ADDRTOT_BUF];
		char lbr[ADDRTOT_BUF];
		char hbr[ADDRTOT_BUF];
		addrtot(&tsi[tsi_ni].low,  0, lbi, sizeof(lbi));
		addrtot(&tsi[tsi_ni].high, 0, hbi, sizeof(hbi));
		addrtot(&tsr[tsr_ni].low,  0, lbr, sizeof(lbr));
		addrtot(&tsr[tsr_ni].high, 0, hbr, sizeof(hbr));

		DBG_log("    tsi[%u]=%s/%s proto=%d portrange %d-%d, tsr[%u]=%s/%s proto=%d portrange %d-%d"
			, tsi_ni, lbi, hbi
			,  tsi[tsi_ni].ipprotoid, tsi[tsi_ni].startport, tsi[tsi_ni].endport
			, tsr_ni, lbr, hbr
			,  tsr[tsr_ni].ipprotoid, tsr[tsr_ni].startport, tsr[tsr_ni].endport);
	    }
	    );
	    /* do addresses fit into the policy? */

	    /*
	     * NOTE: Our parser/config only allows 1 CIDR, however IKEv2 ranges can be non-CIDR
	     *       for now we really support/limit ourselves to a single CIDR
	     */
	    if(addrinsubnet(&tsi[tsi_ni].low, &ei->client)
	       && addrinsubnet(&tsi[tsi_ni].high, &ei->client)
	       && addrinsubnet(&tsr[tsr_ni].low,  &er->client)
	       && addrinsubnet(&tsr[tsr_ni].high, &er->client)
	       && (tsi[tsi_ni].ipprotoid == ei->protocol)
	       && (tsr[tsr_ni].ipprotoid == er->protocol)
	      )
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

		/*
		 * comparing for ports
		 * for finding better local polcy
		 */
		DBG(DBG_CONTROL,DBG_log("ei->port %d  tsi[tsi_ni].startport %d  tsi[tsi_ni].endport %d",
			ei->port , tsi[tsi_ni].startport, tsi[tsi_ni].endport));
		if( ei->port && (tsi[tsi_ni].startport == ei->port && tsi[tsi_ni].endport == ei->port)) {
		fitbits = fitbits << 1;
		}

		if( er->port && (tsr[tsr_ni].startport == er->port && tsr[tsr_ni].endport == er->port)) {
		fitbits = fitbits << 1;
		}

		DBG(DBG_CONTROLMORE,
		{
		    DBG_log("      has ts_range1=%u maskbits1=%u ts_range2=%u maskbits2=%u fitbits=%d <> %d"
			    , ts_range1, maskbits1, ts_range2, maskbits2
			    , fitbits, bestfit);
		}
		);

		if(fitbits > bestfit) {
#if 0
		    best_tsi = tsi_ni;
		    best_tsr = tsr_ni;
#endif
		    bestfit = fitbits;
		}
	    }
	}
    }

    return bestfit;
}

stf_status ikev2_child_sa_respond(struct msg_digest *md
                                  , struct state *st1
                                  , pb_stream *outpbs)
{
    struct state      *pst = md->pst;
    struct connection *c   = NULL;
    /* struct connection *cb; */
    struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
    stf_status ret;
    struct payload_digest *const tsi_pd = md->chain[ISAKMP_NEXT_v2TSi];
    struct payload_digest *const tsr_pd = md->chain[ISAKMP_NEXT_v2TSr];
    struct traffic_selector tsi[16], tsr[16];
    unsigned int tsi_n, tsr_n;

    if(pst == NULL) pst = md->st;
    c = pst->st_connection;

    if (c->kind == CK_INSTANCE) {
        /* We have made it here with a template instance, but in case this
         * connection is coming from another roadwarior, the evaluation
         * should happen on the template instead.  We look up the matching
         * template... */
	struct connection *d;
        for (d = connections; d != NULL; d = d->ac_next) {
            if (!streq(c->name, d->name))
                continue;
            if (d->kind == CK_INSTANCE)
                continue;

            /* we prefer the non instance connection */
            DBG(DBG_CONTROLMORE,
                DBG_log("switching from %s to %s of conn '%s' to evaluate fitness",
                        enum_name(&connection_kind_names, c->kind),
                        enum_name(&connection_kind_names, d->kind),
                        c->name));
            c = d;
            break;
        }
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
	int bestfit_n, newfit, bestfit_p;
	struct spd_route *sra, *bsr;
	struct IDhost_pair *hp = NULL;
	int best_tsi_i ,  best_tsr_i;

	bsr = NULL;
	bestfit_n = -1;
	bestfit_p = -1;
	best_tsi_i =  best_tsr_i = -1;

        DBG(DBG_CONTROLMORE, DBG_log("ikev2_evaluate_connection_fit, evaluating base fit for %s", c->name));
	for (sra = &c->spd; sra != NULL; sra = sra->next) {
            int bfit_n=ikev2_evaluate_connection_fit(c,pst,sra,RESPONDER,tsi,tsr,tsi_n,
                                                     tsr_n);
            if (bfit_n > bestfit_n) {
                DBG(DBG_CONTROLMORE, DBG_log("bfit_n=ikev2_evaluate_connection_fit found better fit c %s", c->name));
                int bfit_p =  ikev2_evaluate_connection_port_fit (c,sra,RESPONDER,tsi,tsr,
                                                                  tsi_n,tsr_n, &best_tsi_i, &best_tsr_i);
                if (bfit_p > bestfit_p) {
                    DBG(DBG_CONTROLMORE, DBG_log("ikev2_evaluate_connection_port_fit found better fit c %s, tsi[%d],tsr[%d]"
                                                 , c->name, best_tsi_i, best_tsr_i));
                    bestfit_p = bfit_p;
                    bestfit_n = bfit_n;
                    b = c;
                    bsr = sra;
                }
            }
            else
                DBG(DBG_CONTROLMORE, DBG_log("prefix range fit c %s c->name was rejected by Traffic Selectors"
                                             , c->name));
        }

	for (sra = &c->spd; hp==NULL && sra != NULL; sra = sra->next) {
            hp = find_ID_host_pair(sra->this.id
                                   , sra->that.id);

#ifdef DEBUG
            if (DBGP(DBG_CONTROLMORE))  {
                char s2[SUBNETTOT_BUF],d2[SUBNETTOT_BUF];

                subnettot(&sra->this.client, 0, s2, sizeof(s2));
                subnettot(&sra->that.client, 0, d2, sizeof(d2));

                DBG_log("  checking hostpair %s -> %s is %s"
                        , s2, d2
                        , (hp ? "found" : "not found"));
            }
#endif /* DEBUG */

            if(!hp) continue;

            for (d = hp->connections; d != NULL; d = d->IDhp_next) {
                struct spd_route *sr;
                int wildcards, pathlen;  /* XXX */

                /* if already best fit, do not try again */
                if(d == c) continue;

                if (d->policy & POLICY_GROUP)
                    continue;

                if (!(same_id(&c->spd.this.id, &d->spd.this.id)
                      && match_id(&c->spd.that.id, &d->spd.that.id, &wildcards)
                      && trusted_ca_by_name(c->spd.that.ca, d->spd.that.ca, &pathlen)))
                    continue;


                for (sr = &d->spd; sr != NULL; sr = sr->next) {
                    newfit=ikev2_evaluate_connection_fit(d,pst, sr,RESPONDER
                                                         ,tsi,tsr,tsi_n,tsr_n);
                    if(newfit > bestfit_n) {  /// will complicated this with narrowing
                        int bfit_p;

                        DBG(DBG_CONTROLMORE, DBG_log("bfit=ikev2_evaluate_connection_fit found better fit d %s", d->name));

                        /* we know that it's already a better fit */
                        bestfit_n = newfit;
                        b = d;
                        bsr = sr;

                        /* now look at port fit, it might be even better! */
                        bfit_p =  ikev2_evaluate_connection_port_fit (c ,sra,RESPONDER,tsi,tsr,
                                                                          tsi_n,tsr_n, &best_tsi_i, &best_tsr_i);
                        if (bfit_p > bestfit_p) {
                            DBG(DBG_CONTROLMORE, DBG_log("ikev2_evaluate_connection_port_fit found better fit d %s, tsi[%d],tsr[%d]"
                                                         , d->name, best_tsi_i, best_tsr_i));
                            bestfit_p = bfit_p;
                        }
                    }
                    else {
                        DBG(DBG_CONTROLMORE, DBG_log("prefix range fit d %s d->name was rejected by connection fit: %d > %d", d->name, newfit, bestfit_n));

                    }
                }
            }
        }

        DBG(DBG_CONTROLMORE, DBG_log("ikev2_evaluate_connection_fit, concluded with %s", b->name));
	/*
	 * now that we have found the best connection (in b), copy the data into
	 * the state structure as the tsi/tsr, perhaps after instantiating it.
	 *
	 */

        if (b->kind == CK_TEMPLATE || b->kind == CK_GROUP) {
            /* instantiate it, filling in peer's ID */
            b = rw_instantiate(b, &pst->st_remoteaddr,
                               NULL,
                               &pst->ikev2.st_peer_id);
        }

        if (b != c)
	{
            char instance[1 + 10 + 1];

            openswan_log("switched from \"%s\" to \"%s\"%s", c->name, b->name
                         , fmt_connection_inst_name(b, instance, sizeof(instance)));

	    pst->st_connection = b;	/* kill reference to c */

	    /* this ensures we don't move cur_connection from NULL to
	     * something, requiring a reset_cur_connection() */
	    if (cur_connection == c) {
		set_cur_connection(b);
	    }

	    connection_discard(c);
	}

	/* better connection */
	c=b;

        if(bsr == NULL) {
            /* no proposal matched... */
            return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
        }

        if(st1 == NULL) {
            /* we are sure, so lets make a state for this child SA */
            st1 = duplicate_state(pst);
            st1->st_policy = c->policy & POLICY_IPSEC_MASK;
            insert_state(st1);
        }

        st1->st_ts_this = ikev2_end_to_ts(&bsr->this, pst->st_localaddr);
        st1->st_ts_that = ikev2_end_to_ts(&bsr->that, pst->st_remoteaddr);
        ikev2_print_ts(&st1->st_ts_this);
        ikev2_print_ts(&st1->st_ts_that);
    }

    /* note that st1 starts == st, but a child SA creation can change that */
    st1->st_connection = c;
    md->st = st1;

    /* start of SA out */
    {
        struct isakmp_sa r_sa = sa_pd->payload.sa;
        notification_t rn;
        pb_stream r_sa_pbs;

        /* set the np for this structure */
        pbs_set_np(outpbs, ISAKMP_NEXT_v2SA);

        r_sa.isasa_np = ISAKMP_NEXT_v2TSi;
        if (!out_struct(&r_sa, &ikev2_sa_desc, outpbs, &r_sa_pbs))
            return STF_INTERNAL_ERROR;

        /* SA body in and out */
        rn = ikev2_parse_child_sa_body(&sa_pd->pbs, &sa_pd->payload.v2sa,
                                       &r_sa_pbs, st1, FALSE);

        /* we do not delete_state st1 yet, because initiator could retransmit */
        if (rn != NOTHING_WRONG) {
            //delete_event(st1);
            event_schedule(EVENT_SO_DISCARD, EVENT_HALF_OPEN_TIMEOUT, st1);
            return STF_FAIL + rn;
        }
    }

    {
        unsigned int next_payload = ISAKMP_NEXT_NONE;
        struct payload_digest *p;
        for(p = md->chain[ISAKMP_NEXT_v2N]; p != NULL; p = p->next) {
            if ( p->payload.v2n.isan_type == v2N_USE_TRANSPORT_MODE ) {
                next_payload = ISAKMP_NEXT_v2N;
                break;
            }
        }

	/* role is always RESPONDER, since we are replying to a request */
        ret = ikev2_calc_emit_ts(md, outpbs, RESPONDER, next_payload
                                 , c, c->policy);
        if(ret != STF_OK) {
            return ret;
        }
    }

    {
        chunk_t child_spi, notifiy_data;
        struct payload_digest *p;
        for(p = md->chain[ISAKMP_NEXT_v2N]; p != NULL; p = p->next) {
            if ( p->payload.v2n.isan_type == v2N_USE_TRANSPORT_MODE ) {

                if(st1->st_connection->policy & POLICY_TUNNEL) {
                    DBG_log("Although local policy is tunnel, received USE_TRANSPORT_MODE");
                    DBG_log("So switching to transport mode, and responding with USE_TRANSPORT_MODE notify");
                }
                else {
                    DBG_log("Local policy is transport, received USE_TRANSPORT_MODE");
                    DBG_log("Now responding with USE_TRANSPORT_MODE notify");
                }

                memset(&child_spi, 0, sizeof(child_spi));
                memset(&notifiy_data, 0, sizeof(notifiy_data));
                ship_v2N (ISAKMP_NEXT_NONE, ISAKMP_PAYLOAD_NONCRITICAL
                          , /*PROTO_ISAKMP*/ 0,
                          &child_spi,
                          v2N_USE_TRANSPORT_MODE, &notifiy_data, outpbs);

                if (st1->st_esp.present == TRUE) {
                    /* openswan supports only "esp" with ikev2 it seems,
                     * look at ikev2_parse_child_sa_body handling*/
                    st1->st_esp.attrs.encapsulation = ENCAPSULATION_MODE_TRANSPORT;
                }
                break;
            }
        }
    }

    /* in this case, RESPONDER means the responder to this message */
    ret = ikev2_derive_child_keys(st1, RESPONDER);
    if (ret != STF_OK)
	return ret;

    /* install inbound and outbound SPI info */
    if(!install_ipsec_sa(pst, st1, TRUE))
        return STF_FATAL;

    /* mark the connection as now having an IPsec SA associated with it. */
    st1->st_connection->newest_ipsec_sa = st1->st_serialno;
    change_state(st1, STATE_CHILD_C1_KEYED);


    return STF_OK;
}


/*
 * IKEv2 - CHILD rekey IPsec SA
 */
stf_status
ipsec_outI1(int whack_sock
	    , struct state *isakmp_sa
	    , struct connection *c
	    , lset_t policy
	    , unsigned long try
	    , so_serial_t replacing
	    , struct xfrm_user_sec_ctx_ike * uctx UNUSED
	    )
{
    if(!isakmp_sa->st_ikev2 && (policy&POLICY_IKEV1_DISABLE)==0) {
#ifdef IKEV1
        return quick_outI1(whack_sock
                           , isakmp_sa
                           , c,policy,try,replacing,uctx);
#else
        openswan_log("IKEv1 disabled at compile time");
        return STF_FAIL;
#endif
    }

    return ikev2child_outC1(whack_sock, isakmp_sa, c, policy, try, replacing, uctx);
}

static void
ikev2child_outC1_continue(struct pluto_crypto_req_cont *pcrc
                            , struct pluto_crypto_req *r
                            , err_t ugh);

static stf_status
ikev2child_outC1_tail(struct pluto_crypto_req_cont *pcrc
                            , struct pluto_crypto_req *r);


stf_status ikev2child_outC1(int whack_sock
                            , struct state *parentst
                            , struct connection *c
                            , lset_t policy
                            , unsigned long try /* how many attempts so far */ UNUSED
                            , so_serial_t replacing
                            , struct xfrm_user_sec_ctx_ike * uctx UNUSED
                            )
{
    struct state *st;
    stf_status ret = STF_FAIL;

    /* okay, got a transmit slot, make a child state to send this. */
    st = duplicate_state(parentst);
    st->st_whack_sock = whack_sock;
    ret = allocate_msgid_from_parent(parentst, &st->st_msgid);
    if(ret != STF_OK)
	    return ret;

    insert_state(st);

    // record which state we are aiming to replace.
    st->st_replaced = replacing;
    st->st_policy = policy;
    st->st_state  = STATE_CHILD_C0_KEYING;
    set_cur_state(st);

    /* now. we need to go calculate the g^xy, if we want PFS (almost always do!!!) */
    {
        struct ke_continuation *ke = alloc_thing(struct ke_continuation
                                                 , "ikev2child_outC1 KE");
        stf_status e;

        ke->md = alloc_md();
        ke->md->from_state = STATE_CHILD_C1_REKEY;
        ke->md->svm = &ikev2_childrekey_microcode;
        ke->md->st  = st;
        ke->md->transition_state = st;  /* this have it's state transitioned by
                                        success_v2_state_transition */
        set_suspended(st, ke->md);

        if(c->policy & POLICY_PFS || !parentst->st_sec_in_use) {
            pcrc_init(&ke->ke_pcrc);
            ke->ke_pcrc.pcrc_func = ikev2child_outC1_continue;
            e = build_ke(&ke->ke_pcrc, st, st->st_oakley.group, pcim_stranger_crypto);
            if( (e != STF_SUSPEND && e != STF_INLINE) || (e == STF_TOOMUCHCRYPTO)) {
                loglog(RC_CRYPTOFAILED, "system too busy");
                delete_state(st);
            }

        } else {
            /* this case is that st_sec already is initialized, not doing PFS,
             * but we still need a new random nonce
             */
            set_cur_state(st);
            fill_rnd_chunk(&st->st_ni, DEFAULT_NONCE_SIZE);
            e = ikev2child_outC1_tail((struct pluto_crypto_req_cont *)ke, NULL);
            complete_v2_state_transition(&ke->md, e);
            pfree(ke);
        }
        reset_globals();

        return e;
    }
}

static void
ikev2child_outC1_continue(struct pluto_crypto_req_cont *pcrc
                                , struct pluto_crypto_req *r
                                , err_t ugh)
{
    struct dh_continuation *dh = (struct dh_continuation *)pcrc;
    struct msg_digest *md = dh->md;
    struct state *const st = md->st;
    stf_status e;

    DBG(DBG_CONTROLMORE
        , DBG_log("ikev2 child outC1: calculating g^{xy}, sending C1"));

    if (st == NULL) {
        loglog(RC_LOG_SERIOUS, "%s: Request was disconnected from state",
               __FUNCTION__);
        if (dh->md)
            release_md(dh->md);
        return;
    }

    /* XXX should check out ugh */
    passert(ugh == NULL);
    passert(cur_state == NULL);
    passert(st != NULL);

    assert_suspended(st, dh->md);
    set_suspended(st,NULL);        /* no longer connected or suspended */

    set_cur_state(st);

    st->st_calculating = FALSE;

    e = ikev2child_outC1_tail(pcrc, r);

    if(dh->md != NULL) {
        complete_v2_state_transition(&dh->md, e);
        if(dh->md) release_md(dh->md);
    }
    reset_globals();

    passert(GLOBALS_ARE_RESET());
}

static stf_status
ikev2child_outC1_tail(struct pluto_crypto_req_cont *pcrc
                      , struct pluto_crypto_req *r       )
{
    struct dh_continuation *dh = (struct dh_continuation *)pcrc;
    struct msg_digest *md = dh->md;
    struct state *st      = md->st;
    struct connection *c = st->st_connection;
    struct ikev2_generic e;
    unsigned char *encstart;
    pb_stream      e_pbs, e_pbs_cipher;
    unsigned char *iv;
    int            ivsize;
    stf_status     ret;
    unsigned char *authstart;
    struct connection *c0 = NULL;
    enum phase1_role role;

    if (IKEv2_IS_ORIG_INITIATOR(st)) {
        role = INITIATOR;
    } else {
        role = RESPONDER;
    }

    if(c->policy & POLICY_PFS) {
        unpack_v2KE(st, r, &st->st_gi);
        unpack_nonce(&st->st_ni, r);
    }

    /* enable NAT-T keepalives, if necessary */
    ikev2_enable_nat_keepalives(st);

    /* beginning of data going out */
    authstart = reply_stream.cur;

    /* make sure HDR is at start of a clean buffer */
    zero(reply_buffer);
    init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer), "reply packet");

    openswan_log("starting rekey of CHILD SA for state=#%lu (expired) using PARENT SA #%lu as %s"
                 , st->st_replaced
                 , st->st_clonedfrom
                 , role == INITIATOR ? "INITIATOR" : "RESPONDER" );

    /* HDR out */
    {
        struct isakmp_hdr r_hdr = md->hdr;

        r_hdr.isa_version = IKEv2_MAJOR_VERSION << ISA_MAJ_SHIFT | IKEv2_MINOR_VERSION;
        r_hdr.isa_np    = ISAKMP_NEXT_v2E;
        r_hdr.isa_xchg  = ISAKMP_v2_CHILD_SA;

        /* we should set the I bit, if we are the original initiator of the
         * the parent SA.
         */
        r_hdr.isa_flags = ISAKMP_FLAGS_E|IKEv2_ORIG_INITIATOR_FLAG(st);
        r_hdr.isa_msgid = htonl(st->st_msgid);
        memcpy(r_hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
        memcpy(r_hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
        if (!out_struct(&r_hdr, &isakmp_hdr_desc, &reply_stream, &md->rbody))
            return STF_INTERNAL_ERROR;
    }

    e.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;
    pbs_set_np(&md->rbody, ISAKMP_NEXT_v2E);
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
    init_sub_pbs(&e_pbs, &e_pbs_cipher, "cleartext");
    encstart = e_pbs_cipher.cur;

    if(c->policy & POLICY_PFS) {
        /* send KE */
        if(!justship_v2KE(st, &st->st_gi, st->st_oakley.groupnum,  &e_pbs_cipher, ISAKMP_NEXT_v2Ni))
            return STF_INTERNAL_ERROR;
    }

    /* send NONCE */
    {
        struct ikev2_generic in;
        pb_stream pb;

        memset(&in, 0, sizeof(in));
        pbs_set_np(&e_pbs_cipher, ISAKMP_NEXT_v2Ni);
        in.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;

        if(!out_struct(&in, &ikev2_nonce_desc, &e_pbs_cipher, &pb) ||
           !out_raw(st->st_ni.ptr, st->st_ni.len, &pb, "IKEv2 nonce"))
            return STF_INTERNAL_ERROR;
        close_output_pbs(&pb);
    }

    /*
     * now, find an eligible child SA from the pending list, and emit
     * SA2(i), TSi and TSr and
     *    (v2N_USE_TRANSPORT_MODE notification in transport mode) for it .
     */
    c0 = st->st_connection;
    if(c0) {
        lset_t policy = c0->policy;
        chunk_t child_spi, notify_data;
        unsigned int next_payload = ISAKMP_NEXT_NONE;
        st->st_connection = c0;

        if( !(st->st_connection->policy & POLICY_TUNNEL) ) {
            next_payload = ISAKMP_NEXT_v2N;
        }

        ikev2_emit_ipsec_sa(md,&e_pbs_cipher,ISAKMP_NEXT_v2TSi,c0, policy);

        st->st_ts_this = ikev2_end_to_ts(&c0->spd.this, st->st_localaddr);
        st->st_ts_that = ikev2_end_to_ts(&c0->spd.that, st->st_remoteaddr);

	/* role is always INITIATOR, since we are making to a request */
        ikev2_calc_emit_ts(md, &e_pbs_cipher, INITIATOR, next_payload, c0, policy);

        if( !(st->st_connection->policy & POLICY_TUNNEL) ) {
            DBG_log("Initiator child policy is transport mode, sending v2N_USE_TRANSPORT_MODE");
            memset(&child_spi, 0, sizeof(child_spi));
            memset(&notify_data, 0, sizeof(notify_data));
            ship_v2N (ISAKMP_NEXT_NONE, ISAKMP_PAYLOAD_NONCRITICAL, 0,
                      &child_spi,
                      v2N_USE_TRANSPORT_MODE, &notify_data, &e_pbs_cipher);
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

        if(authloc == NULL || authloc < encstart) return STF_INTERNAL_ERROR;

        close_output_pbs(&e_pbs);
        close_output_pbs(&md->rbody);
        close_output_pbs(&reply_stream);

        ret = ikev2_encrypt_msg(md, role,
                                authstart,
                                iv, encstart, authloc,
                                &e_pbs, &e_pbs_cipher);

        if(ret != STF_OK) return ret;
    }

    /* let TCL hack it before we mark the length. */
    TCLCALLOUT("v2_rekeyChild", st, st->st_connection, md);

    /* keep it for a retransmit if necessary, but on initiator
     * we never do that, but send_packet() uses it.
     */
    freeanychunk(st->st_tpacket);
    clonetochunk(st->st_tpacket, reply_stream.start, pbs_offset(&reply_stream)
                 , "reply packet for ikev2_out_C1_tail");

    send_packet(st, __FUNCTION__, TRUE);

    /*
     * Delete previous retransmission event.
     */
    delete_event(st);
    event_schedule(EVENT_v2_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);

    return STF_OK;
}


/*
 * RESPOND to CHILD SA REKEY.
 *   There are two ways to respond: one routine has the KE in the packet
 *   (valid with or without POLICY_PFS).
 *   The other has no KE in the packet (valid only when !POLICY_PFS).
 *
 *     It is not an error to not-require PFS, and yet have an exponent:
 *      the initiator may have simply decided that there was no further entropy in g^xy
 *      (CHECK RFC7296 on this)
 *
 */

/* after calculating g^y */
static void ikev2child_inCI1_continue1(struct pluto_crypto_req_cont *pcrc
                                       , struct pluto_crypto_req *r
                                       , err_t ugh);

/* after calculating g^xy */
static void ikev2child_inCI1_continue2(struct pluto_crypto_req_cont *pcrc
                                       , struct pluto_crypto_req *r
                                       , err_t ugh);

/* process the packet and send reply */
static stf_status
ikev2child_inCI1_tail(struct msg_digest *md, struct state *st, bool dopfs);


static stf_status ikev2child_inCI1_pfs(struct msg_digest *md)
{
    struct state *st = md->st;

    /* if we are already processing a packet on this st, we will be unable
     * to start another crypto operation below */
    if (is_suspended(st)) {
        openswan_log("%s: already processing a suspended cyrpto operation "
                     "on this SA, duplicate will be dropped.", __func__);
	return STF_TOOMUCHCRYPTO;
    }

    loglog(RC_COMMENT, "msgid=%u CHILD_SA PFS rekey message received from %s:%u on %s (port=%d)"
           , md->msgid_received
           , ip_str(&md->sender), (unsigned)md->sender_port
           , md->iface->ip_dev->id_rname
           , md->iface->port);

    /* create a new parent event to rekey again */
    delete_event(st);
    event_schedule(EVENT_SO_DISCARD, 0, st);

    /* now. we need to go calculate our g^y, then calculate the g^xy */
    {
        struct ke_continuation *ke = alloc_thing(struct ke_continuation
                                                 , "ikev2child_inCI1 KE");
        stf_status e;

        ke->md = md;
        set_suspended(st, ke->md);

        pcrc_init(&ke->ke_pcrc);
        ke->ke_pcrc.pcrc_func = ikev2child_inCI1_continue1;
        e = build_ke(&ke->ke_pcrc, st, st->st_oakley.group, pcim_known_crypto);
        if( (e != STF_SUSPEND && e != STF_INLINE) || (e == STF_TOOMUCHCRYPTO)) {
            loglog(RC_CRYPTOFAILED, "system too busy");
            delete_state(st);
        }
        reset_globals();
        return e;
    }
}


static stf_status ikev2child_inCI1_nopfs(struct msg_digest *md)
{
    struct state *st = md->st;
    int rn;

    loglog(RC_COMMENT, "msgid=%u CHILD_SA no-PFS rekey message received from %s:%u on %s (port=%d)"
           , md->msgid_received
           , ip_str(&md->sender), (unsigned)md->sender_port
           , md->iface->ip_dev->id_rname
           , md->iface->port);

    /* process nonce coming in */
    rn = accept_v2_nonce(md, &st->st_ni, "Ni");
    if(rn != v2N_NOTHING_WRONG) {
        enum isakmp_xchg_types xchg = md->hdr.isa_xchg;
        send_v2_notification_enc(md, xchg, rn, NULL);
        loglog(RC_LOG_SERIOUS, "no valid Nonce payload found");
	return STF_INTERNAL_ERROR;
    }

    /* create a nonce for our reply */
    fill_rnd_chunk(&st->st_nr, DEFAULT_NONCE_SIZE);

    return ikev2child_inCI1_tail(md, st, FALSE);
}

stf_status ikev2child_inCI1(struct msg_digest *md)
{
    struct state *parentst = md->st;   /* this is parent state! */
    struct state *st;
    struct connection *c;
    enum phase1_role enc_role;
    stf_status ret;

    md->pst = parentst;
    c = parentst->st_connection;

    st = duplicate_state(parentst);
    st->st_msgid = md->msgid_received;
    insert_state(st);
    md->st = st;
    st->st_state   = md->from_state = STATE_CHILD_C1_REKEY;
    md->transition_state = st;
    set_cur_state(st);

    /* create a new parent event to rekey again */
    delete_event(st);
    event_schedule(EVENT_SO_DISCARD, 0, st);

    /* now decrypt payload and extract values */
    enc_role = IKEv2_ORIGINAL_ROLE(md->pst);
    DBG(DBG_CONTROLMORE, DBG_log("decrypting payload as %s",
			enc_role == INITIATOR ? "INITIATOR" : "RESPONDER" ));
    ret = ikev2_decrypt_msg(md, enc_role);
    if(ret != STF_OK) {
	    loglog(RC_LOG_SERIOUS, "unable to decrypt message");
	    delete_state(st);
	    return ret;
    }

    if (md->chain[ISAKMP_NEXT_v2KE]) {
        if (!(c->policy & POLICY_PFS)) {
                DBG_log("WARNING: ignoring v2KE exchange, "
                        "agreed on a non-PFS proposal");

        } else {
            /* we have negotiated PFS, and the remote sent us a v2KE
             * exchange */

            return ikev2child_inCI1_pfs(md);
        }

    } else if (c->policy & POLICY_PFS) {
        /* we negotiated a PFS proposal, but received no v2KE exchnage */
        DBG_log("WARNING: missing expected v2KE exchange, "
                "cannot proceed with agreed upon PFS proposal");
    }

    /* we have negotiated non-PFS proposal, and/or received no v2KE exchange */
    return ikev2child_inCI1_nopfs(md);
}

stf_status ikev2child_inI3(struct msg_digest *md)
{
	return ikev2child_inCI1(md);
}

/*
 * this function is called after g^y is calculated, in order to
 * start the calculation of g^xy
 */
static void ikev2child_inCI1_continue1(struct pluto_crypto_req_cont *pcrc
                                       , struct pluto_crypto_req *r
                                       , err_t ugh)
{
    /* first, gather up the crypto that just finished */
    struct ke_continuation *ke = (struct ke_continuation *)pcrc;
    struct msg_digest *md = ke->md;
    struct state *const st = md->st;
    stf_status e;
    v2_notification_t rn;

    DBG(DBG_CONTROLMORE
        , DBG_log("ikev2 child inCI1: calculated ke+nonce, calculating g^xy"));

    if (st == NULL) {
        loglog(RC_LOG_SERIOUS, "%s: Request was disconnected from state",
               __FUNCTION__);
        if (ke->md)
            release_md(ke->md);
        return;
    }

    /* XXX should check out ugh */
    passert(ugh == NULL);
    passert(cur_state == NULL);
    passert(st != NULL);

    assert_suspended(st, ke->md);
    set_suspended(st,NULL);        /* no longer connected or suspended */
    set_cur_state(st);

    st->st_calculating = FALSE;

    /* collect data out of pcrc */
    /* collect new NONCE */
    unpack_nonce(&st->st_nr, r);
    unpack_v2KE(st, r, &st->st_gr);

    /* Gi in */
    e = accept_v2_KE(md, st, &st->st_gi, "Gi");
    if(e != STF_OK) {
        /* feel something shoud be done with e */
        loglog(RC_LOG_SERIOUS, "no valid KE payload found");
        goto returnerr;
    }

    /* Ni in */
    rn = accept_v2_nonce(md, &st->st_ni, "Ni");
    if(rn != v2N_NOTHING_WRONG) {
        enum isakmp_xchg_types xchg = md->hdr.isa_xchg;
        send_v2_notification_enc(md, xchg, rn, NULL);
        loglog(RC_LOG_SERIOUS, "no valid Nonce payload found");
        goto returnerr;
    }

    /* now. we need to go calculate the g^xy */
    {
        struct dh_continuation *dh = alloc_thing(struct dh_continuation
                                                 , "ikev2_inCI1 KE");
        dh->md = md;
        set_suspended(st, dh->md);

        pcrc_init(&dh->dh_pcrc);
        dh->dh_pcrc.pcrc_func = ikev2child_inCI1_continue2;

        e = start_dh_v2(&dh->dh_pcrc, st, pcim_known_crypto, RESPONDER, st->st_oakley.groupnum);
        if(e != STF_SUSPEND && e != STF_INLINE) {
            loglog(RC_CRYPTOFAILED, "system too busy");
            delete_state(st);
        }
    }

    reset_globals();
    return;

 returnerr:
    /* error notification was already sent, kill the state */
    md->st = NULL;
    delete_state(st);
    reset_globals();
    return;
}

/*
 * this function is called after g^xy is calculated, and just collects
 * the results, and calls inC1_tail.
 */
static void ikev2child_inCI1_continue2(struct pluto_crypto_req_cont *pcrc
                                       , struct pluto_crypto_req *r
                                       , err_t ugh)
{
    struct dh_continuation *dh = (struct dh_continuation *)pcrc;
    struct msg_digest *md = dh->md;
    struct state *const st = md->st;
    stf_status e;

    DBG(DBG_CONTROLMORE
        , DBG_log("ikev2 child inCI1: calculated g^{xy}, sending R2"));
    if (st == NULL) {
        loglog(RC_LOG_SERIOUS, "%s: Request was disconnected from state",
               __FUNCTION__);
        if (dh->md)
            release_md(dh->md);
        return;
    }

    assert_suspended(st, dh->md);
    set_suspended(st,NULL);        /* no longer connected or suspended */
    set_cur_state(st);
    st->st_calculating = FALSE;
    passert(ugh == NULL);

    /* extract calculated values from r */
    finish_dh_v2(st, r);

    e = ikev2child_inCI1_tail(md, st, TRUE);

    if(dh->md != NULL) {
        complete_v2_state_transition(&dh->md, e);
        if(dh->md) release_md(dh->md);
    }
    reset_globals();

    passert(GLOBALS_ARE_RESET());
}

stf_status
ikev2child_inCI1_tail(struct msg_digest *md, struct state *st, bool dopfs)
{
    unsigned char *authstart;

    authstart = reply_stream.cur;

    /* at this point, the child will be the one making the transition */
    set_cur_state(st);
    md->transition_state = st;

    /* enable NAT-T keepalives, if necessary */
    ikev2_enable_nat_keepalives(st);

    /* send response */
    {
        unsigned char *encstart;
        unsigned char *iv;
        unsigned int ivsize;
        struct ikev2_generic e;
        pb_stream      e_pbs, e_pbs_cipher;
        stf_status     ret;

        /* make sure HDR is at start of a clean buffer */
        zero(reply_buffer);
        init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer), "reply packet");

        /* see if there is a child SA being proposed */
        if(md->chain[ISAKMP_NEXT_v2TSi] == NULL
           || md->chain[ISAKMP_NEXT_v2TSr] == NULL) {

            /* initiator didn't propose anything. Weird. Try unpending out end. */
            /* UNPEND XXX */
            openswan_log("No CHILD SA proposals received.");
            e.isag_np = ISAKMP_NEXT_NONE;
        } else {
            DBG_log("CHILD SA proposals received");
            e.isag_np = ISAKMP_NEXT_v2Nr;
        }

        /* HDR out */
        {
            struct isakmp_hdr r_hdr = md->hdr;

            /* let the isa_version reply be the same as what the sender had */
            r_hdr.isa_np    = ISAKMP_NEXT_v2E;
            r_hdr.isa_xchg  = ISAKMP_v2_CHILD_SA;
            r_hdr.isa_flags = ISAKMP_FLAGS_R|IKEv2_ORIG_INITIATOR_FLAG(st);
	    /* also let teh isa_msgid reply be the same as what sender sent */
            //r_hdr.isa_msgid = htonl(md->msgid_received);
            memcpy(r_hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
            memcpy(r_hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
            if (!out_struct(&r_hdr, &isakmp_hdr_desc, &reply_stream, &md->rbody))
                return STF_INTERNAL_ERROR;
        }

        /* insert an Encryption payload header */
        e.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;

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
        init_sub_pbs(&e_pbs, &e_pbs_cipher, "cleartext");
        encstart = e_pbs_cipher.cur;

        if(e.isag_np != ISAKMP_NEXT_NONE) {
            int v2_notify_num = 0;

            /* insert Nonce and KE (if PFS) */

	    if (! md->chain[ISAKMP_NEXT_v2Ni]) {
		    /* XXX: do we want to assert here? */
		    DBG_log("We are responding with a Ni, but didn't receive a Ni");
	    }

            if(!justship_v2Nonce(st,  &e_pbs_cipher, &st->st_nr, 0)) {
                return STF_INTERNAL_ERROR;
            }

            /* see if we are supposed to send the KE */
            if(dopfs) {
                if(!justship_v2KE(st, &st->st_gr, st->st_oakley.groupnum,  &e_pbs_cipher, 0))
                    return STF_INTERNAL_ERROR;
            }

            /* must have enough to build an CHILD_SA... go do that! */
            ret = ikev2_child_sa_respond(md, st, &e_pbs_cipher);
            if(ret > STF_FAIL) {
                v2_notify_num = ret - STF_FAIL;
                DBG(DBG_CONTROL,DBG_log("ikev2_child_sa_respond returned STF_FAIL with %s", enum_name(&ikev2_notify_names, v2_notify_num)))
            } else if(ret != STF_OK) {
                DBG_log("ikev2_child_sa_respond returned %s", stf_status_name(ret));
            }
        }

        ikev2_padup_pre_encrypt(md, &e_pbs_cipher);
        close_output_pbs(&e_pbs_cipher);

        {
            unsigned char *authloc = ikev2_authloc(md, &e_pbs);

            if(authloc == NULL || authloc < encstart) return STF_INTERNAL_ERROR;

            close_output_pbs(&e_pbs);

            close_output_pbs(&md->rbody);
            close_output_pbs(&reply_stream);

	    if (IKEv2_IS_ORIG_INITIATOR(md->pst)) {
		    DBG(DBG_CONTROLMORE, DBG_log("encrypting payload as INITIATOR"));
		    ret = ikev2_encrypt_msg(md, INITIATOR,
					    authstart,
					    iv, encstart, authloc,
					    &e_pbs, &e_pbs_cipher);
	    } else {
		    DBG(DBG_CONTROLMORE, DBG_log("encrypting payload as RESPONDER"));
		    ret = ikev2_encrypt_msg(md, RESPONDER,
					    authstart,
					    iv, encstart, authloc,
					    &e_pbs, &e_pbs_cipher);
	    }
            if(ret != STF_OK) return ret;
        }
    }
    return STF_OK;
}


/************************************************************************
 *
 * Processing of CR1 packet - CHILD_SA Responder in (on initiator)
 *
 * this processes the reply from the child rekey.
 * If PFS is enabled, the responder will have calculated a new g^y and sent it
 * to us, and we will calculate a new shared state by completing the DH operation.
 *
 * If No-PFS, then there will be no g^y, and the responder will have just sent us
 * a new nonce, and we proceed into the PRF and derive keys for the IPsec SA.
 */
static void ikev2child_inCR1_continue(struct pluto_crypto_req_cont *pcrc
                                       , struct pluto_crypto_req *r
                                      , err_t ugh);
static stf_status ikev2child_inCR1_tail(struct msg_digest *md, struct state *st);

static stf_status ikev2child_inCR1_decrypt(struct msg_digest *md)
{
    struct state *st = md->st;
    v2_notification_t rn;
    enum phase1_role enc_role;
    stf_status ret;

    /* now decrypt payload and extract values */
    enc_role = IKEv2_ORIGINAL_ROLE(st);
    DBG(DBG_CONTROLMORE, DBG_log("decrypting payload as %s",
			enc_role == INITIATOR ? "INITIATOR" : "RESPONDER" ));
    ret = ikev2_decrypt_msg(md, enc_role);
    if (ret == STF_IGNORE) {
        /* already handled in notification handler */
        return ret;

    } else if (ret != STF_OK) {
        /* something else went wrong */
        loglog(RC_LOG_SERIOUS, "unable to decrypt message");
        /* XXX maybe try rekey again? */
        return STF_FAIL;
    }

    /* Nr in */
    rn = accept_v2_nonce(md, &st->st_nr, "Nr");
    if(rn != v2N_NOTHING_WRONG) {
        enum isakmp_xchg_types xchg = md->hdr.isa_xchg;
        send_v2_notification_enc(md, xchg, rn, NULL);
        loglog(RC_LOG_SERIOUS, "no valid Nonce payload found");
        return STF_FAIL;
    }
    return STF_OK;
}

static stf_status ikev2child_inCR1_pfs(struct msg_digest *md)
{
    struct state *st = md->st;
    stf_status e;

    /* if we are already processing a packet on this st, we will be unable
     * to start another crypto operation below */
    if (is_suspended(st)) {
        openswan_log("%s: already processing a suspended cyrpto operation "
                     "on this SA, duplicate will be dropped.", __func__);
	return STF_TOOMUCHCRYPTO;
    }

    /* Gr in */
    e = accept_v2_KE(md, st, &st->st_gr, "Gr");
    if(e != STF_OK) {
        /* feel something should be done with e */
        loglog(RC_LOG_SERIOUS, "no valid KE payload found");
        md->st = NULL;
        delete_state(st);
        return STF_FAIL; /* XXX - invalid packet notify? */
    }

    /* now. we need to go calculate the g^xy */
    {
        struct dh_continuation *dh = alloc_thing(struct dh_continuation
                                                 , "ikev2_inCR1 KE");
        dh->md = md;
        set_suspended(st, dh->md);

        pcrc_init(&dh->dh_pcrc);
        dh->dh_pcrc.pcrc_func = ikev2child_inCR1_continue;

        e = start_dh_v2(&dh->dh_pcrc, st, pcim_known_crypto, INITIATOR, st->st_oakley.groupnum);
        if(e != STF_SUSPEND && e != STF_INLINE) {
            loglog(RC_CRYPTOFAILED, "system too busy..? but we initiated?");
            delete_state(st);
        }
        reset_globals();
        return e;
    }
}

stf_status ikev2child_inCR1(struct msg_digest *md)
{
    struct state *st = md->st;
    stf_status e;

    e = ikev2child_inCR1_decrypt(md);
    if(e != STF_OK) {
        return e;
    }

    if(md->chain[ISAKMP_NEXT_v2KE]) {
        return ikev2child_inCR1_pfs(md);
    } else {
	set_cur_state(st);
	md->transition_state = st;
        return ikev2child_inCR1_tail(md, st);
    }
}

/* We were expecting a positive acknowledgement to a CHILD_SA request we sent
 * out, instead we got an encrypted notification.  We will log it, and
 * cancel our request to avoid retransmission of the bad packet. */
stf_status ikev2child_inCR1_ntf(struct msg_digest *md)
{
    struct state *st = md->st;
    struct payload_digest *p;

    set_cur_state(st);

    for(p = md->chain[ISAKMP_NEXT_v2N]; p != NULL; p = p->next) {
        /* did we get any notifications that make sense */

        openswan_log("received notification %u: %s", p->payload.v2n.isan_type,
                     enum_name(&ikev2_notify_names, p->payload.v2n.isan_type));

    }

    DBG(DBG_CONTROL, DBG_log("cleaning up state #%lu", st->st_serialno));

    delete_event(st);
    delete_state(st);

    return STF_IGNORE;
}

/*
 * this function is called after g^xy is calculated on initiator,
 * and just collects the results, and calls inCR1_tail.
 */
static void ikev2child_inCR1_continue(struct pluto_crypto_req_cont *pcrc
                                       , struct pluto_crypto_req *r
                                       , err_t ugh)
{
    struct dh_continuation *dh = (struct dh_continuation *)pcrc;
    struct msg_digest *md = dh->md;
    struct state *const st = md->st;
    stf_status e;

    DBG(DBG_CONTROLMORE
        , DBG_log("ikev2 child inCR1: calculated g^{xy}, setting up CHILD SA"));
    if (st == NULL) {
        loglog(RC_LOG_SERIOUS, "%s: Request was disconnected from state",
               __FUNCTION__);
        if (dh->md)
            release_md(dh->md);
        return;
    }

    assert_suspended(st, dh->md);
    set_suspended(st, NULL);        /* no longer connected or suspended */
    set_cur_state(st);
    st->st_calculating = FALSE;
    md->transition_state = st;
    passert(ugh == NULL);

    /* extract calculated values from r */
    finish_dh_v2(st, r);

    e = ikev2child_inCR1_tail(md, st);

    if(dh->md != NULL) {
        complete_v2_state_transition(&dh->md, e);
        if(dh->md) release_md(dh->md);
    }
    reset_globals();

    passert(GLOBALS_ARE_RESET());
}

/*
 * this function validates that the Traffic Selectors that the responder selected
 * (and perhaps narrowed to), still fit into our policy.
 */
stf_status ikev2_child_validate_responder_proposal(struct msg_digest *md
                                                   , struct state *st)
{
    struct connection *c = st->st_connection;
    int best_tsi_i ,  best_tsr_i;
    int bestfit_n = -1;
    int bestfit_p = -1;
    int bestfit_pr= -1;

    struct payload_digest *const tsi_pd = md->chain[ISAKMP_NEXT_v2TSi];
    struct payload_digest *const tsr_pd = md->chain[ISAKMP_NEXT_v2TSr];
    struct traffic_selector tsi[16], tsr[16];

    const int tsi_n = ikev2_parse_ts(tsi_pd, tsi, elemsof(tsi));
    const int tsr_n = ikev2_parse_ts(tsr_pd, tsr, elemsof(tsr));

    DBG_log("checking TSi(%d)/TSr(%d) selectors, looking for exact match"
            , tsi_n,tsr_n);
    if (tsi_n < 0 || tsr_n < 0)
        return STF_FAIL + v2N_TS_UNACCEPTABLE;

    if (!(c->policy & POLICY_TUNNEL)) {
	int err = ikev2_validate_transport_proposal(c, st, INITIATOR,
						    tsi, tsr, tsi_n, tsr_n);
	if (err != v2N_NOTHING_WRONG)
	    return STF_FAIL + err;
    }

    {
        struct spd_route *sra ;
        sra = &c->spd;
        int bfit_n=ikev2_evaluate_connection_fit(c, st
                                                 ,sra
                                                 ,INITIATOR
                                                 ,tsi   ,tsr
                                                 ,tsi_n ,tsr_n);
        if (bfit_n > bestfit_n)
            {
                DBG(DBG_CONTROLMORE,
                    DBG_log(" prefix fitness found a better match c %s"
                            , c->name));
                int bfit_p =
                    ikev2_evaluate_connection_port_fit(c
                                                       ,sra
                                                       ,INITIATOR
                                                       ,tsi,tsr
                                                       ,tsi_n,tsr_n
                                                       , &best_tsi_i
                                                       , &best_tsr_i);
                if (bfit_p > bestfit_p) {
                    DBG(DBG_CONTROLMORE,
                        DBG_log("  port fitness found better match c %s, tsi[%d],tsr[%d]"
                                , c->name, best_tsi_i, best_tsr_i));
                    int bfit_pr =
                        ikev2_evaluate_connection_protocol_fit(c, sra
                                                               , INITIATOR
                                                               , tsi, tsr
                                                               , tsi_n, tsr_n
                                                               , &best_tsi_i
                                                               , &best_tsr_i);
                    if (bfit_pr > bestfit_pr ) {
                        DBG(DBG_CONTROLMORE,
                            DBG_log("   protocol fitness found better match c %s, tsi[%d],tsr[%d]"
                                    , c->name, best_tsi_i,
                                    best_tsr_i));
                        bestfit_p = bfit_p;
                        bestfit_n = bfit_n;
                    } else {
                        DBG(DBG_CONTROLMORE,
                            DBG_log("    protocol fitness rejected c %s",
                                    c->name));
                    }
                }
            }
        else
            DBG(DBG_CONTROLMORE, DBG_log("prefix range fit c %s c->name was rejected by port matching"
                                         , c->name));
    }

    if ( ( bestfit_n > 0 )  && (bestfit_p > 0))  {
        ip_subnet tmp_subnet_i;
        ip_subnet tmp_subnet_r;

        DBG(DBG_CONTROLMORE, DBG_log(("found an acceptable TSi/TSr Traffic Selector")));
        memcpy (&st->st_ts_this , &tsi[best_tsi_i],  sizeof(struct traffic_selector));
        memcpy (&st->st_ts_that , &tsr[best_tsr_i],  sizeof(struct traffic_selector));
        ikev2_print_ts(&st->st_ts_this);
        ikev2_print_ts(&st->st_ts_that);

        rangetosubnet(&st->st_ts_this.low,
                      &st->st_ts_this.high, &tmp_subnet_i);
        rangetosubnet(&st->st_ts_that.low,
                      &st->st_ts_that.high, &tmp_subnet_r);

        c->spd.this.client = tmp_subnet_i;
        c->spd.this.port = st->st_ts_this.startport;
        c->spd.this.protocol = st->st_ts_this.ipprotoid;
        setportof(htons(c->spd.this.port),
                  &c->spd.this.host_addr);
        setportof(htons(c->spd.this.port),
                  &c->spd.this.client.addr);

        c->spd.this.has_client =
            !(subnetishost(&c->spd.this.client) &&
              addrinsubnet(&c->spd.this.host_addr,
                           &c->spd.this.client));

        c->spd.that.client = tmp_subnet_r;
        c->spd.that.port = st->st_ts_that.startport;
        c->spd.that.protocol = st->st_ts_that.ipprotoid;
        setportof(htons(c->spd.that.port),
                  &c->spd.that.host_addr);
        setportof(htons(c->spd.that.port),
                  &c->spd.that.client.addr);

        c->spd.that.has_client =
            !(subnetishost(&c->spd.that.client) &&
              addrinsubnet(&c->spd.that.host_addr,
                           &c->spd.that.client));
    }
    else {
        DBG(DBG_CONTROLMORE, DBG_log(("reject responder TSi/TSr Traffic Selector")));
        // prevents parent from going to I3
        return STF_FAIL + v2N_TS_UNACCEPTABLE;
    }

    return STF_OK;
}

stf_status ikev2_child_notify_process(struct msg_digest *md
                                      , struct state *st)
{
    struct payload_digest *p;

    for(p = md->chain[ISAKMP_NEXT_v2N]; p != NULL; p = p->next) {
        /* RFC 5996 */
        /* Types in the range 0 - 16383 are intended for reporting errors.
         * An implementation receiving a Notify payload with one of these
         * types that it does not recognize in a response MUST assume
         * that the corresponding request has failed entirely.
         * Unrecognized error types in a request and status types in a
         * request or response MUST be
         * ignored, and they should be logged.
         */
        if(enum_name(&ikev2_notify_names, p->payload.v2n.isan_type) == NULL) {
            if(p->payload.v2n.isan_type < v2N_INITIAL_CONTACT) {
                return STF_FAIL + p->payload.v2n.isan_type;
            }
        }

        if ( p->payload.v2n.isan_type == v2N_USE_TRANSPORT_MODE ) {
            if ( st->st_connection->policy & POLICY_TUNNEL) {
                /*This means we did not send v2N_USE_TRANSPORT, however responder is sending it in now (inR2), seems incorrect*/
                DBG(DBG_CONTROLMORE,
                    DBG_log("Initiator policy is tunnel, responder sends v2N_USE_TRANSPORT_MODE notification in inR2, ignoring it"));
            }
            else {
                DBG(DBG_CONTROLMORE,
                    DBG_log("Initiator policy is transport, responder sends v2N_USE_TRANSPORT_MODE, setting CHILD SA to transport mode"));
                if (st->st_esp.present == TRUE) {
                    /*openswan supports only "esp" with ikev2 it seems, look at ikev2_parse_child_sa_body handling*/
                    st->st_esp.attrs.encapsulation = ENCAPSULATION_MODE_TRANSPORT;
                }
            }
        }
    } /* for */
    return STF_OK;
}

static stf_status ikev2child_inCR1_tail(struct msg_digest *md, struct state *st)
{
    struct connection *c = st->st_connection;
    struct state *pst;
    stf_status e;

    /* authentication good, see if there is a child SA available */
    if(md->chain[ISAKMP_NEXT_v2SA] == NULL
       || md->chain[ISAKMP_NEXT_v2TSi] == NULL
       || md->chain[ISAKMP_NEXT_v2TSr] == NULL) {
        /* not really anything to here... but it would be worth unpending again */
        DBG(DBG_CONTROLMORE, DBG_log("no v2SA, v2TSi or v2TSr received child trying to rekey CHILD_SA."));
        DBG(DBG_CONTROLMORE, DBG_log("  look for notify of error"));
        /*
         * Delete previous retransmission event.
         */
        delete_event(st);
        return STF_OK;
    }

    /* Check TSi/TSr http://tools.ietf.org/html/rfc5996#section-2.9 */
    DBG(DBG_CONTROLMORE,DBG_log(" checking narrowing - responding to CR1"));

    if ((e = ikev2_child_validate_responder_proposal(md, st)) != STF_OK) {
        return e;
    }

    if ((e = ikev2_child_notify_process(md, st)) != STF_OK) {
        return e;
    }

    {
        v2_notification_t rn;
        struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
        if (sa_pd == NULL) {
                return STF_FAIL;
        }

        rn = ikev2_parse_child_sa_body(&sa_pd->pbs, &sa_pd->payload.v2sa
                                       , NULL, st, /* selection=*/TRUE);

        if(rn != v2N_NOTHING_WRONG)
            return STF_FAIL + rn;
    }

    e = ikev2_derive_child_keys(st, INITIATOR);
    if (e != STF_OK)
	return e;

    c->newest_ipsec_sa = st->st_serialno;

    pst = st;
    if(st->st_clonedfrom != 0) {
        pst = state_with_serialno(st->st_clonedfrom);
    }

    /* now install child SAs */
    if(!install_ipsec_sa(pst, st, TRUE)) {
#ifdef DEBUG_WITH_PAUSE
        pause();
#endif
        loglog(RC_LOG_SERIOUS, "failed to installed IPsec Child SAs");
        return STF_FATAL;
    }

    /*
     * Delete previous retransmission event.
     */
    delete_event(st);

    return STF_OK;
}




/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */

