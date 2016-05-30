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
#include "state.h"
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
                              , unsigned int next_payload
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
	ret = ikev2_emit_ts(md, outpbs, ISAKMP_NEXT_v2TSr, ts_i);
	if(ret!=STF_OK) return ret;

        ret = ikev2_emit_ts(md, outpbs, next_payload, ts_r);
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

    DBG(DBG_CONTROLMORE,
    {
	char ei3[SUBNETTOT_BUF];
	char er3[SUBNETTOT_BUF];
        if(ei->has_client) {
            subnettot(&ei->client,  0, ei3, sizeof(ei3));
        } else {
            strcpy(ei3, "<noclient>");

            /* here, fill in new end with actual client info from the state */
            if(ei->host_type == KH_ANY) {
                fei = *ei;
                ei  = &fei;
                strcpy(ei3, "<self>");
                addrtosubnet(&st->st_remoteaddr, &fei.client);
            }
        }

        if(er->has_client) {
            subnettot(&er->client,  0, er3, sizeof(er3));
        } else {
            strcpy(er3, "<noclient");

            /* here, fill in new end with actual client info from the state */
            if(er->host_type == KH_ANY) {
                fer = *er;
                er  = &fer;
                strcpy(er3, "<self>");
                addrtosubnet(&st->st_remoteaddr, &fer.client);
            }
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
                                  , pb_stream *outpbs)
{
    struct state      *st = md->st;
    struct state      *st1= st;
    struct connection *c  = st->st_connection;
    /* struct connection *cb; */
    struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
    stf_status ret;
    struct payload_digest *const tsi_pd = md->chain[ISAKMP_NEXT_v2TSi];
    struct payload_digest *const tsr_pd = md->chain[ISAKMP_NEXT_v2TSr];
    struct traffic_selector tsi[16], tsr[16];
    unsigned int tsi_n, tsr_n;

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
            int bfit_n=ikev2_evaluate_connection_fit(c,st,sra,RESPONDER,tsi,tsr,tsi_n,
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
                      && trusted_ca(c->spd.that.ca, d->spd.that.ca, &pathlen)))
                    continue;


                for (sr = &d->spd; sr != NULL; sr = sr->next) {
                    newfit=ikev2_evaluate_connection_fit(d,st, sr,RESPONDER
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
            b = rw_instantiate(b, &st->st_remoteaddr,
                               NULL,
                               &st->ikev2.st_peer_id);
        }

        if (b != c)
	{
            char instance[1 + 10 + 1];

            openswan_log("switched from \"%s\" to \"%s\"%s", c->name, b->name
                         , fmt_connection_inst_name(b, instance, sizeof(instance)));

	    st->st_connection = b;	/* kill reference to c */

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

        /* we are sure, so lets make a state for this child SA */
        st1 = duplicate_state(st);
        insert_state(st1);

        st1->st_ts_this = ikev2_end_to_ts(&bsr->this, st->st_localaddr);
        st1->st_ts_that = ikev2_end_to_ts(&bsr->that, st->st_remoteaddr);
        ikev2_print_ts(&st1->st_ts_this);
        ikev2_print_ts(&st1->st_ts_that);
    }

    /* note that st1 starts == st, but a child SA creation can change that */
    st1->st_connection = c;
    md->st = st1;
    md->pst= st;

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

        /* we do not delete_state st1 yet, because initiator could retransmit */
        if (rn != NOTHING_WRONG) {
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

    ikev2_derive_child_keys(st1, RESPONDER);
    /* install inbound and outbound SPI info */
    if(!install_ipsec_sa(st, st1, TRUE))
        return STF_FATAL;

    /* mark the connection as now having an IPsec SA associated with it. */
    st1->st_connection->newest_ipsec_sa = st1->st_serialno;

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


stf_status ikev2child_outC1(int whack_sock UNUSED
                            , struct state *parentst
                            , struct connection *c
                            , lset_t policy UNUSED
                            , unsigned long try /* how many attempts so far */ UNUSED
                            , so_serial_t replacing  UNUSED
                            , struct xfrm_user_sec_ctx_ike * uctx UNUSED
                            )
{
    struct state *st;
    stf_status ret = STF_FAIL;

    /* okay, got a transmit slot, make a child state to send this. */
    st = duplicate_state(parentst);
    ret = allocate_msgid_from_parent(parentst, &st->st_msgid);

    if(ret != STF_OK) return ret;

    insert_state(st);

    /* create a new parent event to rekey again */
    delete_event(parentst);
    event_schedule(EVENT_SA_REPLACE, c->sa_ike_life_seconds, parentst);

    /* XXX -- this needs a new child state value */
    //change_state(st, STATE_PARENT_I2);

    // XXX do something with replacing!

    /* now. we need to go calculate the g^xy, if we want PFS (almost always do!!!) */
    {
        struct ke_continuation *ke = alloc_thing(struct ke_continuation
                                                 , "ikev2child_outC1 KE");
        stf_status e;

        ke->md = alloc_md();
        ke->md->from_state = STATE_CHILD_C1_REKEY;
        ke->md->svm = &ikev2_parent_firststate_microcode;
        ke->md->st  = st;
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
            /* this case is that st_sec already is initialized */
            e = ikev2child_outC1_tail((struct pluto_crypto_req_cont *)ke, NULL);
        }

        reset_globals();

        return e;
    }
}


#if 0
    /* beginning of data going out */
    authstart = reply_stream.cur;

    /* make sure HDR is at start of a clean buffer */
    zero(reply_buffer);
    init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer), "reply packet");


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
        v2_notification_t rn;

        /* SA body in and out */
        rn = ikev2_parse_parent_sa_body(&sa_pd->pbs, &sa_pd->payload.v2sa,
                                        NULL, st, FALSE);

        if (rn != v2N_NOTHING_WRONG)
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

        pcrc_init(&dh->dh_pcrc);
        dh->dh_pcrc.pcrc_func = ikev2_parent_inR1outI2_continue;
        e = start_dh_v2(&dh->dh_pcrc, st, st->st_import, INITIATOR, st->st_oakley.groupnum);
        if(e != STF_SUSPEND && e != STF_INLINE) {
            loglog(RC_CRYPTOFAILED, "system too busy");
            delete_state(st);
        }

        reset_globals();

        return e;
    }
#endif

static void
ikev2child_outC1_continue(struct pluto_crypto_req_cont *pcrc UNUSED
                                , struct pluto_crypto_req *r   UNUSED
                                , err_t ugh UNUSED)
{
#if 0
    struct dh_continuation *dh = (struct dh_continuation *)pcrc;
    struct msg_digest *md = dh->md;
    struct state *const st = md->st;
    stf_status e;

    DBG(DBG_CONTROLMORE
        , DBG_log("ikev2 parent inR1outI2: calculating g^{xy}, sending I2"));

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

    passert(st->st_suspended_md == dh->md);
    set_suspended(st,NULL);        /* no longer connected or suspended */

    set_cur_state(st);

    st->st_calculating = FALSE;

    e = ikev2_parent_inR1outI2_tail(pcrc, r);

    if(dh->md != NULL) {
        complete_v2_state_transition(&dh->md, e);
        if(dh->md) release_md(dh->md);
    }
#endif
    reset_globals();

    passert(GLOBALS_ARE_RESET());
}

static stf_status
ikev2child_outC1_tail(struct pluto_crypto_req_cont *pcrc UNUSED
                      , struct pluto_crypto_req *r       UNUSED)
{
#if 0
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
    msgid_t        mid = INVALID_MSGID;
    bool send_cert = FALSE;

    finish_dh_v2(st, r);

    if(DBGP(DBG_PRIVATE) && DBGP(DBG_CRYPT)) {
        ikev2_log_parentSA(st);
    }

    pst = st;
    ret = allocate_msgid_from_parent(pst, &mid);
    if(ret != STF_OK) {
        /*
         * XXX: need to return here, having enqueued our pluto_crypto_req_cont
         * onto a structure on the parent for processing when there is message
         * ID available.
         */
        return ret;
    }

    /* okay, got a transmit slot, make a child state to send this. */
    st = duplicate_state(pst);

    st->st_msgid = mid;
    insert_state(st);
    md->st = st;
    md->pst= pst;

    /* parent had crypto failed, replace it with rekey! */
    delete_event(pst);
    event_schedule(EVENT_SA_REPLACE, c->sa_ike_life_seconds, pst);

    /* need to force parent state to I2 */
    change_state(pst, STATE_PARENT_I2);

    /* record first packet for later checking of signature */
    clonetochunk(pst->st_firstpacket_him, md->message_pbs.start
                 , pbs_offset(&md->message_pbs), "saved first received packet");

    /* beginning of data going out */
    authstart = reply_stream.cur;

    /* make sure HDR is at start of a clean buffer */
    zero(reply_buffer);
    init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer), "reply packet");

    /* HDR out */
    {
        struct isakmp_hdr r_hdr = md->hdr;

        /* should be set to version received */
        // r_hdr.isa_version = IKEv2_MAJOR_VERSION << ISA_MAJ_SHIFT | IKEv2_MINOR_VERSION;
        r_hdr.isa_np    = ISAKMP_NEXT_v2E;
        r_hdr.isa_xchg  = ISAKMP_v2_AUTH;
        r_hdr.isa_flags = ISAKMP_FLAGS_I;
        r_hdr.isa_msgid = htonl(st->st_msgid);
        memcpy(r_hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
        memcpy(r_hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
        if (!out_struct(&r_hdr, &isakmp_hdr_desc, &reply_stream, &md->rbody))
            return STF_INTERNAL_ERROR;
    }

    /* insert an Encryption payload header */
    e.isag_np = ISAKMP_NEXT_v2IDi;
    e.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;
    if(DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
        openswan_log(" setting bogus ISAKMP_PAYLOAD_OPENSWAN_BOGUS flag in ISAKMP payload");
        e.isag_critical |= ISAKMP_PAYLOAD_OPENSWAN_BOGUS;
    }

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

        hmac_init_chunk(&id_ctx, pst->st_oakley.prf_hasher, pst->st_skey_pi);
        build_id_payload((struct isakmp_ipsec_id *)&r_id, &id_b, &c->spd.this);
        r_id.isai_critical = ISAKMP_PAYLOAD_NONCRITICAL;
        if(DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
            openswan_log(" setting bogus ISAKMP_PAYLOAD_OPENSWAN_BOGUS flag in ISAKMP payload");
            r_id.isai_critical |= ISAKMP_PAYLOAD_OPENSWAN_BOGUS;
        }

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
        idhash = alloca(pst->st_oakley.prf_hasher->hash_digest_len);
        hmac_final(idhash, &id_ctx);
    }

    /* send [CERT,] payload RFC 4306 3.6, 1.2) */
    {

        if(send_cert) {
            stf_status certstat = ikev2_send_cert( st, md
                                                       , INITIATOR
                                                   , ISAKMP_NEXT_v2AUTH
                                                   , &e_pbs_cipher);
            if(certstat != STF_OK) return certstat;
        }
    }

    /* send out the AUTH payload */
    {
        lset_t policy;
        struct connection *c0= first_pending(pst, &policy,&st->st_whack_sock);
        unsigned int np = (c0 ? ISAKMP_NEXT_v2SA : ISAKMP_NEXT_NONE);
        DBG(DBG_CONTROL,DBG_log(" payload after AUTH will be %s", (c0) ? "ISAKMP_NEXT_v2SA" : "ISAKMP_NEXT_NONE/NOTIFY"));

        stf_status authstat = ikev2_send_auth(c, st
                                              , INITIATOR
                                              , np
                                              , idhash, &e_pbs_cipher);
        if(authstat != STF_OK) return authstat;

        /*
         * now, find an eligible child SA from the pending list, and emit
         * SA2i, TSi and TSr and (v2N_USE_TRANSPORT_MODE notification in transport mode) for it .
         */
        if(c0) {
            chunk_t child_spi, notify_data;
            unsigned int next_payload = ISAKMP_NEXT_NONE;
            st->st_connection = c0;

            if( !(st->st_connection->policy & POLICY_TUNNEL) ) {
                next_payload = ISAKMP_NEXT_v2N;
            }

	    ikev2_emit_ipsec_sa(md,&e_pbs_cipher,ISAKMP_NEXT_v2TSi,c0, policy);

	    st->st_ts_this = ikev2_end_to_ts(&c0->spd.this, st->st_localaddr);
	    st->st_ts_that = ikev2_end_to_ts(&c0->spd.that, st->st_remoteaddr);

	    ikev2_calc_emit_ts(md, &e_pbs_cipher, INITIATOR, next_payload, c0, policy);

            if( !(st->st_connection->policy & POLICY_TUNNEL) ) {
                DBG_log("Initiator child policy is transport mode, sending v2N_USE_TRANSPORT_MODE");
                memset(&child_spi, 0, sizeof(child_spi));
                memset(&notify_data, 0, sizeof(notify_data));
                ship_v2N (ISAKMP_NEXT_NONE, ISAKMP_PAYLOAD_NONCRITICAL, 0,
                          &child_spi,
                          v2N_USE_TRANSPORT_MODE, &notify_data, &e_pbs_cipher);
            }
        } else {
            openswan_log("no pending SAs found, PARENT SA keyed only");
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
    freeanychunk(pst->st_tpacket);
    clonetochunk(pst->st_tpacket, reply_stream.start, pbs_offset(&reply_stream)
                 , "reply packet for ikev2_parent_outI1");

    /*
     * Delete previous retransmission event.
     */
    delete_event(st);
    event_schedule(EVENT_v2_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);

    return STF_OK;
#endif
    return STF_FAIL;
}


/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */

