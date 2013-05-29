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
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "packet.h"
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "ike_alg.h"
#include "log.h"
#include "demux.h"        /* needs packet.h */
#include "ikev2.h"
#include "ipsec_doi.h"        /* needs demux.h and state.h */
#include "timer.h"
#include "whack.h"        /* requires connections.h */
#include "server.h"
#include "vendor.h"
#include "dpd.h"
#include "udpfromto.h"
#include "tpm/tpm.h"
#include "kernel.h"
#include "virtual.h"
#include "hostpair.h"

/* rewrite me with addrbytesptr() */
struct traffic_selector ikev2_subnettots(struct end *e)
{
    struct traffic_selector ts;
    struct in6_addr v6mask;

    memset(&ts, 0, sizeof(ts));

    switch(e->client.addr.u.v4.sin_family) {
    case AF_INET:
        ts.ts_type = IKEv2_TS_IPV4_ADDR_RANGE;
        ts.low   = e->client.addr;
        ts.low.u.v4.sin_addr.s_addr  &= bitstomask(e->client.maskbits).s_addr;
        ts.high  = e->client.addr;
        ts.high.u.v4.sin_addr.s_addr |= ~bitstomask(e->client.maskbits).s_addr;
        break;

    case AF_INET6:
        ts.ts_type = IKEv2_TS_IPV6_ADDR_RANGE;
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

    /* Setting ts_type IKEv2_TS_FC_ADDR_RANGE (RFC-4595) not yet supproted */

    /*
     * The IKEv2 code used to send 0-65535 as port regardless of
     * the local policy specified. if local policy states a specific
     * protocol and port, then send that protocol value and port to
     * other end  -- Avesh
     * Paul: TODO: I believe IKEv2 allows multiple port ranges?
     */

    DBG(DBG_CONTROLMORE,
        {
        DBG_log("local policy host_addr-port=%d, client-port=%d, port=%d, protocol=%d, has_port_wildcard=%d",
                ntohs(e->host_addr.u.v4.sin_port), ntohs(e->client.addr.u.v4.sin_port)
                , e->port, e->protocol, e->has_port_wildcard);
        }
    );

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

        ts.next = NULL;

    return ts;
}

void
ikev2_store_ts_instate(struct traffic_selector *array_tsi
                ,struct traffic_selector * array_tsr
                , unsigned int tsi_n
                , unsigned int tsr_n
                , struct traffic_selector *ts_this
                , struct traffic_selector *ts_that)
{
        unsigned int i;
        struct traffic_selector *curts, *prevts;

        prevts = NULL;
        curts = ts_this;
        for(i=0; i<tsi_n; i++) {
                if(curts == NULL) {
                curts = alloc_thing(struct traffic_selector, "struct traffic_selector");
                }

                *curts = array_tsi[i];
                curts->next = NULL;

                if(prevts!= NULL) {
                prevts->next = curts;
                }

                prevts = curts;
                curts = curts->next;
        }

        prevts = NULL;
        curts = ts_that;

        for(i=0; i<tsr_n; i++) {
                if(curts == NULL) {
                curts = alloc_thing(struct traffic_selector, "struct traffic_selector");
                }

                *curts = array_tsr[i];
                curts->next = NULL;

                if(prevts!= NULL) {
                prevts->next = curts;
                }

                prevts = curts;
                curts = curts->next;
        }
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
    struct traffic_selector *tmp=ts;

    its.isat_np = np;
    its.isat_critical = ISAKMP_PAYLOAD_NONCRITICAL;

    its.isat_num = 0;
    while(tmp!=NULL) {
        its.isat_num++;
        tmp = tmp->next;
    }

    if(!out_struct(&its, &ikev2_ts_desc, outpbs, &ts_pbs))
        return STF_INTERNAL_ERROR;

   while(ts!=NULL) {

    switch(ts->ts_type) {
    case IKEv2_TS_IPV4_ADDR_RANGE:
        its1.isat1_type = IKEv2_TS_IPV4_ADDR_RANGE;
        its1.isat1_sellen = 16;
        break;
    case IKEv2_TS_IPV6_ADDR_RANGE:
        its1.isat1_type = IKEv2_TS_IPV6_ADDR_RANGE;
        its1.isat1_sellen = 40;
        break;
    case IKEv2_TS_FC_ADDR_RANGE:
        DBG_log("IKEv2 Traffic Selector IKEv2_TS_FC_ADDR_RANGE not yet supported");
        return STF_INTERNAL_ERROR;
    default:
        DBG_log("IKEv2 Traffic Selector type '%d' not supported", ts->ts_type);
    }

    /*
     * The IKEv2 code used to send 0-65535 as port regardless of
     * the local policy specified. if local policy states a specific
     * protocol and port, then send that protocol value and port to
     * other end  -- Avesh
     * Paul: TODO: I believe IKEv2 allows multiple port ranges?
     */

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
    ts = ts->next;
    }

    close_output_pbs(&ts_pbs);

    return STF_OK;
}

bool
ikev2_perfect_match_ts(struct traffic_selector *tsi
                ,struct traffic_selector *tsr
                , unsigned int tsi_n
                , unsigned int tsr_n UNUSED
                , struct connection *c
                , enum phase1_role role)
{
        struct end *ei, *er;
        struct traffic_selector tmpi, tmpr;

        if(tsi_n > 1 ||  tsi_n > 1) {
                return FALSE;
        }

        if(role == INITIATOR) {
                ei = &c->spd.this;
                er = &c->spd.that;
        } else {
                ei = &c->spd.that;
                er = &c->spd.this;
        }

        tmpi = ikev2_subnettots(ei);
        tmpr = ikev2_subnettots(er);

        if(addrcmp(&tmpi.low, &tsi[0].low) == 0
                && addrcmp(&tmpi.high, &tsi[0].high) == 0
                && tmpi.startport == tsi[0].startport
                && tmpi.endport == tsi[0].endport
                && tmpi.ipprotoid == tsi[0].ipprotoid
                && addrcmp(&tmpr.low, &tsr[0].low) == 0
                && addrcmp(&tmpr.high, &tsr[0].high) == 0
                && tmpr.startport == tsr[0].startport
                && tmpr.endport == tsr[0].endport
                && tmpr.ipprotoid == tsr[0].ipprotoid)
        {
                return TRUE;
        }

        return FALSE;
}

stf_status ikev2_calc_emit_ts(struct msg_digest *md
                              , pb_stream *outpbs
                              , enum phase1_role role
                              , struct connection *c0 UNUSED
                              , lset_t policy UNUSED)
{
    struct state *st = md->st;
    struct traffic_selector *ts_i, *ts_r;
    stf_status ret;


    if(role == INITIATOR) {
        ts_i = &st->st_ts_this;
        ts_r = &st->st_ts_that;
    } else {
        ts_i = &st->st_ts_that;
        ts_r = &st->st_ts_this;
    }

        ret = ikev2_emit_ts(md, outpbs, ISAKMP_NEXT_v2TSr
                            , ts_i, INITIATOR);
        if(ret!=STF_OK) return ret;

        if(role == INITIATOR) {
        ret = ikev2_emit_ts(md, outpbs, st->st_connection->policy & POLICY_TUNNEL ? ISAKMP_NEXT_NONE : ISAKMP_NEXT_v2N
                            , ts_r, RESPONDER);
        }
        else {
                struct payload_digest *p;
                for(p = md->chain[ISAKMP_NEXT_v2N]; p != NULL; p = p->next)
                {
                        if ( p->payload.v2n.isan_type == v2N_USE_TRANSPORT_MODE ) {
                        DBG_log("Received v2N_USE_TRANSPORT_MODE from the other end, next payload is v2N_USE_TRANSPORT_MODE notification");
                        ret = ikev2_emit_ts(md, outpbs, ISAKMP_NEXT_v2N
                                                , ts_r, RESPONDER);
                        break;
                        }
                }
                if(!p){
                        ret = ikev2_emit_ts(md, outpbs, ISAKMP_NEXT_NONE
                                                , ts_r, RESPONDER);
                }
        }

        if(ret!=STF_OK) return ret;

    return STF_OK;
}

bool
ikev2_verify_ts(struct traffic_selector *tsi
                , struct traffic_selector *tsr
                , unsigned int ntsi
                , unsigned int ntsr
                , struct traffic_selector *this_ts
                , struct traffic_selector *that_ts
                , enum phase1_role role)
{
        unsigned int i;
        struct traffic_selector *tmptsi, *tmptsr;


        if(role == INITIATOR) {
                tmptsi = this_ts;
                tmptsr = that_ts;
        }
        else {
                tmptsi = that_ts;
                tmptsr = this_ts;
        }

        for(i = 0; i < ntsi; i++ ) {

                /* verify addresses*/
                if(addrcmp(&tmptsi->low, &tsi[i].low) > 0
                        || addrcmp(&tmptsi->high, &tsi[i].high) < 0)
                {
                        return FALSE;
                }

                /* verify port */
                if(tmptsi->startport > tsi[i].startport
                        || tmptsi->endport < tsi[i].endport)
                {
                        return FALSE;
                }

                /* verify protocol */
                if( tmptsi->ipprotoid !=0
                        && tmptsi->ipprotoid != tsi[i].ipprotoid)
                {
                        return FALSE;
                }
        }

        for(i = 0; i < ntsr; i++ ) {

                /* verify addresses*/
                if(addrcmp(&tmptsr->low, &tsr[i].low) > 0
                        || addrcmp(&tmptsr->high, &tsr[i].high) < 0)
                {
                        return FALSE;
                }

                /* verify port */
                if(tmptsr->startport > tsr[i].startport
                        || tmptsr->endport < tsr[i].endport)
                {
                        return FALSE;
                }

                /* verify protocol */

                if( tmptsr->ipprotoid !=0
                        && tmptsr->ipprotoid != tsr[i].ipprotoid)
                {
                        return FALSE;
                }
        }
        return TRUE;
}

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
#ifdef NEED_SIN_LEN
                array[i].low.u.v4.sin_len = sizeof( struct sockaddr_in);
#endif
                if(!in_raw(&array[i].low.u.v4.sin_addr.s_addr, 4, &addr, "ipv4 ts"))
                    return -1;

                array[i].high.u.v4.sin_family = AF_INET;
#ifdef NEED_SIN_LEN
                array[i].high.u.v4.sin_len = sizeof( struct sockaddr_in);
#endif

                if(!in_raw(&array[i].high.u.v4.sin_addr.s_addr, 4, &addr, "ipv4 ts"))
                    return -1;
                break;

            case IKEv2_TS_IPV6_ADDR_RANGE:
                array[i].ts_type = IKEv2_TS_IPV6_ADDR_RANGE;
                array[i].low.u.v6.sin6_family  = AF_INET6;
#ifdef NEED_SIN_LEN
                array[i].low.u.v6.sin6_len = sizeof( struct sockaddr_in6);
#endif

                if(!in_raw(&array[i].low.u.v6.sin6_addr.s6_addr, 16, &addr, "ipv6 ts"))
                    return -1;

                array[i].high.u.v6.sin6_family = AF_INET6;
#ifdef NEED_SIN_LEN
                array[i].high.u.v6.sin6_len = sizeof( struct sockaddr_in6);
#endif

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

static bool
ikev2_narrowing(struct connection *c
                  , enum phase1_role role
                  , struct traffic_selector *tsi
                  , struct traffic_selector *tsr
                  , unsigned int tsi_n
                  , unsigned int tsr_n
                  , struct traffic_selector **narrowed_tsi
                  , struct traffic_selector **narrowed_tsr
                  , struct connection **result)
{
struct host_pair *hp = NULL;
struct connection *d;
unsigned int i;
struct end *ei, *er;
int  bests=0;
struct connection *bestc=NULL;
#if 0
bool specific_first_ts = FALSE;
#endif


        hp = find_host_pair(&c->spd.this.host_addr
                                , c->spd.this.host_port
                                , &c->spd.that.host_addr
                                , c->spd.that.host_port);

#ifdef DEBUG
        if (DBGP(DBG_CONTROLMORE))
        {
                char s2[SUBNETTOT_BUF],d2[SUBNETTOT_BUF];

                subnettot(&c->spd.this.client, 0, s2, sizeof(s2));
                subnettot(&c->spd.that.client, 0, d2, sizeof(d2));

                DBG_log("  checking hostpair %s -> %s is %s"
                        , s2, d2
                        , (hp ? "found" : "not found"));
        }
#endif /* DEBUG */

        if(!hp) {
                return FALSE;
        }

#if 0
        /* check if there is any specific first traffic selector */
        if( addrcmp(&tsi[0].low, &tsi[0].high)==0 && tsi[0].startport == tsi[0].endport &&  tsi[0].ipprotoid!=0
                && addrcmp(&tsr[0].low, &tsr[0].high)==0 && tsr[0].startport ==  tsr[0].endport &&  tsr[0].ipprotoid!=0) {
                specific_first_ts = TRUE;
        }

        if(!specific_first_ts && (tsi_n >= 2 || tsr_n >= 2) )
        {
                return FALSE;
        }
#endif

        for (d = hp->connections; d != NULL; d = d->hp_next)
        {
                int wildcards, pathlen;  /* XXX */
                struct traffic_selector tmp,  tmp2;
                int curs=0;
                bool found_one_match_tsi = FALSE, found_one_match_tsr = FALSE;

                if (d->policy & POLICY_GROUP)
                        continue;

                if (!(same_id(&c->spd.this.id, &d->spd.this.id)
                      && match_id(&c->spd.that.id, &d->spd.that.id, &wildcards)
                      && trusted_ca(c->spd.that.ca, d->spd.that.ca, &pathlen)))
                    continue;


                if(ikev2_perfect_match_ts(tsi, tsr, tsi_n, tsr_n, d, role)) {
                        *result = d;
                        return TRUE;
                }

                if(role == INITIATOR) {
                        ei = &d->spd.this;
                        er = &d->spd.that;
                } else {
                        ei = &d->spd.that;
                        er = &d->spd.this;
                }

                tmp = ikev2_subnettots(ei);


                for(i=0; i<tsi_n; i++) {

                        /* ip address */
                        if(addrcmp(&tmp.low, &tsi[i].low) >= 0)
                        {
                                tmp2.low = tmp.low;
                        }
                        else
                        {
                                tmp2.low = tsi[i].low;
                        }

                        if(addrcmp(&tmp.high, &tsi[i].high) >= 0)
                        {
                                tmp2.high = tsi[i].high;
                        }
                        else
                        {
                                tmp2.high = tmp.high;
                        }

                        if(addrcmp(&tmp2.low, &tmp2.high) > 0) {
                                continue;
                        }

                        if(addrtypeof(&tmp2.low) != addrtypeof(&tmp2.high)) {
                                continue;
                        }

                        /* port */
                        if(tmp.startport >= tsi[i].startport )
                        {
                                tmp2.startport=tmp.startport;
                        }
                        else
                        {
                                tmp2.startport=tsi[i].startport;
                        }

                        if(tmp.endport >= tsi[i].endport )
                        {
                                tmp2.endport=tsi[i].endport;
                        }
                        else
                        {
                                tmp2.endport=tmp.endport;
                        }

                        if(tmp2.startport >  tmp2.endport)
                        {
                                continue;
                        }

                        /* protocol */
                        if( !tmp.ipprotoid && !tsi[i].ipprotoid && tmp.ipprotoid!=tsi[i].ipprotoid )
                        {
                                continue;
                        }

                        curs++;
                        found_one_match_tsi = TRUE;
                }

                tmp = ikev2_subnettots(er);
                for(i=0; i<tsr_n; i++) {

                        /* ip address */
                        if(addrcmp(&tmp.low, &tsr[i].low) >= 0)
                        {
                                tmp2.low = tmp.low;
                        }
                        else
                        {
                                tmp2.low = tsr[i].low;
                        }

                        if(addrcmp(&tmp.high, &tsr[i].high) >= 0)
                        {
                                tmp2.high = tsr[i].high;
                        }
                        else
                        {
                                tmp2.high = tmp.high;
                        }

                        if(addrcmp(&tmp2.low, &tmp2.high) > 0) {
                                continue;
                        }

                        if(addrtypeof(&tmp2.low) != addrtypeof(&tmp2.high)) {
                                continue;
                        }

                        /* port */
                        if(tmp.startport >= tsr[i].startport )
                        {
                                tmp2.startport=tmp.startport;
                        }
                        else
                        {
                                tmp2.startport=tsr[i].startport;
                        }

                        if(tmp.endport >= tsr[i].endport )
                        {
                                tmp2.endport=tsr[i].endport;
                        }
                        else
                        {
                                tmp2.endport=tmp.endport;
                        }

                        if(tmp2.startport >  tmp2.endport)
                        {
                                continue;
                        }

                        /* protocol */
                        if( !tmp.ipprotoid && !tsr[i].ipprotoid && tmp.ipprotoid!=tsr[i].ipprotoid )
                        {
                                continue;
                        }

                        curs++;
                        found_one_match_tsr = TRUE;

                }

                if(curs > bests && found_one_match_tsi && found_one_match_tsr)
                {
                bests = curs;
                bestc = d;

                }
        }

        if(bestc == NULL) {
                return FALSE;
        }

        /* creating narrowed traffic selector */
        {
                struct traffic_selector tmp,  tmp2, *tmp3;

                *result = bestc;

                if(role == INITIATOR) {
                        ei = &bestc->spd.this;
                        er = &bestc->spd.that;
                } else {
                        ei = &bestc->spd.that;
                        er = &bestc->spd.this;
                }


                tmp = ikev2_subnettots(ei);
                for(i=0; i<tsi_n; i++) {

                        /* ip address */
                        if(addrcmp(&tmp.low, &tsi[i].low) >= 0)
                        {
                                tmp2.low = tmp.low;
                        }
                        else
                        {
                                tmp2.low = tsi[i].low;
                        }

                        if(addrcmp(&tmp.high, &tsi[i].high) >= 0)
                        {
                                tmp2.high = tsi[i].high;
                        }
                        else
                        {
                                tmp2.high = tmp.high;
                        }

                        if(addrcmp(&tmp2.low, &tmp2.high) > 0) {
                                continue;
                        }

                        /* port */
                        if(tmp.startport >= tsi[i].startport )
                        {
                                tmp2.startport=tmp.startport;
                        }
                        else
                        {
                                tmp2.startport=tsi[i].startport;
                        }

                        if(tmp.endport >= tsi[i].endport )
                        {
                                tmp2.endport=tsi[i].endport;
                        }
                        else
                        {
                                tmp2.endport=tmp.endport;
                        }

                        if(tmp2.startport >  tmp2.endport)
                        {
                                continue;
                        }

                        /* as openswan supports only single port, so picking one port*/
                        if( tmp2.startport > 0){
                                tmp2.endport = tmp2.startport;
                        }
                        else if (tmp2.endport < 65535 ){
                                tmp2.startport = tmp2.endport;
                        }

                        /* protocol */
                        if( tmp.ipprotoid > 0 && tsi[i].ipprotoid > 0 && tmp.ipprotoid!=tsi[i].ipprotoid)
                        {
                                continue;
                        }
                        else if(tmp.ipprotoid == 0)
                        {
                                tmp2.ipprotoid = tsi[i].ipprotoid;
                        }
                        else
                        {
                                tmp2.ipprotoid = tmp.ipprotoid;
                        }

                        /*setting type */
                        switch(tmp2.low.u.v4.sin_family) {
                        case AF_INET:
                                tmp2.ts_type = IKEv2_TS_IPV4_ADDR_RANGE;
                                break;
                        case AF_INET6:
                                tmp2.ts_type = IKEv2_TS_IPV6_ADDR_RANGE;
                                break;
                        }

                        tmp3 = alloc_thing(struct traffic_selector, "struct traffic_selector");
                        *tmp3 = tmp2;
                        tmp3->next = NULL;

                        if(*narrowed_tsi == NULL)
                        {
                                *narrowed_tsi = tmp3;
                        }
                        else
                        {
                                struct traffic_selector *tmp4 = *narrowed_tsi;
                                while(tmp4->next!=NULL){
                                tmp4 = tmp4->next;
                                }
                                tmp4->next = tmp3;

                        }
                }

                tmp = ikev2_subnettots(er);
                for(i=0; i<tsr_n; i++) {

                        /* ip address */
                        if(addrcmp(&tmp.low, &tsr[i].low) >= 0)
                        {
                                tmp2.low = tmp.low;
                        }
                        else
                        {
                                tmp2.low = tsr[i].low;
                        }

                        if(addrcmp(&tmp.high, &tsr[i].high) >= 0)
                        {
                                tmp2.high = tsr[i].high;
                        }
                        else
                        {
                                tmp2.high = tmp.high;
                        }

                        if(addrcmp(&tmp2.low, &tmp2.high) > 0) {
                                continue;
                        }

                        /* port */
                        if(tmp.startport >= tsr[i].startport )
                        {
                                tmp2.startport=tmp.startport;
                        }
                        else
                        {
                                tmp2.startport=tsr[i].startport;
                        }

                        if(tmp.endport >= tsr[i].endport )
                        {
                                tmp2.endport=tsr[i].endport;
                        }
                        else
                        {
                                tmp2.endport=tmp.endport;
                        }

                        if(tmp2.startport >  tmp2.endport)
                        {
                                continue;
                        }

                        /* as openswan supports only single port, so picking one port*/
                        if( tmp2.startport > 0){
                                tmp2.endport = tmp2.startport;
                        }
                        else if (tmp2.endport < 65535 ){
                                tmp2.startport = tmp2.endport;
                        }

                        /* protocol */
                        if( !tmp.ipprotoid && !tsr[i].ipprotoid && tmp.ipprotoid!=tsr[i].ipprotoid )
                        {
                                continue;
                        }
                        else if(tmp.ipprotoid == 0)
                        {
                                tmp2.ipprotoid = tsr[i].ipprotoid;
                        }
                        else
                        {
                                tmp2.ipprotoid = tmp.ipprotoid;
                        }

                        /*setting type */
                        switch(tmp2.low.u.v4.sin_family) {
                        case AF_INET:
                                tmp2.ts_type = IKEv2_TS_IPV4_ADDR_RANGE;
                                break;
                        case AF_INET6:
                                tmp2.ts_type = IKEv2_TS_IPV6_ADDR_RANGE;
                                break;
                        }

                        tmp3 = alloc_thing(struct traffic_selector, "struct traffic_selector");
                        *tmp3 = tmp2;
                        tmp3->next = NULL;

                        if(*narrowed_tsr == NULL)
                        {
                                *narrowed_tsr = tmp3;
                        }
                        else
                        {
                                struct traffic_selector *tmp4 = *narrowed_tsr;
                                while(tmp4->next!=NULL){
                                tmp4 = tmp4->next;
                                }

                                tmp4->next = tmp3;
                        }

                }
        }

        struct traffic_selector *tmp;
        tmp = *narrowed_tsi;
        while(tmp!= NULL) {

            DBG(DBG_CONTROLMORE,
            {
                char lbi[ADDRTOT_BUF];
                char hbi[ADDRTOT_BUF];
                addrtot(&tmp->low,  0, lbi, sizeof(lbi));
                addrtot(&tmp->high, 0, hbi, sizeof(hbi));

                DBG_log("    tsi=%s/%s, port=%d/%d, protocol=%d"
                        ,  lbi, hbi, tmp->startport, tmp->endport, tmp->ipprotoid);
            }
            );

        tmp=tmp->next;
        }

        tmp = *narrowed_tsr;
        while(tmp!= NULL) {

            DBG(DBG_CONTROLMORE,
            {
                char lbi[ADDRTOT_BUF];
                char hbi[ADDRTOT_BUF];
                addrtot(&tmp->low,  0, lbi, sizeof(lbi));
                addrtot(&tmp->high, 0, hbi, sizeof(hbi));

                DBG_log("    tsr=%s/%s, port=%d/%d, protocol=%d"
                        ,  lbi, hbi, tmp->startport, tmp->endport, tmp->ipprotoid);
            }
            );

        tmp=tmp->next;
        }
        return TRUE;
}

struct connection *
ikev2_create_narrowed_con(struct connection *c
                        , struct traffic_selector *narrowed_tsi
                        , struct traffic_selector *narrowed_tsr
                        , enum phase1_role role)
{
        struct connection *narrowed_con=NULL;
        struct spd_route *tmp_spd=NULL, *tmp_spd1=NULL;
        struct traffic_selector *tmptsi=NULL, *tmptsr=NULL;

        narrowed_con = ikev2_narrow_instantiate(c);

        /* setup spds for narrowed connection*/
        tmp_spd1 = NULL;
        tmp_spd = &narrowed_con->spd;
        tmptsi = narrowed_tsi;

        while(tmptsi != NULL) {
                ip_subnet tmpsubneti;
                rangetosubnet(&tmptsi->low, &tmptsi->high, &tmpsubneti);
                tmptsr = narrowed_tsr;

                while(tmptsr != NULL ) {
                        ip_subnet tmpsubnetr;
                        rangetosubnet(&tmptsr->low, &tmptsr->high, &tmpsubnetr);

                        if(tmp_spd == NULL) {
                                struct spd_route *tmp_spd2 = clone_thing(narrowed_con->spd, "spds from narrowed ts");
                                tmp_spd = tmp_spd2;
                                tmp_spd->next = NULL;

                                if(tmp_spd1!= NULL){
                                        tmp_spd1->next = tmp_spd;
                                }

                                if(tmp_spd != &narrowed_con->spd) {
                                tmp_spd->this.id.name.ptr = NULL;
                                tmp_spd->this.id.name.len = 0;
                                    tmp_spd->that.id.name.ptr = NULL;
                                    tmp_spd->that.id.name.len = 0;

                                tmp_spd->this.host_addr_name = NULL;
                                tmp_spd->that.host_addr_name = NULL;

                                tmp_spd->this.updown = clone_str(tmp_spd->this.updown, "updown");
                                tmp_spd->that.updown = clone_str(tmp_spd->that.updown, "updown");

                                tmp_spd->this.cert_filename = NULL;
                                tmp_spd->that.cert_filename = NULL;

                                tmp_spd->this.cert.type = 0;
                                tmp_spd->that.cert.type = 0;

                                tmp_spd->this.ca.ptr = NULL;
                                tmp_spd->that.ca.ptr = NULL;

                                tmp_spd->this.groups = NULL;
                                tmp_spd->that.groups = NULL;

                                tmp_spd->this.virt = NULL;
                                tmp_spd->that.virt = NULL;
                                }
                        }

                        if(role == INITIATOR) {
                                tmp_spd->this.client = tmpsubneti;
                                tmp_spd->this.port = tmptsi->startport;
                                tmp_spd->this.protocol = tmptsi->ipprotoid;
                                if( subnetishost(&tmp_spd->this.client) && addrinsubnet(&tmp_spd->this.host_addr, &tmp_spd->this.client)) {
                                tmp_spd->this.has_client = FALSE;
                                }
                                else {
                                tmp_spd->this.has_client = TRUE;
                                }
                                tmp_spd->this.has_client_wildcard =  FALSE;
                                tmp_spd->this.has_port_wildcard = FALSE;
                                setportof(htons(tmp_spd->this.port), &tmp_spd->this.host_addr);
                                setportof(htons(tmp_spd->this.port), &tmp_spd->this.client.addr);

                                tmp_spd->that.client = tmpsubnetr;
                                tmp_spd->that.port = tmptsr->startport;
                                tmp_spd->that.protocol = tmptsr->ipprotoid;
                                if( subnetishost(&tmp_spd->that.client) && addrinsubnet(&tmp_spd->that.host_addr, &tmp_spd->that.client)) {
                                tmp_spd->that.has_client = FALSE;
                                }
                                else {
                                tmp_spd->that.has_client = TRUE;
                                }
                                tmp_spd->that.has_client_wildcard =  FALSE;
                                tmp_spd->that.has_port_wildcard = FALSE;
                                setportof(htons(tmp_spd->that.port), &tmp_spd->that.host_addr);
                                setportof(htons(tmp_spd->that.port), &tmp_spd->that.client.addr);
                        }
                        else {
                                tmp_spd->this.client = tmpsubnetr;
                                tmp_spd->this.port = tmptsr->startport;
                                tmp_spd->this.protocol = tmptsr->ipprotoid;
                                if( subnetishost(&tmp_spd->this.client) && addrinsubnet(&tmp_spd->this.host_addr, &tmp_spd->this.client)) {
                                tmp_spd->this.has_client = FALSE;
                                }
                                else {
                                tmp_spd->this.has_client = TRUE;
                                }
                                tmp_spd->this.has_client_wildcard =  FALSE;
                                tmp_spd->this.has_port_wildcard = FALSE;
                                setportof(htons(tmp_spd->this.port), &tmp_spd->this.host_addr);
                                setportof(htons(tmp_spd->this.port), &tmp_spd->this.client.addr);

                                tmp_spd->that.client = tmpsubneti;
                                tmp_spd->that.port = tmptsi->startport;
                                tmp_spd->that.protocol = tmptsi->ipprotoid;
                                if( subnetishost(&tmp_spd->that.client) && addrinsubnet(&tmp_spd->that.host_addr, &tmp_spd->that.client)) {
                                tmp_spd->that.has_client = FALSE;
                                }
                                else {
                                tmp_spd->that.has_client = TRUE;
                                }
                                tmp_spd->that.has_client_wildcard =  FALSE;
                                tmp_spd->that.has_port_wildcard = FALSE;
                                setportof(htons(tmp_spd->that.port), &tmp_spd->that.host_addr);
                                setportof(htons(tmp_spd->that.port), &tmp_spd->that.client.addr);
                        }

                tmp_spd1 = tmp_spd;
                tmp_spd = tmp_spd1->next;
                tmptsr = tmptsr->next;
                }
        tmptsi = tmptsi->next;
        }

                    char buftest[ADDRTOT_BUF];
                    tmp_spd = &narrowed_con->spd;
                    int count_spd=0;
                    do {
                        DBG(DBG_CONTROLMORE, DBG_log("spd route number: %d", ++count_spd));

                        /**that info**/
                        DBG(DBG_CONTROLMORE, DBG_log("that id kind: %d",tmp_spd->that.id.kind));
                        DBG(DBG_CONTROLMORE,
                                DBG_log("that id ipaddr: %s", (addrtot(&tmp_spd->that.id.ip_addr, 0, buftest, sizeof(buftest)), buftest)));

                        if (tmp_spd->that.id.name.ptr != NULL) {
                        DBG(DBG_CONTROLMORE, DBG_dump_chunk("that id name",tmp_spd->that.id.name));
                        }

                        DBG(DBG_CONTROLMORE,
                            DBG_log("that host_addr: %s", (addrtot(&tmp_spd->that.host_addr, 0, buftest, sizeof(buftest)), buftest)));
                        DBG(DBG_CONTROLMORE,
                            DBG_log("that nexthop: %s", (addrtot(&tmp_spd->that.host_nexthop, 0, buftest, sizeof(buftest)), buftest)));
                        DBG(DBG_CONTROLMORE,
                            DBG_log("that srcip: %s", (addrtot(&tmp_spd->that.host_srcip, 0, buftest, sizeof(buftest)), buftest)));
                        DBG(DBG_CONTROLMORE,
                            DBG_log("that client_addr: %s, maskbits:%d", (addrtot(&tmp_spd->that.client.addr, 0,
                                                        buftest, sizeof(buftest)), buftest),tmp_spd->that.client.maskbits));
                        DBG(DBG_CONTROLMORE, DBG_log("that has_client: %d", tmp_spd->that.has_client));
                        DBG(DBG_CONTROLMORE, DBG_log("that has_client_wildcard: %d", tmp_spd->that.has_client_wildcard));
                        DBG(DBG_CONTROLMORE, DBG_log("that has_port_wildcard: %d", tmp_spd->that.has_port_wildcard));
                        DBG(DBG_CONTROLMORE, DBG_log("that has_id_wildcards: %d", tmp_spd->that.has_id_wildcards));

                        /**this info**/
                        DBG(DBG_CONTROLMORE, DBG_log("this id kind: %d",tmp_spd->this.id.kind));
                        DBG(DBG_CONTROLMORE,
                            DBG_log("this id ipaddr: %s", (addrtot(&tmp_spd->this.id.ip_addr, 0, buftest, sizeof(buftest)), buftest)));

                        if (tmp_spd->this.id.name.ptr != NULL) {
                        DBG_dump_chunk("this id name",tmp_spd->this.id.name);
                        }

                        DBG(DBG_CONTROLMORE,
                            DBG_log("this host_addr: %s", (addrtot(&tmp_spd->this.host_addr, 0, buftest, sizeof(buftest)), buftest)));
                        DBG(DBG_CONTROLMORE,
                            DBG_log("this nexthop: %s", (addrtot(&tmp_spd->this.host_nexthop, 0, buftest, sizeof(buftest)), buftest)));
                        DBG(DBG_CONTROLMORE,
                            DBG_log("this srcip: %s", (addrtot(&tmp_spd->this.host_srcip, 0, buftest, sizeof(buftest)), buftest)));
                        DBG(DBG_CONTROLMORE, DBG_log("this client_addr: %s, maskbits:%d", (addrtot(&tmp_spd->this.client.addr,
                                                                0, buftest, sizeof(buftest)), buftest),tmp_spd->this.client.maskbits));
                        DBG(DBG_CONTROLMORE, DBG_log("this has_client: %d", tmp_spd->this.has_client));
                        DBG(DBG_CONTROLMORE, DBG_log("this has_client_wildcard: %d", tmp_spd->this.has_client_wildcard));
                        DBG(DBG_CONTROLMORE, DBG_log("this has_port_wildcard: %d", tmp_spd->this.has_port_wildcard));
                        DBG(DBG_CONTROLMORE, DBG_log("this has_id_wildcards: %d", tmp_spd->this.has_id_wildcards));

                        tmp_spd = tmp_spd->next;
                    } while(tmp_spd!=NULL);

        return narrowed_con;
}

stf_status ikev2_child_sa_respond(struct msg_digest *md
                                  , enum phase1_role role
                                  , pb_stream *outpbs)
{
    struct state      *st = md->st;
    struct state      *st1;
    struct connection *c  = st->st_connection;
    /* struct connection *cb; */
    struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
    stf_status ret;
    struct payload_digest *const tsi_pd = md->chain[ISAKMP_NEXT_v2TSi];
    struct payload_digest *const tsr_pd = md->chain[ISAKMP_NEXT_v2TSr];
    struct traffic_selector tsi[16], tsr[16], *narrowed_tsi=NULL, *narrowed_tsr=NULL;
    struct connection *narrowed_con=NULL, *result=NULL;
    unsigned int tsi_n, tsr_n;
    bool ts_negotiation_failed = FALSE;


    st1 = duplicate_state(st);

    /*
     * now look at provided TSx, and see if these fit the connection
     * that we have, and narrow them if necessary.
     */
    tsi_n = ikev2_parse_ts(tsi_pd, tsi, 16);
    tsr_n = ikev2_parse_ts(tsr_pd, tsr, 16);

    if(ikev2_narrowing(c, role, tsi, tsr, tsi_n, tsr_n, &narrowed_tsi , &narrowed_tsr, &result)){

        if(narrowed_tsi == NULL && narrowed_tsr == NULL && result!= NULL) {
        /*found exact match */
                narrowed_con = result;

                /*preparing traffic selectors (need to do: free first narrowed_ts here) */
                st1->st_ts_this= ikev2_subnettots(&result->spd.this);
                st1->st_ts_that= ikev2_subnettots(&result->spd.that);
        }
        else {
                narrowed_con = ikev2_create_narrowed_con(result, narrowed_tsi, narrowed_tsr, role);

                /*preparing traffic selectors (need to do: free first narrowed_ts here) */
                if(role == INITIATOR) {
                st1->st_ts_this= *narrowed_tsi;
                st1->st_ts_that= *narrowed_tsr;
                }
                else {
                st1->st_ts_this= *narrowed_tsr;
                st1->st_ts_that= *narrowed_tsi;
                }

                pfreeany(narrowed_tsi);
                pfreeany(narrowed_tsr);
        }
    }
    else {
        ts_negotiation_failed = TRUE;
    }

    if(narrowed_con!= NULL && !ts_negotiation_failed) {
    c = narrowed_con;
    }

    st1->st_connection = c;
    st1->st_childsa = NULL;
    insert_state(st1);

    /* start of SA out */
    {
        struct isakmp_sa r_sa = sa_pd->payload.sa;
        notification_t rn;
        pb_stream r_sa_pbs;

        if(ts_negotiation_failed) {
        r_sa.isasa_np = ISAKMP_NEXT_v2N;
        }
        else {
        r_sa.isasa_np = ISAKMP_NEXT_v2TSi;
        }

        if (!out_struct(&r_sa, &ikev2_sa_desc, outpbs, &r_sa_pbs))
            return STF_INTERNAL_ERROR;

        /* SA body in and out */
        rn = ikev2_parse_child_sa_body(&sa_pd->pbs, &sa_pd->payload.v2sa,
                                       &r_sa_pbs, st1, FALSE);

        if (rn != NOTHING_WRONG)
            return STF_FAIL + rn;
    }

    if(ts_negotiation_failed) {
        chunk_t child_spi, notifiy_data;
        memset(&child_spi, 0, sizeof(child_spi));
        memset(&notifiy_data, 0, sizeof(notifiy_data));
        ship_v2N (ISAKMP_NEXT_NONE, ISAKMP_PAYLOAD_NONCRITICAL, /*PROTO_ISAKMP*/ 0,
                        &child_spi,
                        v2N_TS_UNACCEPTABLE, &notifiy_data, outpbs);
        change_state(st1, STATE_CHILDSA_DEL);
        delete_state(st1);
        return STF_OK;
    }

    md->st = st1;
    md->pst= st;

        ret = ikev2_calc_emit_ts(md, outpbs, role
                        , c, c->policy);
        if(ret != STF_OK) return ret; // should we delete_state st1?

    if( role == RESPONDER ) {
        chunk_t child_spi, notifiy_data;
        struct payload_digest *p;
        for(p = md->chain[ISAKMP_NEXT_v2N]; p != NULL; p = p->next)
        {
           if ( p->payload.v2n.isan_type == v2N_USE_TRANSPORT_MODE ) {

           if(st1->st_connection->policy & POLICY_TUNNEL) {
                DBG_log("Although local policy is tunnel, received v2N_USE_TRANSPORT_MODE");
                DBG_log("So switching to transport mode, and responding with v2N_USE_TRANSPORT_MODE notify");
           }
           else {
                DBG_log("Local policy is transport, received v2N_USE_TRANSPORT_MODE");
                DBG_log("Now responding with v2N_USE_TRANSPORT_MODE notify");
           }

           memset(&child_spi, 0, sizeof(child_spi));
           memset(&notifiy_data, 0, sizeof(notifiy_data));
           ship_v2N (ISAKMP_NEXT_NONE, ISAKMP_PAYLOAD_NONCRITICAL, /*PROTO_ISAKMP*/ 0,
                        &child_spi,
                        v2N_USE_TRANSPORT_MODE, &notifiy_data, outpbs);

           if (st1->st_esp.present == TRUE) {
                /*openswan supports only "esp" with ikev2 it seems, look at ikev2_parse_child_sa_body handling*/
                st1->st_esp.attrs.encapsulation = ENCAPSULATION_MODE_TRANSPORT;
           }
           break;
           }
        }
    }

    ikev2_derive_child_keys(st1, role);
    /* install inbound and outbound SPI info */
    if(!install_ipsec_sa(st1, TRUE))
        return STF_FATAL;

    st1->st_childsa = c;

    /* mark the connection as now having an IPsec SA associated with it. */
    st1->st_connection->newest_ipsec_sa = st1->st_serialno;

    return STF_OK;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */

