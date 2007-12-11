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

void ikev2_derive_child_keys(struct state *st UNUSED)
{
}
 

stf_status ikev2_emit_ts(struct msg_digest *md   UNUSED
			 , pb_stream *outpbs   
			 , unsigned int np
			 , struct end *end       UNUSED
			 , enum phase1_role role UNUSED)
{
    struct ikev2_ts its;
    struct ikev2_ts1 its1;
    ip_address low, high;
    struct in6_addr v6mask;
    pb_stream ts_pbs;
    pb_stream ts_pbs2;

    its.isat_np = np;
    its.isat_critical = ISAKMP_PAYLOAD_CRITICAL;
    its.isat_num = 1;

    if(!out_struct(&its, &ikev2_ts_desc, outpbs, &ts_pbs))
	return STF_INTERNAL_ERROR;

    switch(end->client.addr.u.v4.sin_family) {
    case AF_INET:
	its1.isat1_type = ID_IPV4_ADDR_RANGE;
	low   = end->client.addr;
	low.u.v4.sin_addr.s_addr  &= bitstomask(end->client.maskbits).s_addr;
	high  = end->client.addr;
	high.u.v4.sin_addr.s_addr |= ~bitstomask(end->client.maskbits).s_addr;
	break;
    case AF_INET6:
	its1.isat1_type = ID_IPV6_ADDR_RANGE;
	v6mask = bitstomask6(end->client.maskbits);

	low   = end->client.addr;
	low.u.v6.sin6_addr.s6_addr32[0] &= v6mask.s6_addr32[0];
	low.u.v6.sin6_addr.s6_addr32[1] &= v6mask.s6_addr32[1];
	low.u.v6.sin6_addr.s6_addr32[2] &= v6mask.s6_addr32[2];
	low.u.v6.sin6_addr.s6_addr32[3] &= v6mask.s6_addr32[3];
	high  = end->client.addr;
	high.u.v6.sin6_addr.s6_addr32[0]|= ~v6mask.s6_addr32[0];
	high.u.v6.sin6_addr.s6_addr32[1]|= ~v6mask.s6_addr32[1];
	high.u.v6.sin6_addr.s6_addr32[2]|= ~v6mask.s6_addr32[2];
	high.u.v6.sin6_addr.s6_addr32[3]|= ~v6mask.s6_addr32[3];
	break;
    }
    its1.isat1_ipprotoid = 0;      /* all protocols */
    its1.isat1_sellen = 16;        /* for IPv4 */
    its1.isat1_startport = 0;      /* all ports */
    its1.isat1_endport = 65535;  
    if(!out_struct(&its1, &ikev2_ts1_desc, &ts_pbs, &ts_pbs2))
	return STF_INTERNAL_ERROR;
    
    /* now do IP addresses */
    switch(end->client.addr.u.v4.sin_family) {
    case AF_INET:
	if(!out_raw(&low.u.v4.sin_addr.s_addr, 4, &ts_pbs2, "ipv4 low")
	   ||!out_raw(&high.u.v4.sin_addr.s_addr, 4,&ts_pbs2,"ipv4 high"))
	    return STF_INTERNAL_ERROR;
	break;
    case AF_INET6:
	if(!out_raw(&low.u.v6.sin6_addr.s6_addr, 16, &ts_pbs2, "ipv6 low")
	   ||!out_raw(&high.u.v6.sin6_addr.s6_addr,16,&ts_pbs2,"ipv6 high"))
	    return STF_INTERNAL_ERROR;
	break;
    }

    close_output_pbs(&ts_pbs2);
    close_output_pbs(&ts_pbs);
    
    return STF_OK;
}


stf_status ikev2_calc_emit_ts(struct msg_digest *md
			      , pb_stream *outpbs
			      , enum phase1_role role UNUSED
			      , struct connection *c0
			      , lset_t policy UNUSED)
{
    struct state *st = md->st;
    struct spd_route *sr;
    stf_status ret;
    
    ikev2_derive_child_keys(st);
    install_inbound_ipsec_sa(st);
    st->st_childsa = c0;

    for(sr=&c0->spd; sr != NULL; sr = sr->next) {
	ret = ikev2_emit_ts(md, outpbs, ISAKMP_NEXT_v2TSr
			    , &sr->this, INITIATOR);
	if(ret!=STF_OK) return ret;
	ret = ikev2_emit_ts(md, outpbs, ISAKMP_NEXT_NONE
			    , &sr->that, RESPONDER);
	if(ret!=STF_OK) return ret;
    }

    return STF_OK;
}

stf_status ikev2_child_sa_respond(struct msg_digest *md
				  , enum phase1_role role
				  , pb_stream *outpbs)
{
    struct state      *st = md->st;
    struct connection *c  = st->st_connection;
    struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
    stf_status ret;
    //struct payload_digest *const tsi_pd = md->chain[ISAKMP_NEXT_v2TSi];
    //struct payload_digest *const tsr_pd = md->chain[ISAKMP_NEXT_v2TSr];
    
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
				       &r_sa_pbs, st, FALSE);
	
	if (rn != NOTHING_WRONG)
	    return STF_FAIL + rn;
    }

    /*
     * now look at provided TSx, and see if these fit the connection
     * that we have, and narrow them if necessary.
     */

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
 
