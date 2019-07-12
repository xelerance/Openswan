/*
 * IKEv2 parent SA creation routines
 * Copyright (C) 2007-2017 Michael Richardson <mcr@xelerance.com>
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
#include "pluto/state.h"
#include "id.h"
#include "pluto/connections.h"
#include "hostpair.h"

#include "crypto.h" /* requires sha1.h and md5.h */
#include "sha1.h"   /* for NAT DETECTION processing */
#include "x509.h"
#include "x509more.h"
#include "ike_alg.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "pluto_crypt.h"
#include "packet.h"
#include "demux.h"
#include "ikev2.h"
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
#include "pluto/nat_traversal.h"

#include "tpm/tpm.h"

void calculate_nat_hash(const unsigned char cookie_i[COOKIE_SIZE]
                        , const unsigned char cookie_r[COOKIE_SIZE]
                        , const ip_address     addr
                        , const unsigned short port
                        , unsigned char digest[SHA1_DIGEST_SIZE])
{
    SHA1_CTX srchash;
    unsigned char thingstohash[COOKIE_SIZE/*spiI*/+COOKIE_SIZE/*spiR*/+16/*IPaddr*/+2/*port*/];
    unsigned char *next = thingstohash;
    unsigned char *addrptr;
    unsigned int addrlen;

    memcpy(next, cookie_i, COOKIE_SIZE);   next += COOKIE_SIZE;
    memcpy(next, cookie_r, COOKIE_SIZE);   next += COOKIE_SIZE;

    addrlen = addrbytesptr(&addr, &addrptr);
    memcpy(next, addrptr, addrlen);  next += addrlen;
    passert(addrlen == 4 || addrlen == 16);

    next[0] = port >> 8;
    next[1] = port & 0xff;
    next += 2;

    DBG(DBG_EMITTING|DBG_PARSING|DBG_CONTROLMORE, DBG_dump("nat chunk", thingstohash, (next - thingstohash)));

    SHA1Init(&srchash);
    SHA1Update(&srchash, thingstohash, (next - thingstohash));
    SHA1Final(digest, &srchash);
}

stf_status process_nat_payload(struct state *st
                               , struct msg_digest *md
                               , struct payload_digest *p UNUSED
                               , const char *payload_name
                               , v2_notification_t notify_type UNUSED
                               , chunk_t *data)
{
    unsigned char digest[SHA1_DIGEST_SIZE];
    char addrbuf[ADDRTOT_BUF];
    chunk_t calculated_hash;
    ip_address *addr;
    unsigned short port;

    switch(notify_type) {
    case v2N_NAT_DETECTION_DESTINATION_IP:
        addr = &st->st_localaddr;
        port =  st->st_localport;
        break;
    case v2N_NAT_DETECTION_SOURCE_IP:
        addr = &st->st_remoteaddr;
        port =  st->st_remoteport;
        break;
    default:
        return STF_FAIL;
    }

    calculate_nat_hash(md->hdr.isa_icookie, md->hdr.isa_rcookie, *addr, port, digest);
    setchunk(calculated_hash, digest, SHA1_DIGEST_SIZE);

    DBG(DBG_PARSING, DBG_log("processing %s", payload_name));
    DBG(DBG_PARSING, DBG_dump_chunk("received nat-t hash", *data));
    DBG(DBG_PARSING, DBG_dump_chunk("calculated nat-t  h", calculated_hash));

    if(same_chunk(*data, calculated_hash)) {
        DBG(DBG_PARSING|DBG_CONTROLMORE, DBG_log("nat-t payloads for %s match: no NAT", payload_name));
    } else {
	st->hidden_variables.st_nat_traversal = NAT_T_WITH_RFC_VALUES;

        switch(notify_type) {
        case v2N_NAT_DETECTION_DESTINATION_IP:
            loglog(RC_COMMENT, "detected that I am NATed");
	    st->hidden_variables.st_nat_traversal |= LELEM(NAT_TRAVERSAL_NAT_BHND_ME);
            break;
        case v2N_NAT_DETECTION_SOURCE_IP:
            addrtot(addr, 0, addrbuf, ADDRTOT_BUF);
            loglog(RC_COMMENT, "detected that they are NATed at: %s:%u"
                         , addrbuf, port);
	    st->hidden_variables.st_nat_traversal |= LELEM(NAT_TRAVERSAL_NAT_BHND_PEER);
            break;
        default:
            break;
        }
    }

    return STF_OK;
}

stf_status ikev2_process_notifies(struct state *st, struct msg_digest *md)
{
    struct payload_digest *p;
    chunk_t spi;
    chunk_t data;
    pb_stream *data_pbs;
    const char *payload_name = NULL;
    char payload_name_buf[20];

    for(p = md->chain[ISAKMP_NEXT_v2N]; p != NULL; p = p->next) {
      payload_name = enum_name(&ikev2_notify_names, p->payload.v2n.isan_type);
      if(payload_name == NULL) {
        if(p->payload.v2n.isan_type < v2N_INITIAL_CONTACT) {
          return STF_FAIL + p->payload.v2n.isan_type;
        } else {
          payload_name = enum_show(&ikev2_notify_names, p->payload.v2n.isan_type);
          payload_name_buf[0]='\0';
          strncat(payload_name_buf, payload_name, sizeof(payload_name_buf)-1);
          payload_name = payload_name_buf;
        }
      }

      data_pbs = &p->pbs;
      data = empty_chunk;
      spi  = empty_chunk;

      /* pull the SPI and notify body out, verify sizes */
      switch(p->payload.v2n.isan_protoid) {
      case v2N_noSA:
        break;
      case v2N_IKE_SA:
      case v2N_AH:
      case v2N_ESP:

        /* process the SPISIZE */
        if(pbs_left(data_pbs) < p->payload.v2n.isan_spisize) {
          loglog(RC_LOG_SERIOUS, "notify payload %s received with too small spisize: %lu < %u (dropped)"
                 , payload_name, (long unsigned)pbs_left(data_pbs),  p->payload.v2n.isan_spisize);
        }
        setchunk(spi, data_pbs->cur, p->payload.v2n.isan_spisize);
        data_pbs->cur += p->payload.v2n.isan_spisize;
      }

      if(pbs_left(data_pbs)) {
        setchunk(data, data_pbs->cur, pbs_left(data_pbs));
      }

      switch(p->payload.v2n.isan_type) {
      case v2N_NAT_DETECTION_DESTINATION_IP:
      case v2N_NAT_DETECTION_SOURCE_IP:
        process_nat_payload(st, md, p, payload_name, p->payload.v2n.isan_type, &data);
        break;

      default:
        loglog(RC_LOG, "received (ignored) notify: %s (spisize=%u, data=%u)", payload_name, (unsigned int)spi.len, (unsigned int)data.len);
        break;
      }
    }

    return STF_OK;
}

void ikev2_enable_nat_keepalives(struct state *st)
{
    if (st->hidden_variables.st_nat_traversal & NAT_T_WITH_KA)
	nat_traversal_new_ka_event();
}

/* add notify payload to the rbody */
bool ship_v2N(unsigned int np, u_int8_t  critical,
              u_int8_t protoid, chunk_t *spi,
              u_int16_t type, chunk_t *n_data, pb_stream *rbody)
{
    struct ikev2_notify n;
    pb_stream n_pbs;
    DBG(DBG_CONTROLMORE
        ,DBG_log("Adding a v2N Payload"));

    pbs_set_np(rbody, ISAKMP_NEXT_v2N);

    n.isan_np =  np;
    n.isan_critical = critical;
    if(DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
        openswan_log(" setting bogus ISAKMP_PAYLOAD_OPENSWAN_BOGUS flag in ISAKMP payload");
        n.isan_critical |= ISAKMP_PAYLOAD_OPENSWAN_BOGUS;
    }

    n.isan_protoid =  protoid;
    n.isan_spisize = 0;
    if(spi) {
        n.isan_spisize = spi->len;
    }
    n.isan_type = type;

    if (!out_struct(&n, &ikev2_notify_desc, rbody, &n_pbs)) {
        openswan_log("error initializing notify payload for notify message");
        return FALSE;
    }

    if(spi && spi->len > 0) {
        if (!out_raw(spi->ptr, spi->len, &n_pbs, "SPI ")) {
            openswan_log("error writing SPI to notify payload");
            return FALSE;
        }
    }
    if(n_data && n_data->len) {
        if (!out_raw(n_data->ptr, n_data->len, &n_pbs, "Notify data")) {
            openswan_log("error writing notify payload for notify message");
            return FALSE;
        }
    }

    close_output_pbs(&n_pbs);
    return TRUE;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
