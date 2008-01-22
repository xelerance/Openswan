  /* do RSA operations for IKEv2
 *
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
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
#include "server.h"
#include "vendor.h"
#include "dpd.h"
#include "keys.h"

#ifdef HAVE_OCF
#include "ocf_pk.h"
#endif

static u_char psk_key_pad_str[] = "Key Pad for IKEv2"; 
static int psk_key_pad_str_len = sizeof( psk_key_pad_str);

static void ikev2_calculate_psk_sighash(struct state *st
				    , enum phase1_role role
				    , unsigned char *idhash
				    , chunk_t firstpacket
				    , unsigned char *signed_octets)
{
    const chunk_t *nonce;
    const char    *nonce_name;
    const struct connection *c = st->st_connection;
    const chunk_t *pss = get_preshared_secret(c);
    unsigned char *prf_psk;
	

    /*	RFC 4306  2:15
	AUTH = prf(prf(Shared Secret,"Key Pad for IKEv2"), <msg octets>)
    */

    /* calculate inner prf */
    {
	struct hmac_ctx id_ctx;
	hmac_init_chunk(&id_ctx, st->st_oakley.prf_hasher, *pss);	
	hmac_update(&id_ctx, psk_key_pad_str, psk_key_pad_str_len);
	prf_psk = alloca(st->st_oakley.prf_hasher->hash_digest_len);
	hmac_final(prf_psk, &id_ctx);
    }

    DBG(DBG_CRYPT
	,DBG_log("negotiated prf: %s ", st->st_oakley.prf_hasher->common.name);
	 DBG_dump("inner prf ouput", prf_psk, 
		   st->st_oakley.prf_hasher->hash_digest_len););
    
    
    /* calculate outer prf */
    if(role == INITIATOR) {
	/* on initiator, we need to hash responders nonce */
	nonce = &st->st_nr;
	nonce_name = "inputs to hash2 (responder nonce)";
    } else {
	nonce = &st->st_ni;
	nonce_name = "inputs to hash2 (initiator nonce)";
    }
	

    {
	struct hmac_ctx id_ctx;
		
	hmac_init(&id_ctx, st->st_oakley.prf_hasher, prf_psk, 
		  st->st_oakley.prf_hasher->hash_digest_len);	
/*
 *  For the responder, the octets to
 *  be signed start with the first octet of the first SPI in the header
 *  of the second message and end with the last octet of the last payload
 *  in the second message.  Appended to this (for purposes of computing
 *  the signature) are the initiator's nonce Ni (just the value, not the
 *  payload containing it), and the value prf(SK_pr,IDr') where IDr' is
 *  the responder's ID payload excluding the fixed header.  Note that
 *  neither the nonce Ni nor the value prf(SK_pr,IDr') are transmitted.
 */

	hmac_update(&id_ctx, firstpacket.ptr, firstpacket.len);
	hmac_update(&id_ctx, nonce->ptr, nonce->len);
	hmac_update(&id_ctx, idhash, st->st_oakley.prf_hasher->hash_digest_len);
	signed_octets = alloca(st->st_oakley.prf_hasher->hash_digest_len);
	hmac_final(signed_octets, &id_ctx);
	   
    }

    DBG(DBG_CRYPT
	, DBG_dump_chunk("inputs to hash1 (first packet)", firstpacket);
	DBG_dump_chunk(nonce_name, *nonce);
	
	DBG_dump("idhash", idhash, st->st_oakley.prf_hasher->hash_digest_len));
}

bool ikev2_calculate_psk_auth(struct state *st
			      , enum phase1_role role
			      , unsigned char *idhash
			      , pb_stream *a_pbs)
{
	unsigned char  *signed_octets;
	size_t         signed_len;
	const struct connection *c = st->st_connection;
	const chunk_t *pss = get_preshared_secret(c);
	
	if (pss == NULL)
	    return 0;	/* failure: no PSK to use */
	 DBG(DBG_CRYPT
	     , DBG_log("connection:%s", st->st_connection->name, 
			strlen(st->st_connection->name)+1  );
	     DBG_log("psk:%s",*pss));

	ikev2_calculate_psk_sighash(st, role, idhash
				, st->st_firstpacket_me
				, signed_octets);
	DBG(DBG_CRYPT
	    , DBG_dump("psk auth octets", signed_octets, 
	    	        st->st_oakley.prf_hasher->hash_digest_len));
	
	out_raw(signed_octets, st->st_oakley.prf_hasher->hash_digest_len, 
		a_pbs, "psk auth");

	return TRUE;
}

stf_status
ikev2_verify_psk_auth(struct state *st
		      , enum phase1_role role
			    , unsigned char *idhash
			    , pb_stream *sig_pbs)
{
    unsigned int  hash_len =  st->st_oakley.prf_hasher->hash_digest_len;
    unsigned char calc_hash[hash_len];
    size_t sig_len = pbs_left(sig_pbs);

    enum phase1_role invertrole;

    invertrole = (role == INITIATOR ? RESPONDER : INITIATOR);
   
   if(sig_len != hash_len) {
    return STF_FAIL ;
   }
    ikev2_calculate_psk_sighash(st, invertrole, idhash, st->st_firstpacket_him, calc_hash);

   if(memcmp(sig_pbs->cur, calc_hash, hash_len) ) {
   return STF_FAIL ;
   }
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
