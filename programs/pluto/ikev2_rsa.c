/* do RSA operations for IKEv2
 *
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
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
#include "pluto/state.h"
#include "packet.h"
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "ike_alg.h"
#include "log.h"
#include "demux.h"	/* needs packet.h */
#include "ikev2.h"
#include "pluto/server.h"
#include "vendor.h"
#include "dpd.h"
#include "keys.h"

#include "oswcrypto.h"

void ikev2_calculate_sighash(struct state *st
                             , enum phase1_role role
                             , unsigned char *idhash
                             , chunk_t firstpacket
                             , unsigned char *sig_octets)
{
	SHA1_CTX       ctx_sha1;
	const chunk_t *nonce;
	const char    *nonce_name;

	if(role == INITIATOR) {
	    /* on initiator, we need to hash responders nonce */
	    nonce = &st->st_nr;
	    nonce_name = "inputs to hash2 (responder nonce)";
	} else {
	    nonce = &st->st_ni;
	    nonce_name = "inputs to hash2 (initiator nonce)";
	}

	DBG(DBG_CRYPT
	    , DBG_dump_chunk("inputs to hash1 (first packet)", firstpacket);
	      DBG_dump_chunk(nonce_name, *nonce);
	    DBG_dump("idhash", idhash, st->st_oakley.prf_hasher->hash_digest_len));

	SHA1Init(&ctx_sha1);
	SHA1Update(&ctx_sha1
		   , firstpacket.ptr
		   , firstpacket.len);
	SHA1Update(&ctx_sha1, nonce->ptr, nonce->len);

	/* we took the PRF(SK_d,ID[ir]'), so length is prf hash length */
	SHA1Update(&ctx_sha1, idhash
		   , st->st_oakley.prf_hasher->hash_digest_len);

	SHA1Final(sig_octets, &ctx_sha1);
}

stf_status
ikev2_verify_rsa_sha1(struct state *st
		      , enum phase1_role role
			    , unsigned char *idhash
			    , const struct pubkey_list *keys_from_dns
			    , const struct gw_info *gateways_from_dns
			    , pb_stream *sig_pbs)
{
    unsigned char calc_hash[SHA1_DIGEST_SIZE];
    unsigned int  hash_len = SHA1_DIGEST_SIZE;
    enum phase1_role invertrole;

    invertrole = (role == INITIATOR ? RESPONDER : INITIATOR);

    ikev2_calculate_sighash(st, invertrole, idhash, st->st_firstpacket_him, calc_hash);

    DBG(DBG_CRYPT,
        DBG_dump("v2rsa calculated octets", calc_hash, hash_len);
        DBG_dump_pbs(sig_pbs);
        );

    return RSA_check_signature_gen(st, calc_hash, hash_len
				   , sig_pbs
#ifdef USE_KEYRR
				   , keys_from_dns
#endif
				   , gateways_from_dns
				   , try_RSA_signature_v2);

}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
