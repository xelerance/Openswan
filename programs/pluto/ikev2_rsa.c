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

#include "oswcrypto.h"

static u_char der_digestinfo[]={
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
    0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
};
static int der_digestinfo_len=sizeof(der_digestinfo);

static void ikev2_calculate_sighash(struct state *st
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

bool ikev2_calculate_rsa_sha1(struct state *st
			      , enum phase1_role role
			      , unsigned char *idhash
			      , pb_stream *a_pbs)
{
	unsigned char  signed_octets[SHA1_DIGEST_SIZE+16];
	size_t         signed_len;
	const struct connection *c = st->st_connection;
	const struct RSA_private_key *k = get_RSA_private_key(c);
	unsigned int sz;

	if (k == NULL)
	    return 0;	/* failure: no key to use */

	sz = k->pub.k;

	memcpy(signed_octets, der_digestinfo, der_digestinfo_len);

	ikev2_calculate_sighash(st, role, idhash
				, st->st_firstpacket_me
				, signed_octets+der_digestinfo_len);
	signed_len = der_digestinfo_len + SHA1_DIGEST_SIZE;

	passert(RSA_MIN_OCTETS <= sz && 4 + signed_len < sz && sz <= RSA_MAX_OCTETS);

	DBG(DBG_CRYPT
	    , DBG_dump("v2rsa octets", signed_octets, signed_len));

	{
		u_char sig_val[RSA_MAX_OCTETS];

		/* now generate signature blob */
		sign_hash(k, signed_octets, signed_len
			  , sig_val, sz);
		out_raw(sig_val, sz, a_pbs, "rsa signature");
	}

	return TRUE;
}

static err_t
try_RSA_signature_v2(const u_char hash_val[MAX_DIGEST_LEN]
		     , size_t hash_len
		     , const pb_stream *sig_pbs, struct pubkey *kr
		     , struct state *st)
{
    const u_char *sig_val = sig_pbs->cur;
    size_t sig_len = pbs_left(sig_pbs);
#ifndef HAVE_LIBNSS
    u_char s[RSA_MAX_OCTETS];	/* for decrypted sig_val */
    u_char *sig;
    unsigned int padlen;
#endif
    const struct RSA_public_key *k = &kr->u.rsa;

    if (k == NULL)
	return "1""no key available";	/* failure: no key to use */

    /* decrypt the signature -- reversing RSA_sign_hash */
    if (sig_len != k->k)
    {
	return "1""SIG length does not match public key length";
    }

#ifdef HAVE_LIBNSS
    err_t ugh = RSA_signature_verify_nss (k,hash_val,hash_len,sig_val,sig_len);
    if(ugh!=NULL) {
	return ugh;
    }
#else
    /* actual exponentiation; see PKCS#1 v2.0 5.1 */
    {
	chunk_t temp_s;
	MP_INT c;

	n_to_mpz(&c, sig_val, sig_len);
	oswcrypto.mod_exp(&c, &c, &k->e, &k->n);

	temp_s = mpz_to_n(&c, sig_len);	/* back to octets */
	memcpy(s, temp_s.ptr, sig_len);
	pfree(temp_s.ptr);
	mpz_clear(&c);
    }

    /* check signature contents */
    /* verify padding */
    padlen = sig_len - 3 - (hash_len+der_digestinfo_len);
    /* now check padding */
    sig = s;

    if(sig[0]    != 0x00
       || sig[1] != 0x01
       || sig[padlen+2] != 0x00) {
	return "2""SIG padding does not check out";
    }

    /* skip padding */
    sig += padlen+3;

    /* 2 verify that the has was done with SHA1 */
    if(memcmp(der_digestinfo, sig, der_digestinfo_len)!=0) {
	return "SIG not performed with SHA1";
    }

    sig += der_digestinfo_len;

    DBG(DBG_CRYPT,
	DBG_dump("v2rsa decrypted SIG:", hash_val, hash_len);
	DBG_dump("v2rsa computed hash:", sig, hash_len);
    );

    if(memcmp(sig, hash_val, hash_len) != 0) {
	return "9""authentication failure: received SIG does not match computed HASH, but message is well-formed";
    }
#endif

    unreference_key(&st->st_peer_pubkey);
    st->st_peer_pubkey = reference_key(kr);

    return NULL;
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
