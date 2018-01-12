/* do RSA calculations operations for IKEv2
 *
 * Copyright (C) 2015 Michael Richardson <mcr@xelerance.com>
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
#include "pluto/crypto.h" /* requires sha1.h and md5.h */
#include "pluto/ike_alg.h"
#include "log.h"
#include "demux.h"	/* needs packet.h */
#include "ikev2.h"
#include "pluto/server.h"
#include "vendor.h"
#include "dpd.h"
#include "keys.h"

#include "oswcrypto.h"

bool ikev2_calculate_rsa_sha1(struct state *st
			      , enum phase1_role role
			      , unsigned char *idhash
			      , pb_stream *a_pbs)
{
	unsigned char  signed_octets[SHA1_DIGEST_SIZE+16];
	size_t         signed_len;
	const struct connection *c = st->st_connection;
	const struct private_key_stuff *pks = get_RSA_private_key(c);
	unsigned int sz;

	if (pks == NULL)
	    return 0;	/* failure: no key to use */

	sz = pks->pub->u.rsa.k;

        /* record what key we did the signature with */
        memcpy(st->st_our_keyid, pks->pub->u.rsa.keyid, KEYID_BUF);

        /*
         * this is the prefix of the ASN/DER goop that lives inside RSA-SHA1
         * signatures.  If the signing hash changes, this needs to change
         * too, but this function is specific to RSA-SHA1.
         */
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
		sign_hash(pks, signed_octets, signed_len
			  , sig_val, sz);
		out_raw(sig_val, sz, a_pbs, "rsa signature");
	}

	return TRUE;
}

err_t
try_RSA_signature_v2(const u_char hash_val[MAX_DIGEST_LEN]
		     , size_t hash_len
		     , const pb_stream *sig_pbs, struct pubkey *kr
		     , struct state *st)
{
    const u_char *sig_val = sig_pbs->cur;
    size_t sig_len = pbs_left(sig_pbs);
    u_char s[RSA_MAX_OCTETS];	/* for decrypted sig_val */
    u_char *sig;
    err_t e = NULL;
    const struct RSA_public_key *k = &kr->u.rsa;

    if (k == NULL)
	return "1""no key available";	/* failure: no key to use */

    /* decrypt the signature -- reversing RSA_sign_hash */
    if (sig_len != k->k)
    {
        DBG_log("sig_len: %u != k->k: %u"
                , (unsigned int)sig_len, (unsigned int)k->k);
	return "1""SIG length does not match public key length";
    }

    if((e = verify_signed_hash(k, s, sizeof(s), &sig, hash_len+der_digestinfo_len,
                               sig_val, sig_len)) != NULL) {
        return e;
    }

    /* 2 verify that the has was done with SHA1 */
    if(memcmp(der_digestinfo, sig, der_digestinfo_len)!=0) {
	return "SIG not performed with SHA1";
    }
    sig += der_digestinfo_len;

    DBG(DBG_CRYPT,
	DBG_dump("v2rsa decrypted SIG:", sig,      hash_len);
	DBG_dump("v2rsa computed hash:", hash_val, hash_len);
    );

    if(memcmp(sig, hash_val, hash_len) != 0) {
	return "9""authentication failure: received SIG does not match computed HASH, but message is well-formed";
    }

    unreference_key(&st->st_peer_pubkey);
    st->st_peer_pubkey = reference_key(kr);

    return NULL;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
