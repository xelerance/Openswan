/* do RSA operations for IKEv2
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

bool ikev2_calculate_rsa_sha1(struct state *st
			 , unsigned char *idhash
			 , pb_stream *a_pbs)
{
	SHA1_CTX       ctx_sha1;
	unsigned char  signed_octets[SHA1_DIGEST_SIZE+16];
	size_t         signed_len;
	static u_char der_digestinfo[]={
		0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
		0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
	};
	static int der_digestinfo_len=sizeof(der_digestinfo);
	const struct connection *c = st->st_connection;
	const struct RSA_private_key *k = get_RSA_private_key(c);
	unsigned int sz;

	if (k == NULL)
	    return 0;	/* failure: no key to use */

	sz = k->pub.k;

	memcpy(signed_octets, der_digestinfo, der_digestinfo_len);

	SHA1Init(&ctx_sha1);
	SHA1Update(&ctx_sha1
		   , st->st_firstpacket.ptr
		   , st->st_firstpacket.len);
	SHA1Update(&ctx_sha1, st->st_nr.ptr, st->st_nr.len);
	SHA1Update(&ctx_sha1, idhash
		   , st->st_oakley.prf_hasher->hash_digest_len);
	SHA1Final(signed_octets+der_digestinfo_len, &ctx_sha1);

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
	
	return STF_OK;
}





/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
