/* IKEv2 - more cryptographic calculations
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
#include "libopenswan.h"

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
#include "ikev2.h"
#include "ikev2_prfplus.h"
#include "ike_alg.h"
#include "alg_info.h"
#include "kernel_alg.h"

void ikev2_derive_child_keys(struct state *st)
{
	struct v2prf_stuff childsacalc;
	enum phase1_role role = INITIATOR;
	chunk_t ikeymat,rkeymat;
	struct ipsec_proto_info *ipi = &st->st_esp;
	
	ipi->attrs.transattrs.ei=kernel_alg_esp_info(
		ipi->attrs.transattrs.encrypt, 
		ipi->attrs.transattrs.enckeylen,
		ipi->attrs.transattrs.integ_hash);

	passert(ipi->attrs.transattrs.ei != NULL);
	memset(&childsacalc, 0, sizeof(childsacalc));
	childsacalc.prf_hasher = (struct hash_desc *)
		ike_alg_ikev2_find(IKE_ALG_HASH
				   , IKEv2_PRF_HMAC_SHA1, 0);
	
	setchunk(childsacalc.ni, st->st_ni.ptr, st->st_ni.len);
	setchunk(childsacalc.nr, st->st_nr.ptr, st->st_nr.len);
	childsacalc.spii.len=0;
	childsacalc.spir.len=0;
	
	childsacalc.skeyseed = &st->st_skey_d;
	
	st->st_esp.present = TRUE;
	st->st_esp.keymat_len = st->st_esp.attrs.transattrs.ei->enckeylen+
		st->st_esp.attrs.transattrs.ei->authkeylen;
	
	
/*
 *
 * Keying material MUST be taken from the expanded KEYMAT in the
 * following order:
 *
 *    All keys for SAs carrying data from the initiator to the responder
 *    are taken before SAs going in the reverse direction.
 *
 *    If multiple IPsec protocols are negotiated, keying material is
 *    taken in the order in which the protocol headers will appear in
 *    the encapsulated packet.
 *
 *    If a single protocol has both encryption and authentication keys,
 *    the encryption key is taken from the first octets of KEYMAT and
 *    the authentication key is taken from the next octets.
 *
 */
	
	v2genbytes(&ikeymat, st->st_esp.keymat_len
		   , "initiator keys", &childsacalc);
	
	v2genbytes(&rkeymat, st->st_esp.keymat_len
		   , "initiator keys", &childsacalc);
	
	if(role == INITIATOR) {
		st->st_esp.our_keymat = ikeymat.ptr;
		st->st_esp.peer_keymat= rkeymat.ptr;
	} else {
		st->st_esp.peer_keymat= ikeymat.ptr;
		st->st_esp.our_keymat = rkeymat.ptr;
	}
}
 

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
 
