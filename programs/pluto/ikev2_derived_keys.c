/* IKEv2 - more cryptographic calculations
 *
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2010 Paul Wouters <paul@xelerance.com>
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
#include "pluto/connections.h"	/* needs id.h */
#include "state.h"
#include "packet.h"
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "demux.h"
#include "ike_alg.h"
#include "ikev2.h"
#include "ikev2_prfplus.h"
#include "alg_info.h"
#include "kernel_alg.h"

stf_status ikev2_derive_child_keys(struct state *st, enum phase1_role role)
{
	struct v2prf_stuff childsacalc;
	struct state *pst;
	enum ikev2_trans_type_prf alg;

	chunk_t ikeymat,rkeymat;
	struct ipsec_proto_info *ipi = &st->st_esp;

	ipi->attrs.transattrs.ei=kernel_alg_esp_info(
		ipi->attrs.transattrs.encrypt,
		ipi->attrs.transattrs.enckeylen,
		ipi->attrs.transattrs.integ_hash);

	passert(ipi->attrs.transattrs.ei != NULL);
	memset(&childsacalc, 0, sizeof(childsacalc));

	pst = st;
	if(st && st->st_clonedfrom) {
		/* find parent state for PRF hash alg */
		pst = state_with_serialno(st->st_clonedfrom);
	}

	alg = pst->st_oakley.prf_hash;
	childsacalc.prf_hasher = ikev1_crypto_get_prf(alg);
	if (!childsacalc.prf_hasher) {
		DBG(DBG_CONTROL,
		    DBG_log("unsupported prf+ algorithm %d", alg));
		return STF_FAIL;
	}

	DBG(DBG_CRYPT,
	    DBG_log("%s: using %s for prf+ (SA #%ld cloned from #%ld)",
		    __FUNCTION__, childsacalc.prf_hasher
			    ?  childsacalc.prf_hasher->common.name
			    : "n/a",
		    st->st_serialno, st->st_clonedfrom));

	DBG(DBG_CRYPT,
		char buf[256];
		struct connection *c = st->st_connection;
		if (c->alg_info_ike) {
			alg_info_snprint(buf, sizeof(buf),
				 (struct alg_info *)c->alg_info_ike);
			DBG_log("SA #%lu IKE alg: %s", st->st_serialno, buf);
		}
		if (c->alg_info_esp) {
			alg_info_snprint(buf, sizeof(buf),
				 (struct alg_info *)c->alg_info_esp);
			DBG_log("SA #%lu ESP alg: %s", st->st_serialno, buf);
		}
		c = pst->st_connection;
		if (st != pst && c->alg_info_ike) {
			alg_info_snprint(buf, sizeof(buf),
				 (struct alg_info *)c->alg_info_ike);
			DBG_log("SA #%lu IKE alg: %s", pst->st_serialno, buf);
		}
		if (st != pst && c->alg_info_esp) {
			alg_info_snprint(buf, sizeof(buf),
				 (struct alg_info *)c->alg_info_esp);
			DBG_log("SA #%lu ESP alg: %s", pst->st_serialno, buf);
		}
	);

	setchunk(childsacalc.ni, st->st_ni.ptr, st->st_ni.len);
	setchunk(childsacalc.nr, st->st_nr.ptr, st->st_nr.len);

	DBG(DBG_CRYPT,
	    DBG_dump("childsacalc.ni", childsacalc.ni.ptr, childsacalc.ni.len);
	    DBG_dump("childsacalc.nr", childsacalc.nr.ptr, childsacalc.nr.len));

	childsacalc.spii.len=0;
	childsacalc.spir.len=0;

	childsacalc.counter[0] = 1;
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

	DBG(DBG_CRYPT,
	    DBG_log("%s: my role is %s", __FUNCTION__, ROLE_NAME(role)));

	v2genbytes(&ikeymat, st->st_esp.keymat_len
		   , "initiator keys", &childsacalc);

	v2genbytes(&rkeymat, st->st_esp.keymat_len
		   , "responder keys", &childsacalc);

	if(role != INITIATOR) {
	    DBG(DBG_CRYPT,
		DBG_dump_chunk("our  keymat", ikeymat);
		DBG_dump_chunk("peer keymat", rkeymat);
	    );
	    st->st_esp.our_keymat = ikeymat.ptr;
	    st->st_esp.peer_keymat= rkeymat.ptr;
	} else {
	    DBG(DBG_CRYPT,
		DBG_dump_chunk("our  keymat", rkeymat);
		DBG_dump_chunk("peer keymat", ikeymat);
	    );
	    st->st_esp.peer_keymat= ikeymat.ptr;
	    st->st_esp.our_keymat = rkeymat.ptr;
	}

	return STF_OK;
}


/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */

