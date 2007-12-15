/* 
 * unit test for IKEv2 RSA signature/verification
 *
 * Copyright (C) 2007 Michael C. Richardson <mcr@xelerance.com>
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

#define LEAK_DETECTIVE
#define AGGRESSIVE 1
#define XAUTH 
#define MODECFG 
#define DEBUG 1
#define PRINT_SA_DEBUG 1
#define USE_KEYRR 1

#include <stdio.h>
#include <stdlib.h>
#include "sysqueue.h"
#include "oswlog.h"
#include "oswconf.h"
#include "packet.h"
#include "defs.h"
#include "connections.h"
#include "state.h"
#include "keys.h"
#include "crypto.h"
#include "readwhackmsg.h"
#include "ike_alg.h"
#include "ikev2.h"
#include "ocf_pk.h"

/* for child sa calculation */
#include "alg_info.h"
#include "kernel_alg.h"
#include "ikev2_prfplus.h"

#include "seam_pending.c"
#include "whackmsgtestlib.c"
#include "seam_whack.c"
#include "seam_log.c"
#include "seam_east.c"
#include "seam_rnd.c"
#include "seam_timer.c"
#include "seam_initiate.c" 
#include "seam_xauth.c"
#include "seam_natt.c"
#include "seam_state.c"
#include "seam_kernelops.c"

void gw_addref(struct gw_info *gw) {}
void gw_delref(struct gw_info **gwp) {}
bool in_pending_use(struct connection *c) { return FALSE; }

char *progname;

const char*
check_expiry(time_t expiration_date, int warning_interval, bool strict)
{
	return "ok (never)";
}

void exit_log(const char *message, ...)
{
	va_list args;
	char m[LOG_WIDTH];	/* longer messages will be truncated */

	va_start(args, message);
	vsnprintf(m, sizeof(m), message, args);
	va_end(args);

	fprintf(stderr, "FATAL ERROR: %s\n", m);
	exit(0);
}

void exit_tool(int code)
{
	exit(code);
}

void exit_pluto(int code)
{
	exit(code);
}

extern struct encrypt_desc algo_aes;
struct encrypt_desc *tc3_encrypter = &algo_aes;
#include "../../lib/libpluto/seam_gi_sha1.c"

int main(int argc, char *argv[])
{
	struct state st1;

	progname = argv[0];
	cur_debugging = DBG_CRYPT;

	memset(&st1, 0, sizeof(st1));
	pluto_shared_secrets_file = "../../baseconfigs/east/etc/ipsec.secrets";

	osw_init_ipsecdir("../../baseconfigs/east/etc/ipsec.d");
	osw_init_rootdir("../../baseconfigs/east");

	/* initialize list of moduli */
	init_crypto();
	load_cryptodev();

	/* now derive the keys for the CHILD_SA */
	{
		chunk_t ikeymat,rkeymat;
		chunk_t skey_d;
		struct v2prf_stuff childsacalc;
		struct ipsec_proto_info ipi;
		enum phase1_role role = INITIATOR;

		ipi.attrs.transattrs.encrypt   = IKEv2_ENCR_AES_CBC;
		ipi.attrs.transattrs.enckeylen = 128;
		ipi.attrs.transattrs.integ_hash = IKEv2_AUTH_HMAC_SHA1_96;

                ipi.attrs.transattrs.ei=kernel_alg_esp_info(
			ipi.attrs.transattrs.encrypt,
			ipi.attrs.transattrs.enckeylen,
			ipi.attrs.transattrs.integ_hash);
		
		passert(ipi.attrs.transattrs.ei != NULL);

		memset(&childsacalc, 0, sizeof(childsacalc));
		setchunk(childsacalc.ni, st1.st_ni.ptr, st1.st_ni.len);
		setchunk(childsacalc.nr, st1.st_nr.ptr, st1.st_nr.len);
		childsacalc.spii.len=0;
		childsacalc.spir.len=0;
		
		setchunk(skey_d, tc3_results_skey_d, sizeof(tc3_results_skey_d));
		childsacalc.skeyseed = &skey_d;
		
		ipi.present = TRUE;
		ipi.keymat_len = ipi.attrs.transattrs.ei->enckeylen+
			ipi.attrs.transattrs.ei->authkeylen;


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
		
		v2genbytes(&ikeymat, ipi.keymat_len
			   , "initiator keys", &childsacalc);

		v2genbytes(&rkeymat, ipi.keymat_len
			   , "initiator keys", &childsacalc);

		if(role == INITIATOR) {
			ipi.our_keymat = ikeymat.ptr;
			ipi.peer_keymat= rkeymat.ptr;
		} else {
			ipi.peer_keymat= ikeymat.ptr;
			ipi.our_keymat = rkeymat.ptr;
		}

		DBG_dump_chunk("initiator keymat: ", ikeymat);
		DBG_dump_chunk("responder keymat: ", rkeymat);
	}
		

	exit(0);
}


