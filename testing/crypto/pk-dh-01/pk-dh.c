/* 
 * unit tests for cryptographic helper function - calculate KE and nonce
 *
 * Copyright (C) 2006 Michael C. Richardson <mcr@xelerance.com>
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
 * This code was developed with the support of IXIA communications.
 *
 * RCSID $Id: crypt_dh.c,v 1.11 2005/08/14 21:47:29 mcr Exp $
 */

#include "../../../programs/pluto/hmac.c"
#include "../../../programs/pluto/crypto.c"
#include "../../../programs/pluto/ike_alg.c"
#include "../../../programs/pluto/crypt_utils.c"
#include "../../../programs/pluto/crypt_dh.c"

#include "crypto.h"

char *progname;

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

/*
 * while the rest of this file is covered under the GPL, the following
 * constant values, being inputs and outputs of a mathematical formula
 * are hereby placed in the public domain, including the expression of them
 * in the form of this C code.
 *
 * I.e. please rip off my test data so that the world will be a better place.
 *
 */

#include "../../lib/libpluto/seam_gir.c"
struct encrypt_desc *tc2_encrypter = &crypto_encrypter_3des;

int main(int argc, char *argv[])
{
	struct pluto_crypto_req r;
	struct pcr_skeyid_r *skr = &r.pcr_d.dhr;
	struct pcr_skeyid_q *skq = &r.pcr_d.dhq;

	progname = argv[0];
	
	/* initialize list of moduli */
	init_crypto();

	skq->thespace.start = 0;
	skq->thespace.len   = sizeof(skq->space);
	skq->auth = tc2_auth;
	skq->hash = tc2_hash;
	skq->oakley_group = tc2_oakleygroup;
	skq->init = tc2_init;
	skq->keysize = tc2_encrypter->keydeflen/BITS_PER_BYTE;

#define copydatlen(field, data, len) do { \
		chunk_t tchunk;           \
		setchunk(tchunk, data, len); \
		pluto_crypto_copychunk(&skq->thespace, skq->space \
				       , &skq->field, tchunk); }   \
		while(0)

	copydatlen(ni, tc2_ni, tc2_ni_len);
	copydatlen(nr, tc2_nr, tc2_nr_len);
	copydatlen(gi, tc2_gi, tc2_gi_len);
	copydatlen(gr, tc2_gr, tc2_gr_len);
	copydatlen(secret, tc2_secret, tc2_secret_len);
	copydatlen(icookie, tc2_icookie, tc2_icookie_len);
	copydatlen(rcookie, tc2_rcookie, tc2_rcookie_len);

#define dumpdat(field) \
	openswan_DBG_dump(#field,	\
			  wire_chunk_ptr(skq, &skq->field), \
			  skq->field.len);

	dumpdat(icookie);
	dumpdat(rcookie);
	dumpdat(ni);
	dumpdat(nr);
	dumpdat(gi);
	dumpdat(gr);
	dumpdat(secret);

	fflush(stdout);
	fflush(stderr);
	
	calc_dh_iv(&r);

	printf("\noutput:\n");
	

	{
		void *shared = wire_chunk_ptr(skr, &skr->shared);

		openswan_DBG_dump("shared", shared, skr->shared.len);
	}

	exit(4);
}
