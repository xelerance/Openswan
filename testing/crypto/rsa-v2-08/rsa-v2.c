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
 * This code was developed with the support of IXIA communications.
 *
 * RCSID $Id: crypt_dh.c,v 1.11 2005/08/14 21:47:29 mcr Exp $
 */

#include "../../../programs/pluto/ikev2_rsa.c"
#include "seam_whack.c"

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

unsigned char idhash[SHA1_DIGEST_SIZE] = {
	0x01, 0x02, 0x03, 0x04,
	0x11, 0x12, 0x13, 0x14,
	0x21, 0x22, 0x23, 0x24,
	0x31, 0x32, 0x33, 0x34,
	0x41, 0x42, 0x43, 0x44,
};

#include "packetsI1.c"

extern struct encrypt_desc algo_aes;
struct encrypt_desc *tc3_encrypter = &algo_aes;
#include "../../lib/libpluto/seam_gi_sha1.c"

int main(int argc, char *argv[])
{
	unsigned char outbuf[1024];
	struct state st1;
	pb_stream outs;

	progname = argv[0];
	cur_debugging = DBG_CRYPT;

	/* initialize list of moduli */
	init_crypto();

	init_pbs(&outs, outbuf, 1024, "rsa signature");

	clonetochunk(st1.st_firstpacket, packet1+20, packet1_len-20, "I1");

	ikev2_calculate_rsa_sha1(&st1,
				 idhash,
				 &outs);

	exit(0);
}
