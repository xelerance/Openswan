/*
 * Pluto interface to crypto
 *
 * Copyright (C) 2008 David McCullough <david_mccullough@securecomputing.com>
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

#include <sys/types.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>
#include <sys/time.h>
#include <errno.h>
#include <oswalloc.h>

#include <oswcrypto.h>

/*
 * Do the modular exponentiation with Chinese Remainder Theorem in sofware
 */
static void
oswcrypto_rsa_mod_exp_crt_sw(
	mpz_t dst, const mpz_t src,
	const mpz_t p, const mpz_t dP, const mpz_t q, const mpz_t dQ,
	const mpz_t qInv)
{
	mpz_t t2, t3;
	mpz_init(t2);
	mpz_init(t3);

	mpz_powm(t2, src, dP, p);	/* m1 = c^dP mod p */

	mpz_powm(t3, src, dQ, q);	/* m2 = c^dQ mod Q */

	mpz_sub(t2, t2, t3);		/* h = qInv (m1 - m2) mod p */
	mpz_mod(t2, t2, p);
	mpz_mul(t2, t2, qInv);
	mpz_mod(t2, t2, p);

	mpz_mul(t2, t2, q);			/* m = m2 + h q */
	mpz_add(dst, t3, t2);
	mpz_clear(t2);
	mpz_clear(t3);
}

/*
 * Do the modular exponentiation in sofware
 */
static void
oswcrypto_mod_exp_sw(mpz_t r0, const mpz_t mp_g,
	const mpz_t secret, const mpz_t modulus)
{
	mpz_powm(r0, mp_g, secret, modulus);
}


/*
 * Find out what we can support and use it: XXX NEEDS TO BE OBSOLETED.
 */
void
load_oswcrypto(void)
{
	oswcrypto.rsa_mod_exp_crt      = oswcrypto_rsa_mod_exp_crt_sw;
	oswcrypto.mod_exp              = oswcrypto_mod_exp_sw;

	oswcrypto.aes_set_key          = AES_set_key;
	oswcrypto.aes_cbc_encrypt      = AES_cbc_encrypt;

	oswcrypto.des_set_key          = des_set_key;
	oswcrypto.des_cbc_encrypt      = des_cbc_encrypt;
	oswcrypto.des_encrypt          = des_encrypt;
	oswcrypto.des_ncbc_encrypt     = des_ncbc_encrypt;
	oswcrypto.des_ecb_encrypt      = des_ecb_encrypt;

	oswcrypto.des_ede3_cbc_encrypt = des_ede3_cbc_encrypt;

#ifdef HAVE_OCF
	load_cryptodev();
#endif
}

