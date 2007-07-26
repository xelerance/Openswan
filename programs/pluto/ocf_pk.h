/* 
 * Pluto interface to the Open Cryptographic Framework (OCF) for PK operations.
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
 * This code was developed with the support of Hifn, Inc.
 *
 */

struct cryptodev_meth {
	//int (*rsa_mod_exp_crt)(const struct RSA_private_key *k, mpz_t *t1, BIGNUM *r0);
	void (*mod_exp)(MP_INT *r0, MP_INT *mp_g
			, const MP_INT *secret, const MP_INT *modulus);
};

extern struct cryptodev_meth cryptodev;
extern void load_cryptodev(void);
extern int get_asym_dev_crypto(void);

