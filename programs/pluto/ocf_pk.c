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

#include <sys/types.h>
#include <crypto/cryptodev.h>
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

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "constants.h"
#include "defs.h"
#include "id.h"
#include "pgp.h"
#include "x509.h"
#include "certs.h"
#include "keys.h"
#include "log.h"
#include "ocf_pk.h"
#include "sysqueue.h"
#include "pluto_crypt.h"
#include "server.h"

static u_int32_t cryptodev_asymfeat = 0;
struct cryptodev_meth cryptodev;

#undef DEBUG

/*
 * Return a fd if /dev/crypto seems usable, 0 otherwise.
 */
static int
open_dev_crypto(void)
{
	static int fd = -1;

	if (fd == -1) {
		if ((fd = open("/dev/crypto", O_RDWR, 0)) == -1)
			return (-1);
		/* close on exec */
		if (fcntl(fd, F_SETFD, 1) == -1) {
			close(fd);
			fd = -1;
			return (-1);
		}
	}
	return (fd);
}

/*
 * Get a /dev/crypto file descriptor
 */
static int
get_dev_crypto(void)
{
	int fd, retfd;

	if ((fd = open_dev_crypto()) == -1)
		return (-1);
	if (ioctl(fd, CRIOGET, &retfd) == -1)
		return (-1);

	/* close on exec */
	if (fcntl(retfd, F_SETFD, 1) == -1) {
		close(retfd);
		return (-1);
	}
	return (retfd);
}

/* Caching version for asym operations */
int get_asym_dev_crypto(void)
{
	static int fd = -1;

	if (fd == -1)
		fd = get_dev_crypto();
	return fd;
}

static void cryptodev_mod_exp_sw(MP_INT *r0, MP_INT *mp_g
				, const MP_INT *secret, const MP_INT *modulus)
{
	mpz_powm(r0, mp_g, secret, modulus);
}


/*
 * Find out what we can support and use it.
 */
void load_cryptodev(void)
{
	int fd;

	cryptodev.mod_exp = cryptodev_mod_exp_sw;

	if((fd = get_dev_crypto()) < 0) {
		return;
	}

	/* find out what asymmetric crypto algorithms we support */
	if (ioctl(fd, CIOCASYMFEAT, &cryptodev_asymfeat) == -1) {
		close(fd);
		return;
	}
	close(fd);

	if (cryptodev_asymfeat & CRF_MOD_EXP) {
#ifdef HAVE_OLD_OCF
		/* Use modular exponentiation */
		cryptodev.mod_exp = cryptodev_mod_exp;
#endif
		openswan_log("Performing modular exponentiation acceleration in hardware");
	}
}
