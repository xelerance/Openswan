/* crypto interfaces -- list of DH groups
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2017 Michael C. Richardson <mcr@xelerance.com>
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
#include <string.h>
#include <stddef.h>
#include <sys/types.h>

#include <openswan.h>

#include <errno.h>

#include "constants.h"
#include "ietf_constants.h"
#include "pluto/defs.h"
#include "pluto/crypto.h"
#include "pluto/log.h"
#include "algoparse.h"

/* Oakley group description
 *
 * See RFC2409 "The Internet key exchange (IKE)" 6.
 */

static MP_INT
#if defined(USE_VERYWEAK_DH1) 	/* modp768 not sufficiently strong */
    modp768_modulus,
#endif
    modp1024_modulus,
    modp1536_modulus,
    modp2048_modulus,
    modp3072_modulus,
    modp4096_modulus,
    modp6144_modulus,
    modp8192_modulus;

static MP_INT
    dh22_modulus,
    dh23_modulus,
    dh24_modulus;

MP_INT groupgenerator;  /* MODP group generator (2) */

MP_INT generator_dh22,
       generator_dh23,
       generator_dh24;

const struct oakley_group_desc unset_group = {0, NULL, NULL, 0};      /* magic signifier */

const struct oakley_group_desc oakley_group[] = {
#if defined(USE_VERYWEAK_DH1)           /* modp768 not sufficiently strong */
    { OAKLEY_GROUP_MODP768, &groupgenerator, &modp768_modulus, BYTES_FOR_BITS(768) },
#endif
    { OAKLEY_GROUP_MODP1024, &groupgenerator, &modp1024_modulus, BYTES_FOR_BITS(1024) },
    { OAKLEY_GROUP_MODP1536, &groupgenerator, &modp1536_modulus, BYTES_FOR_BITS(1536) },
    { OAKLEY_GROUP_MODP2048, &groupgenerator, &modp2048_modulus, BYTES_FOR_BITS(2048) },
    { OAKLEY_GROUP_MODP3072, &groupgenerator, &modp3072_modulus, BYTES_FOR_BITS(3072) },
    { OAKLEY_GROUP_MODP4096, &groupgenerator, &modp4096_modulus, BYTES_FOR_BITS(4096) },
    { OAKLEY_GROUP_MODP6144, &groupgenerator, &modp6144_modulus, BYTES_FOR_BITS(6144) },
    { OAKLEY_GROUP_MODP8192, &groupgenerator, &modp8192_modulus, BYTES_FOR_BITS(8192) },
    { OAKLEY_GROUP_DH22, &generator_dh22, &dh22_modulus, BYTES_FOR_BITS(1024) },
    { OAKLEY_GROUP_DH23, &generator_dh23, &dh23_modulus, BYTES_FOR_BITS(2048) },
    { OAKLEY_GROUP_DH24, &generator_dh24, &dh24_modulus, BYTES_FOR_BITS(2048) },

};

const unsigned int oakley_group_size = elemsof(oakley_group);

const struct oakley_group_desc *
lookup_group(u_int16_t group)
{
    int i;

    for (i = 0; i != elemsof(oakley_group); i++)
	if (group == oakley_group[i].group)
	    return &oakley_group[i];
    return NULL;
}

void
init_crypto_groups(void)
{
    if (mpz_init_set_str(&groupgenerator, MODP_GENERATOR, 10) != 0
    ||  mpz_init_set_str(&generator_dh22, MODP_GENERATOR_DH22, 16) != 0
    ||  mpz_init_set_str(&generator_dh23, MODP_GENERATOR_DH23, 16) != 0
    ||  mpz_init_set_str(&generator_dh24, MODP_GENERATOR_DH24, 16) != 0
#if defined(USE_VERYWEAK_DH1)	                        /* modp768 not sufficiently strong */
    || mpz_init_set_str(&modp768_modulus, MODP768_MODULUS, 16) != 0
#endif
    || mpz_init_set_str(&modp1024_modulus, MODP1024_MODULUS, 16) != 0
    || mpz_init_set_str(&modp1536_modulus, MODP1536_MODULUS, 16) != 0
    || mpz_init_set_str(&modp2048_modulus, MODP2048_MODULUS, 16) != 0
    || mpz_init_set_str(&modp3072_modulus, MODP3072_MODULUS, 16) != 0
    || mpz_init_set_str(&modp4096_modulus, MODP4096_MODULUS, 16) != 0
    || mpz_init_set_str(&modp6144_modulus, MODP6144_MODULUS, 16) != 0
    || mpz_init_set_str(&modp8192_modulus, MODP8192_MODULUS, 16) != 0
    || mpz_init_set_str(&dh22_modulus, MODP1024_MODULUS_DH22, 16) != 0
    || mpz_init_set_str(&dh23_modulus, MODP2048_MODULUS_DH23, 16) != 0
    || mpz_init_set_str(&dh24_modulus, MODP2048_MODULUS_DH24, 16) != 0
      ) {
      openswan_exit_log("mpz_init_set_str() failed in init_crypto()");
     }
}

