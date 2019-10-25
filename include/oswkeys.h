/* mechanisms for reading public keys.
 *
 * Copyright (C) 2017 Michael Richardson <mcr@xelerance.com>
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
 */
#ifndef _OSWKEYS_H
#define _OSWKEYS_H

#include "constants.h"
#include "secrets.h"

extern err_t str2pubkey(const unsigned char *key1, enum pubkey_alg kind, osw_public_key *opk);
extern void calculate_rsa_ckaid(osw_public_key *pub);


#endif /* _OSWKEYS_H */
/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
