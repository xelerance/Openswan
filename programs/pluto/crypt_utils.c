/*
 * Cryptographic helper function.
 * Copyright (C) 2004 Michael C. Richardson <mcr@xelerance.com>
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
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <signal.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "packet.h"
#include "demux.h"
#include "oswlog.h"
#include "log.h"
#include "pluto/state.h"
#include "demux.h"
#include "rnd.h"
#include "pluto_crypt.h"

void pluto_crypto_allocchunk(wire_chunk_t *space
			     , wire_chunk_t *new
			     , size_t howbig)
{
    /*
     * passert for now, since we should be able to figure out what
     * the maximum is.
     */
    passert(howbig < space->len - space->start);

    new->start = space->start;
    new->len   = howbig;

    space->start += howbig;
}

void pluto_crypto_copychunk(wire_chunk_t *spacetrack
			    , unsigned char *space
			    , wire_chunk_t *new
			    , chunk_t data)
{
    /* allocate some space first */
    pluto_crypto_allocchunk(spacetrack, new, data.len);

    /* copy data into it */
    memcpy(space_chunk_ptr(space, new), data.ptr, data.len);
}

int v2tov1_encr(enum ikev2_trans_type_encr encr)
{
    switch(encr) {
    case IKEv2_ENCR_DES:
        return OAKLEY_DES_CBC;
    case  IKEv2_ENCR_IDEA:
        return OAKLEY_IDEA_CBC;
    case  IKEv2_ENCR_BLOWFISH:
        return OAKLEY_BLOWFISH_CBC;
    case  IKEv2_ENCR_RC5:
        return OAKLEY_RC5_R16_B64_CBC;
    case  IKEv2_ENCR_3DES:
        return OAKLEY_3DES_CBC;
    case  IKEv2_ENCR_CAST:
        return OAKLEY_CAST_CBC;
    case  IKEv2_ENCR_AES_CBC:
        return OAKLEY_AES_CBC;
    default:
	return 0;
    }
}

int v2tov1_encr_child(enum ikev2_trans_type_encr encr)
{
    switch(encr) {
    case IKEv2_ENCR_DES:
        return ESP_DES;
    case  IKEv2_ENCR_IDEA:
        return ESP_IDEA;
    case  IKEv2_ENCR_BLOWFISH:
        return ESP_BLOWFISH;
    case  IKEv2_ENCR_RC5:
        return ESP_RC5;
    case  IKEv2_ENCR_3DES:
        return ESP_3DES;
    case  IKEv2_ENCR_CAST:
        return ESP_CAST;
    case  IKEv2_ENCR_NULL:
        return ESP_NULL;
    case  IKEv2_ENCR_AES_CBC:
        return ESP_AES;
    default:
	return 0;
    }
}

int v2tov1_integ(enum ikev2_trans_type_integ v2integ)
{
    switch(v2integ) {
    case IKEv2_AUTH_HMAC_MD5_96:
        return OAKLEY_MD5;
    case IKEv2_AUTH_HMAC_SHA1_96:
        return OAKLEY_SHA1;
    case IKEv2_AUTH_HMAC_SHA2_256_128:
        return OAKLEY_SHA2_256;
     case IKEv2_AUTH_HMAC_SHA2_384_192:
         return OAKLEY_SHA2_384;
     case IKEv2_AUTH_HMAC_SHA2_512_256:
         return OAKLEY_SHA2_512;
     default:
         return -1;
     }
}

int v2tov1_integ_child(enum ikev2_trans_type_integ v2integ)
{
    switch(v2integ) {
    case IKEv2_AUTH_HMAC_MD5_96:
        return AUTH_ALGORITHM_HMAC_MD5;
    case IKEv2_AUTH_HMAC_SHA1_96:
        return AUTH_ALGORITHM_HMAC_SHA1;
    case IKEv2_AUTH_HMAC_SHA2_256_128:
        return AUTH_ALGORITHM_HMAC_SHA2_256;
    case IKEv2_AUTH_HMAC_SHA2_384_192:
        return AUTH_ALGORITHM_HMAC_SHA2_384;
    case IKEv2_AUTH_HMAC_SHA2_512_256:
        return AUTH_ALGORITHM_HMAC_SHA2_512;
    default:
        return IKEv2_AUTH_INVALID;
   }
}

int v2integ_to_prf(enum ikev2_trans_type_integ v2integ)
{
    switch(v2integ) {
    case IKEv2_AUTH_HMAC_MD5_96:
        return IKEv2_PRF_HMAC_MD5;
    case IKEv2_AUTH_HMAC_SHA1_96:
        return IKEv2_PRF_HMAC_SHA1;
    case IKEv2_AUTH_HMAC_SHA2_256_128:
        return IKEv2_PRF_HMAC_SHA2_256;
    case IKEv2_AUTH_HMAC_SHA2_384_192:
        return IKEv2_PRF_HMAC_SHA2_384;
    case IKEv2_AUTH_HMAC_SHA2_512_256:
        return IKEv2_PRF_HMAC_SHA2_512;
    default:
        return IKEv2_PRF_INVALID;
    }
}

int v2prf_to_integ(enum ikev2_trans_type_prf v2prf)
{
    switch(v2prf) {
    case IKEv2_PRF_HMAC_MD5:
        return IKEv2_AUTH_HMAC_MD5_96;
    case IKEv2_PRF_HMAC_SHA1:
        return IKEv2_AUTH_HMAC_SHA1_96;
    case IKEv2_PRF_HMAC_SHA2_256:
        return IKEv2_AUTH_HMAC_SHA2_256_128;
    case IKEv2_PRF_HMAC_SHA2_384:
        return IKEv2_AUTH_HMAC_SHA2_384_192;
    case IKEv2_PRF_HMAC_SHA2_512:
        return IKEv2_AUTH_HMAC_SHA2_512_256;
    default:
        return IKEv2_AUTH_INVALID;
    }

}

int v2tov1_prf(enum ikev2_trans_type_prf v2prf)
{
    switch(v2prf) {
    case IKEv2_PRF_HMAC_MD5:
        return OAKLEY_MD5;
    case IKEv2_PRF_HMAC_SHA1:
        return OAKLEY_SHA1;
    case IKEv2_PRF_HMAC_SHA2_256:
        return OAKLEY_SHA2_256;
    case IKEv2_PRF_HMAC_SHA2_384:
        return OAKLEY_SHA2_384;
    case IKEv2_PRF_HMAC_SHA2_512:
        return OAKLEY_SHA2_512;
    default:
        return -1;
    }
}



/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
