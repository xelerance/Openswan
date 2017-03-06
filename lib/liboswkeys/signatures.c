/*
 * interfaces to the secrets.c library functions in libopenswan.
 * for now, just stupid wrappers!
 *
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2003-2015  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
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
 * Modifications to use OCF interface written by
 * Daniel Djamaludin <danield@cyberguard.com>
 * Copyright (C) 2004-2005 Intel Corporation.
 *
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>

#include <glob.h>
#ifndef GLOB_ABORTED
# define GLOB_ABORTED    GLOB_ABEND	/* fix for old versions */
#endif

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "sysdep.h"
#include "constants.h"
#include "pluto/defs.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "oswlog.h"
#include "mpzfuncs.h"

#include "oswcrypto.h"
#include "pluto/keys.h"

/*
 * compute an RSA signature with PKCS#1 padding: Note that this assumes that any DER encoding is
 *    **INCLUDED** as part of the hash_val/hash_len.
 */
void
sign_hash(const struct private_key_stuff *pks
	  , const u_char *hash_val, size_t hash_len
	  , u_char *sig_val, size_t sig_len)
{
    chunk_t ch;
    mpz_t t1;
    size_t padlen;
    u_char *p = sig_val;
    const struct RSA_private_key *k = &pks->u.RSA_private_key;

    DBG(DBG_CONTROL | DBG_CRYPT,
	DBG_log("signing hash with RSA Key *%s", pks->pub->u.rsa.keyid)
        );

    /* PKCS#1 v1.5 8.1 encryption-block formatting */
    *p++ = 0x00;
    *p++ = 0x01;	/* BT (block type) 01 */
    padlen = sig_len - 3 - hash_len;
    memset(p, 0xFF, padlen);
    p += padlen;
    *p++ = 0x00;
    memcpy(p, hash_val, hash_len);
    passert(p + hash_len - sig_val == (ptrdiff_t)sig_len);

    /* PKCS#1 v1.5 8.2 octet-string-to-integer conversion */
    n_to_mpz(t1, sig_val, sig_len);	/* (could skip leading 0x00) */

    /* PKCS#1 v1.5 8.3 RSA computation y = x^c mod n
     * Better described in PKCS#1 v2.0 5.1 RSADP.
     * There are two methods, depending on the form of the private key.
     * We use the one based on the Chinese Remainder Theorem.
     */
    oswcrypto.rsa_mod_exp_crt(t1, t1, &k->p, &k->dP, &k->q, &k->dQ, &k->qInv);
    /* PKCS#1 v1.5 8.4 integer-to-octet-string conversion */
    ch = mpz_to_n(t1, sig_len);
    memcpy(sig_val, ch.ptr, sig_len);
    pfree(ch.ptr);

    mpz_clear(t1);
}

/*
 * verify an RSA signature with PKCS#1 padding.
 *   psig, which must be non-NULL, is set to where the decoded signature is
 *      s, is some working area which is of size "s_max_octets"
 *   hash_len is expected result size.
 *   sig_val  is actual signature blob.
 *
 */
err_t verify_signed_hash(const struct RSA_public_key *k
                         , u_char *s, unsigned int s_max_octets
                         , u_char **psig
                         , size_t hash_len
                         , const u_char *sig_val, size_t sig_len)
{
    unsigned int padlen;

    /* actual exponentiation; see PKCS#1 v2.0 5.1 */
    {
	chunk_t temp_s;
	MP_INT c;

	n_to_mpz(&c, sig_val, sig_len);
	oswcrypto.mod_exp(&c, &c, &k->e, &k->n);

	temp_s = mpz_to_n(&c, sig_len);	/* back to octets */
        if(s_max_octets < sig_len) {
            return "2""exponentiation failed; too many octets";
        }
	memcpy(s, temp_s.ptr, sig_len);
	pfree(temp_s.ptr);
	mpz_clear(&c);
    }

    /* check signature contents */
    /* verify padding (not including any DER digest info! */
    padlen = sig_len - 3 - hash_len;
    /* now check padding */

    DBG(DBG_CRYPT,
	DBG_dump("verify_sh decrypted SIG1:", s, sig_len));
    DBG(DBG_CRYPT, DBG_log("pad_len calculated: %d hash_len: %d", padlen, (int)hash_len));

    /* skip padding */
    if(s[0]    != 0x00
       || s[1] != 0x01
       || s[padlen+2] != 0x00) {
	return "3""SIG padding does not check out";
    }

    s += padlen + 3;
    (*psig) = s;

    /* return SUCCESS */
    return NULL;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
