/* crypto interfaces
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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
 * RCSID $Id: crypto.c,v 1.26.6.1 2004/03/21 05:23:32 mcr Exp $
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>

#include <openswan.h>
#define HEADER_DES_LOCL_H   /* stupid trick to force prototype decl in <des.h> */
#include <crypto/des.h>

#include "constants.h"
#include "defs.h"
#include "state.h"
#include "log.h"
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */


/* moduli and generator. */


static MP_INT
#if 0	/* modp768 not sufficiently strong */
    modp768_modulus,
#endif
    modp1024_modulus,
    modp1536_modulus;

MP_INT groupgenerator;	/* MODP group generator (2) */

void
init_crypto(void)
{
    if (mpz_init_set_str(&groupgenerator, MODP_GENERATOR, 10) != 0
#if 0	/* modp768 not sufficiently strong */
    || mpz_init_set_str(&modp768_modulus, MODP768_MODULUS, 16) != 0
#endif
    || mpz_init_set_str(&modp1024_modulus, MODP1024_MODULUS, 16) != 0
    || mpz_init_set_str(&modp1536_modulus, MODP1536_MODULUS, 16) != 0)
	exit_log("mpz_init_set_str() failed in init_crypto()");
}

/* Oakley group description
 *
 * See RFC2409 "The Internet key exchange (IKE)" 6.
 */

const struct oakley_group_desc unset_group = {0, NULL, 0};	/* magic signifier */

static const struct oakley_group_desc oakley_group[] = {
#if 0	/* modp768 not sufficiently strong */
    { OAKLEY_GROUP_MODP768, &modp768_modulus, BYTES_FOR_BITS(768) },
#endif
    { OAKLEY_GROUP_MODP1024, &modp1024_modulus, BYTES_FOR_BITS(1024) },
    { OAKLEY_GROUP_MODP1536, &modp1536_modulus, BYTES_FOR_BITS(1536) },
};

const struct oakley_group_desc *
lookup_group(u_int16_t group)
{
    int i;

    for (i = 0; i != elemsof(oakley_group); i++)
	if (group == oakley_group[i].group)
	    return &oakley_group[i];
    return NULL;
}

/* Encryption Routines
 *
 * Each uses and updates the state object's st_new_iv.
 * This must already be initialized.
 */

/* encrypt or decrypt part of an IKE message using DES
 * See RFC 2409 "IKE" Appendix B
 */
static void
do_des(bool enc, void *buf, size_t buf_len, struct state *st)
{
    des_key_schedule ks;

    (void) des_set_key((des_cblock *)st->st_enc_key.ptr, ks);

    passert(st->st_new_iv_len >= DES_CBC_BLOCK_SIZE);
    st->st_new_iv_len = DES_CBC_BLOCK_SIZE;	/* truncate */

    des_ncbc_encrypt((des_cblock *)buf, (des_cblock *)buf, buf_len,
	ks,
	(des_cblock *)st->st_new_iv, enc);
}

/* encrypt or decrypt part of an IKE message using 3DES
 * See RFC 2409 "IKE" Appendix B
 */
static void
do_3des(bool enc, void *buf, size_t buf_len, struct state *st)
{
    des_key_schedule ks[3];

    (void) des_set_key((des_cblock *)st->st_enc_key.ptr + 0, ks[0]);
    (void) des_set_key((des_cblock *)st->st_enc_key.ptr + 1, ks[1]);
    (void) des_set_key((des_cblock *)st->st_enc_key.ptr + 2, ks[2]);

    passert(st->st_new_iv_len >= DES_CBC_BLOCK_SIZE);
    st->st_new_iv_len = DES_CBC_BLOCK_SIZE;	/* truncate */

    des_ede3_cbc_encrypt((des_cblock *)buf, (des_cblock *)buf, buf_len,
	ks[0], ks[1], ks[2],
	(des_cblock *)st->st_new_iv, enc);
}

const struct encrypt_desc oakley_encrypter[OAKLEY_CAST_CBC + 1] = {
    /* (none) */
	{ 0, 0, NULL },
    /* OAKLEY_DES_CBC */
	{ DES_CBC_BLOCK_SIZE, DES_CBC_BLOCK_SIZE, do_des },
    /* OAKLEY_IDEA_CBC */
	{ 0, 0, NULL },
    /* OAKLEY_BLOWFISH_CBC */
	{ 0, 0, NULL },
    /* OAKLEY_RC5_R16_B64_CBC */
	{ 0, 0, NULL },
    /* OAKLEY_3DES_CBC */
	{ DES_CBC_BLOCK_SIZE, DES_CBC_BLOCK_SIZE * 3, do_3des },
    /* OAKLEY_CAST_CBC */
	{ 0, 0, NULL },
    };

/* hash and prf routines */

const struct hash_desc oakley_hasher[OAKLEY_TIGER+1] = {
	{ 0, NULL, NULL, NULL },	/* no specified hasher */

	{ MD5_DIGEST_SIZE,
	    (void (*)(union hash_ctx *)) MD5Init,
	    (void (*)(union hash_ctx *, const u_char *, unsigned int)) MD5Update,
	    (void (*)(u_char *, union hash_ctx *)) MD5Final},	/* OAKLEY_MD5 */

	{ SHA1_DIGEST_SIZE,
	    (void (*)(union hash_ctx *)) SHA1Init,
	    (void (*)(union hash_ctx *, const u_char *, unsigned int)) SHA1Update,
	    (void (*)(u_char *, union hash_ctx *)) SHA1Final},	/* OAKLEY_SHA */

	{ 0, NULL, NULL, NULL }	/* OAKLEY_TIGER */
    };

/* HMAC package
 * rfc2104.txt specifies how HMAC works.
 */

void
hmac_init(struct hmac_ctx *ctx,
    const struct hash_desc *h,
    const u_char *key, size_t key_len)
{
    int k;

    ctx->h = h;
    ctx->hmac_digest_len = h->hash_digest_len;

    /* Prepare the two pads for the HMAC */

    memset(ctx->buf1, '\0', HMAC_BUFSIZE);

    if (key_len <= HMAC_BUFSIZE)
    {
	memcpy(ctx->buf1, key, key_len);
    }
    else
    {
	h->hash_init(&ctx->hash_ctx);
	h->hash_update(&ctx->hash_ctx, key, key_len);
	h->hash_final(ctx->buf1, &ctx->hash_ctx);
    }

    memcpy(ctx->buf2, ctx->buf1, HMAC_BUFSIZE);

    for (k = 0; k < HMAC_BUFSIZE; k++)
    {
	ctx->buf1[k] ^= HMAC_IPAD;
	ctx->buf2[k] ^= HMAC_OPAD;
    }

    hmac_reinit(ctx);
}

void
hmac_reinit(struct hmac_ctx *ctx)
{
    ctx->h->hash_init(&ctx->hash_ctx);
    ctx->h->hash_update(&ctx->hash_ctx, ctx->buf1, HMAC_BUFSIZE);
}

void
hmac_update(struct hmac_ctx *ctx,
    const u_char *data, size_t data_len)
{
    ctx->h->hash_update(&ctx->hash_ctx, data, data_len);
}

void
hmac_final(u_char *output, struct hmac_ctx *ctx)
{
    const struct hash_desc *h = ctx->h;

    h->hash_final(output, &ctx->hash_ctx);

    h->hash_init(&ctx->hash_ctx);
    h->hash_update(&ctx->hash_ctx, ctx->buf2, HMAC_BUFSIZE);
    h->hash_update(&ctx->hash_ctx, output, h->hash_digest_len);
    h->hash_final(output, &ctx->hash_ctx);
}
