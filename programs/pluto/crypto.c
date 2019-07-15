/* crypto interfaces
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2003-2008 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
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
#include "defs.h"
#include "id.h"
#include "pluto/state.h"
#include "log.h"
#include "md5.h"
#include "sha1.h"
#include "pluto/crypto.h" /* requires sha1.h and md5.h */
#include "alg_info.h"
#include "pluto/ike_alg.h"

#include "tpm/tpm.h"

#include "oswcrypto.h"

#ifdef HAVE_LIBNSS
# include "pem.h"
#endif

#ifdef USE_1DES
static void do_des(u_int8_t *buf, size_t buf_len, u_int8_t *key, size_t key_size, u_int8_t *iv, bool enc);

static struct ike_encr_desc crypto_encrypter_des =
{
    common: {name: "oakley_des_cbc",
	     officname:         "1des",
             algo_type:         IKEv2_TRANS_TYPE_ENCR,
             algo_id:           OAKLEY_DES_CBC,
	     algo_v2id:         IKEv2_ENCR_DES,
             algo_next:         NULL, },
    enc_ctxsize:        sizeof(des_key_schedule),
    enc_blocksize:      DES_CBC_BLOCK_SIZE,
    keydeflen:  DES_CBC_BLOCK_SIZE * BITS_PER_BYTE,
    keyminlen:  DES_CBC_BLOCK_SIZE * BITS_PER_BYTE,
    keymaxlen:  DES_CBC_BLOCK_SIZE * BITS_PER_BYTE,
    do_crypt:   do_des,
};
#endif

#ifdef USE_3DES
static void do_3des(u_int8_t *buf, size_t buf_len, u_int8_t *key, size_t key_size, u_int8_t *iv, bool enc);
static struct ike_encr_desc crypto_encrypter_3des =
{
    common: {name: "oakley_3des_cbc",
	     officname:         "3des",
	     algo_type: 	IKEv2_TRANS_TYPE_ENCR,
	     algo_id:   	OAKLEY_3DES_CBC,
	     algo_v2id:         IKEv2_ENCR_3DES,
	     algo_next: 	NULL, },
    enc_ctxsize: 	sizeof(des_key_schedule) * 3,
    enc_blocksize: 	DES_CBC_BLOCK_SIZE,
    keydeflen: 	DES_CBC_BLOCK_SIZE * 3 * BITS_PER_BYTE,
    keyminlen: 	DES_CBC_BLOCK_SIZE * 3 * BITS_PER_BYTE,
    keymaxlen: 	DES_CBC_BLOCK_SIZE * 3 * BITS_PER_BYTE,
    do_crypt: 	do_3des,
};
#endif

static struct ike_integ_desc crypto_hasher_md5 =
{
    common: {name: "oakley_md5",
	     officname: "md5",
	     algo_type: IKEv2_TRANS_TYPE_INTEG,
	     algo_id:   OAKLEY_MD5,
	     algo_v2id: IKEv2_PRF_HMAC_MD5,
	     algo_next: NULL, },
    hash_ctx_size: sizeof(MD5_CTX),
    hash_key_size:   MD5_DIGEST_SIZE,
    hash_digest_len: MD5_DIGEST_SIZE,
    hash_integ_len: 0,				/*Not applicable*/
    hash_init: (void (*)(void *)) osMD5Init,
    hash_update: (void (*)(void *, const u_int8_t *, size_t)) osMD5Update,
    hash_final: (void (*)(u_char *, void *)) osMD5Final,
};

static struct ike_integ_desc crypto_integ_md5 =
{
    common: {name: "oakley_md5",
	     officname: "md5",
	     algo_type: IKEv2_TRANS_TYPE_INTEG,
	     algo_id:   OAKLEY_MD5,
	     algo_v2id: IKEv2_AUTH_HMAC_MD5_96,
	     algo_next: NULL, },
    hash_ctx_size: sizeof(MD5_CTX),
    hash_key_size:   MD5_DIGEST_SIZE,
    hash_digest_len: MD5_DIGEST_SIZE,
    hash_integ_len: MD5_DIGEST_SIZE_96,
    hash_init: (void (*)(void *)) osMD5Init,
    hash_update: (void (*)(void *, const u_int8_t *, size_t)) osMD5Update,
    hash_final: (void (*)(u_char *, void *)) osMD5Final,
};

static struct ike_integ_desc crypto_hasher_sha1 =
{
    common: {name: "oakley_sha",
	     officname: "sha1",
	     algo_type: IKEv2_TRANS_TYPE_INTEG,
	     algo_id:   OAKLEY_SHA,
	     algo_v2id: IKEv2_PRF_HMAC_SHA1,
	     algo_next: NULL, },
    hash_ctx_size: sizeof(SHA1_CTX),
    hash_key_size:   SHA1_DIGEST_SIZE,
    hash_digest_len: SHA1_DIGEST_SIZE,
    hash_integ_len: 0,                          /*Not applicable*/
    hash_init: (void (*)(void *)) SHA1Init,
    hash_update: (void (*)(void *, const u_int8_t *, size_t)) SHA1Update,
    hash_final: (void (*)(u_char *, void *)) SHA1Final,
};

static struct ike_integ_desc crypto_integ_sha1 =
{
    common: {name: "oakley_sha",
	     officname: "sha1",
	     algo_type: IKEv2_TRANS_TYPE_INTEG,
	     algo_id:   OAKLEY_SHA,
	     algo_v2id: IKEv2_AUTH_HMAC_SHA1_96,
	     algo_next: NULL, },
    hash_ctx_size: sizeof(SHA1_CTX),
    hash_key_size:   SHA1_DIGEST_SIZE,
    hash_digest_len: SHA1_DIGEST_SIZE,
    hash_integ_len: SHA1_DIGEST_SIZE_96,
    hash_init: (void (*)(void *)) SHA1Init,
    hash_update: (void (*)(void *, const u_int8_t *, size_t)) SHA1Update,
    hash_final: (void (*)(u_char *, void *)) SHA1Final,
};

void
init_crypto(void)
{
    init_crypto_groups();
	{
#ifdef USE_TWOFISH
	    {
		extern int ike_alg_twofish_init(void);
		ike_alg_twofish_init();
	    }
#endif

#ifdef USE_SERPENT
	    {
		extern int ike_alg_serpent_init(void);
		ike_alg_serpent_init();
	    }
#endif

#ifdef USE_AES
	    {
		extern int ike_alg_aes_init(void);
		ike_alg_aes_init();
	    }
#endif

#ifdef USE_3DES
	    {
		ike_alg_add((struct ike_alg *) &crypto_encrypter_3des, FALSE);
	    }
#endif

#ifdef USE_BLOWFISH
	    {
		extern int ike_alg_blowfish_init(void);
		ike_alg_blowfish_init();
	    }
#endif

#ifdef USE_1DES
/*#warning YOUR PLUTO IS INSECURE, IT HAS 1DES. DO NOT USE IT. */
	    {
		ike_alg_add((struct ike_alg *) &crypto_encrypter_des);
	    }
#endif

#ifdef USE_SHA2
	    {
		extern int ike_alg_sha2_init(void);
		ike_alg_sha2_init();
	    }
#endif

	    ike_alg_add((struct ike_alg *) &crypto_hasher_sha1, FALSE);
	    ike_alg_add((struct ike_alg *) &crypto_integ_sha1,  FALSE);
	    ike_alg_add((struct ike_alg *) &crypto_hasher_md5,  FALSE);
	    ike_alg_add((struct ike_alg *) &crypto_integ_md5,   FALSE);
	}
}

/* Encryption Routines
 *
 * Each uses and updates the state object's st_new_iv.
 * This must already be initialized.
 */

#ifdef USE_1DES
/* encrypt or decrypt part of an IKE message using DES
 * See RFC 2409 "IKE" Appendix B
 */
static void
do_des(u_int8_t *buf, size_t buf_len, u_int8_t *key, size_t key_size, u_int8_t *iv, bool enc)
{
    des_key_schedule ks;

    oswcrypto.des_set_key((des_cblock *)key, ks);

    passert(key_size >= DES_CBC_BLOCK_SIZE);
    key_size = DES_CBC_BLOCK_SIZE;     /* truncate */

    oswcrypto.des_ncbc_encrypt((des_cblock *)buf, (des_cblock *)buf, buf_len,
			 ks, (des_cblock *)iv, enc);
}
#endif

#ifdef USE_3DES
/* encrypt or decrypt part of an IKE message using 3DES
 * See RFC 2409 "IKE" Appendix B
 */
static void
do_3des(u_int8_t *buf, size_t buf_len
	, u_int8_t *key, size_t key_size, u_int8_t *iv, bool enc)
{
    passert(key != NULL);

    des_key_schedule ks[3];

    passert(key_size==(DES_CBC_BLOCK_SIZE * 3));

    (void) oswcrypto.des_set_key((des_cblock *)key + 0, ks[0]);
    (void) oswcrypto.des_set_key((des_cblock *)key + 1, ks[1]);
    (void) oswcrypto.des_set_key((des_cblock *)key + 2, ks[2]);

    oswcrypto.des_ede3_cbc_encrypt((des_cblock *)buf, (des_cblock *)buf, buf_len,
                         ks[0], ks[1], ks[2],
                         (des_cblock *)iv, enc);
}
#endif

/* hash and prf routines */
/*==========================================================
 *
 *  ike_alg linked list
 *
 *==========================================================
 */
struct ike_integ_desc *crypto_get_hasher(enum ikev2_trans_type_integ alg)
{
    return ike_alg_get_integ(alg);
}
struct ike_encr_desc *crypto_get_encrypter(enum ikev2_trans_type_encr alg)
{
    return ike_alg_get_encr(alg);
}

void
crypto_cbc_encrypt(const struct ike_encr_desc *e, bool enc
		   , u_int8_t *buf, size_t size, struct state *st)
{
    passert(st->st_new_iv_len >= e->enc_blocksize);
    st->st_new_iv_len = e->enc_blocksize;	/* truncate */

#if 0
    DBG(DBG_CRYPT
	, DBG_log("encrypting buf=%p size=%d keyptr: %p keysize: %d, iv: %p enc: %d"
		  , buf, size, st->st_enc_key.ptr
		  , st->st_enc_key.len, st->st_new_iv, enc));
#endif

    e->do_crypt(buf, size, st->st_enc_key.ptr
		, st->st_enc_key.len, st->st_new_iv, enc);

    /*
      e->set_key(&ctx, st->st_enc_key.ptr, st->st_enc_key.len);
      e->cbc_crypt(&ctx, buf, size, st->st_new_iv, enc);
    */
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */

