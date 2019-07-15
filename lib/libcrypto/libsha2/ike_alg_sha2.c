/* headers for SHA2 routines
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
 *
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
#include <openswan.h>

#include "constants.h"
#include "pluto/defs.h"
#include "oswlog.h"
#include "sha2.h"
#include "alg_info.h"
#include "pluto/ike_alg.h"

#ifdef HAVE_LIBNSS
# include <pk11pub.h>
# include "oswlog.h"
#endif

static void sha256_hash_final(u_char *hash, sha256_context *ctx)
{
#ifdef HAVE_LIBNSS
	unsigned int len;
	SECStatus s;
	s = PK11_DigestFinal(ctx->ctx_nss, hash, &len, SHA2_256_DIGEST_SIZE);
	PR_ASSERT(len==SHA2_256_DIGEST_SIZE);
	PR_ASSERT(s==SECSuccess);
	PK11_DestroyContext(ctx->ctx_nss, PR_TRUE);
	DBG(DBG_CRYPT, DBG_log("NSS SHA 256 hash final : end"));
#else
	sha256_final(ctx);
	memcpy(hash, &ctx->sha_out[0], SHA2_256_DIGEST_SIZE);
#endif
}
static void sha512_hash_final(u_char *hash, sha512_context *ctx)
{
#ifdef HAVE_LIBNSS
	unsigned int len;
	SECStatus s;
	s = PK11_DigestFinal(ctx->ctx_nss, hash, &len, SHA2_512_DIGEST_SIZE);
	PR_ASSERT(len==SHA2_512_DIGEST_SIZE);
	PR_ASSERT(s==SECSuccess);
	PK11_DestroyContext(ctx->ctx_nss, PR_TRUE);
	DBG(DBG_CRYPT, DBG_log("NSS SHA 512 hash final : end"));
#else
	sha512_final(ctx);
	memcpy(hash, &ctx->sha_out[0], SHA2_512_DIGEST_SIZE);
#endif
}
struct ike_prf_desc hash_desc_sha2_256 = {
	common:{officname:  "prfsha256",
		algo_type: IKEv2_TRANS_TYPE_PRF,
		algo_id:   OAKLEY_SHA2_256,
		algo_v2id: IKEv2_PRF_HMAC_SHA2_256,
		algo_next: NULL, },
	hash_ctx_size: sizeof(sha256_context),
	hash_key_size: SHA2_256_DIGEST_SIZE,
	hash_digest_len: SHA2_256_DIGEST_SIZE,
	hash_integ_len: 0,	/*Not applicable*/
	hash_init: (void (*)(void *))sha256_init,
	hash_update: (void (*)(void *, const u_char *, size_t ))sha256_write,
	hash_final:(void (*)(u_char *, void *))sha256_hash_final,
};

struct ike_prf_desc hash_desc_sha2_512 = {
	common:{officname:  "prfsha512",
		algo_type: IKEv2_TRANS_TYPE_PRF,
		algo_id:   OAKLEY_SHA2_512,
		algo_v2id: IKEv2_PRF_HMAC_SHA2_512,
		algo_next: NULL, },
	hash_ctx_size: sizeof(sha512_context),
	hash_key_size: SHA2_512_DIGEST_SIZE,
	hash_digest_len: SHA2_512_DIGEST_SIZE,
	hash_integ_len: 0,	/*Not applicable*/
	hash_init: (void (*)(void *))sha512_init,
	hash_update: (void (*)(void *, const u_char *, size_t ))sha512_write,
	hash_final:(void (*)(u_char *, void *))sha512_hash_final,
};

struct ike_integ_desc integ_desc_sha2_256 = {
        common:{officname:  "sha256",
		algo_type: IKEv2_TRANS_TYPE_INTEG,
                algo_id:   OAKLEY_SHA2_256,
                algo_v2id: IKEv2_AUTH_HMAC_SHA2_256_128,
                algo_next: NULL, },
        hash_ctx_size: sizeof(sha256_context),
        hash_key_size: SHA2_256_DIGEST_SIZE,
        hash_digest_len: SHA2_256_DIGEST_SIZE,
        hash_integ_len: SHA2_256_DIGEST_SIZE/2,
        hash_init: (void (*)(void *))sha256_init,
        hash_update: (void (*)(void *, const u_char *, size_t ))sha256_write,
        hash_final:(void (*)(u_char *, void *))sha256_hash_final,
};

struct ike_integ_desc integ_desc_sha2_512 = {
	common:{officname: "sha512",
		algo_type: IKEv2_TRANS_TYPE_INTEG,
		algo_id:   OAKLEY_SHA2_512,
                algo_v2id: IKEv2_AUTH_HMAC_SHA2_512_256,
		algo_next: NULL, },
	hash_ctx_size: sizeof(sha512_context),
	hash_key_size: 0,
	hash_digest_len: SHA2_512_DIGEST_SIZE,
	hash_integ_len: 0,      /*Not applicable*/
	hash_init: (void (*)(void *))sha512_init,
	hash_update: (void (*)(void *, const u_char *, size_t ))sha512_write,
	hash_final:(void (*)(u_char *, void *))sha512_hash_final,
};

int ike_alg_sha2_init(void)
{
	int ret;
	ret = ike_alg_register_integ(&integ_desc_sha2_512);
	if (!ret){
	    ret = ike_alg_register_prf(&hash_desc_sha2_512);
        }

	if (!ret){
	    ret = ike_alg_register_integ(&integ_desc_sha2_256);
        }
	if (!ret){
	    ret = ike_alg_register_prf(&hash_desc_sha2_256);
        }

	return ret;
}
/*
IKE_ALG_INIT_NAME: ike_alg_sha2_init
*/
