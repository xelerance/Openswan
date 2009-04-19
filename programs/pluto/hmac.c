/* hmac interface for pluto ciphers.
 * 
 * Copyright (C) 2006  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
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
#include <openswan.h>

#include "constants.h"
#include "defs.h"
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "alg_info.h"
#include "ike_alg.h"
#include "oswlog.h"

#ifdef HAVE_LIBNSS
# include <nss.h>
# include <pkcs11t.h>
# include <pk11pub.h>
# include <prlog.h>
# include <prmem.h>
# include <pk11priv.h>
# include <secport.h>
# include "oswconf.h"
# include "oswlog.h"
#endif


/* HMAC package
 * rfc2104.txt specifies how HMAC works.
 */

#ifdef HAVE_LIBNSS
static CK_MECHANISM_TYPE nss_hash_mech(const struct hash_desc *hasher);
static SECOidTag nss_hash_oid(const struct hash_desc *hasher);
#endif

void
hmac_init(struct hmac_ctx *ctx,
    const struct hash_desc *h,
    const u_char *key, size_t key_len)
{
#ifndef HAVE_LIBNSS
    int k;
#endif
    DBG(DBG_CRYPT, DBG_log("hmac_init() start"));
    ctx->h = h;
    ctx->hmac_digest_len = h->hash_digest_len;

#ifdef HAVE_LIBNSS
    SECStatus status;
    PK11SymKey *symkey=NULL; 
    PK11SymKey *tkey1=NULL;
    unsigned int klen;
    chunk_t hmac_opad, hmac_ipad, hmac_pad;
    /* empty parameters for the cryptographic context */
    SECItem noparams = { siBuffer, NULL, 0 };

    memcpy(&symkey, key, key_len);
    nss_symkey_log(symkey, "hmac symkey");

    klen =  PK11_GetKeyLength(symkey);

    hmac_opad = hmac_pads(HMAC_OPAD,HMAC_BUFSIZE);
    hmac_ipad = hmac_pads(HMAC_IPAD,HMAC_BUFSIZE);
    hmac_pad  = hmac_pads(0x00,HMAC_BUFSIZE-h->hash_digest_len);

    if(klen > HMAC_BUFSIZE) 
    {
	DBG(DBG_CRYPT, DBG_log("NSS: key len is greater than block size"));
	tkey1 = PK11_Derive(symkey, nss_key_derivation_mech(h), NULL, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
	DBG(DBG_CRYPT, DBG_log("NSS: created digest of key"));
	nss_symkey_log(tkey1, "hmac symkey digested");
    }
    else
    {
	DBG(DBG_CRYPT, DBG_log("NSS: key len is smaller than block size"));
	tkey1 = symkey; 
    }

    PK11SymKey *tkey2 = pk11_derive_wrapper_osw(tkey1, CKM_CONCATENATE_BASE_AND_DATA
				, hmac_pad,CKM_XOR_BASE_AND_DATA, CKA_DERIVE, HMAC_BUFSIZE);

    PR_ASSERT(tkey2!=NULL);

    ctx->ikey = pk11_derive_wrapper_osw(tkey2, CKM_XOR_BASE_AND_DATA
					, hmac_ipad,nss_hash_mech(h), CKA_DIGEST, 0);

    PR_ASSERT(ctx->ikey !=NULL);
    nss_symkey_log(ctx->ikey, "ctx ikey");

    ctx->okey = pk11_derive_wrapper_osw(tkey2, CKM_XOR_BASE_AND_DATA
					, hmac_opad,nss_hash_mech(h), CKA_DIGEST, 0);

    PR_ASSERT(ctx->okey !=NULL);
    nss_symkey_log(ctx->okey, "ctx okey");

    if(tkey1!=symkey) {
	PK11_FreeSymKey(tkey1);
    } 
    PK11_FreeSymKey(tkey2);

    freeanychunk(hmac_opad);
    freeanychunk(hmac_ipad);
    freeanychunk(hmac_pad);
    ctx->ctx_nss = PK11_CreateDigestContext(nss_hash_oid(h));
    PR_ASSERT(ctx->ctx_nss!=NULL);
    DBG(DBG_CRYPT, DBG_log("NSS: context created for hmac (doing it the hash way)"));

    status=PK11_DigestBegin(ctx->ctx_nss);
    PR_ASSERT(status==SECSuccess);
    DBG(DBG_CRYPT, DBG_log("NSS: Digest begin succeeded"));

    status=PK11_DigestKey(ctx->ctx_nss, ctx->ikey);
    PR_ASSERT(status==SECSuccess);

    DBG(DBG_CRYPT, DBG_log("NSS: digested inner key"));

#else

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
#endif
}

#ifndef HAVE_LIBNSS
void
hmac_reinit(struct hmac_ctx *ctx)
{
    ctx->h->hash_init(&ctx->hash_ctx);
    ctx->h->hash_update(&ctx->hash_ctx, ctx->buf1, HMAC_BUFSIZE);
}
#endif

void
hmac_update(struct hmac_ctx *ctx,
    const u_char *data, size_t data_len)
{
#ifdef HAVE_LIBNSS
    DBG(DBG_CRYPT, DBG_log("NSS: hmac update start"));
    if(data_len > 0) {
	SECStatus status = PK11_DigestOp(ctx->ctx_nss, data, data_len);
	PR_ASSERT(status == SECSuccess);
    }
	DBG(DBG_CRYPT, DBG_log("NSS: hmac update end"));
#else
    ctx->h->hash_update(&ctx->hash_ctx, data, data_len);
#endif
}

void
hmac_final(u_char *output, struct hmac_ctx *ctx)
{
#ifndef HAVE_LIBNSS
    const struct hash_desc *h = ctx->h;

    h->hash_final(output, &ctx->hash_ctx);

    h->hash_init(&ctx->hash_ctx);
    h->hash_update(&ctx->hash_ctx, ctx->buf2, HMAC_BUFSIZE);
    h->hash_update(&ctx->hash_ctx, output, h->hash_digest_len);
    h->hash_final(output, &ctx->hash_ctx);
#else
    DBG(DBG_CRYPT, DBG_log("NSS: hmac final start"));
    unsigned int outlen = 0;
    SECStatus status = PK11_DigestFinal(ctx->ctx_nss, output, &outlen, ctx->hmac_digest_len);
    PR_ASSERT(status == SECSuccess);
    PR_ASSERT(outlen == ctx->hmac_digest_len);
    PK11_DestroyContext(ctx->ctx_nss, PR_TRUE);
    ctx->ctx_nss = NULL;  

    ctx->ctx_nss = PK11_CreateDigestContext(nss_hash_oid(ctx->h));
    PR_ASSERT(ctx->ctx_nss!=NULL);
    DBG(DBG_CRYPT, DBG_log("NSS: hmac final context creation"));

    status=PK11_DigestBegin(ctx->ctx_nss);
    PR_ASSERT(status==SECSuccess);
    DBG(DBG_CRYPT, DBG_log("NSS: hmac second final digest begin"));

    status=PK11_DigestKey(ctx->ctx_nss, ctx->okey);
    PR_ASSERT(status==SECSuccess);

    DBG(DBG_CRYPT, DBG_log("NSS: digested outer key"));
    status = PK11_DigestOp(ctx->ctx_nss, output, outlen);
    PR_ASSERT(status == SECSuccess);

    DBG(DBG_CRYPT, DBG_log("NSS: digested inner data"));
    status = PK11_DigestFinal(ctx->ctx_nss, output, &outlen, ctx->hmac_digest_len);
    PR_ASSERT(status == SECSuccess);
    PR_ASSERT(outlen == ctx->hmac_digest_len);
    PK11_DestroyContext(ctx->ctx_nss, PR_TRUE);

    PK11_FreeSymKey(ctx->ikey);
    PK11_FreeSymKey(ctx->okey);
    DBG(DBG_CRYPT, DBG_log("NSS: hmac final end"));
#endif
}

#ifdef HAVE_LIBNSS
static SECOidTag nss_hash_oid(const struct hash_desc *hasher)
{
    SECOidTag mechanism;

    switch(hasher->common.algo_id) {
	case OAKLEY_MD5:   mechanism = SEC_OID_MD5; break;
	case OAKLEY_SHA1:  mechanism = SEC_OID_SHA1; break;
	case OAKLEY_SHA2_256:  mechanism = SEC_OID_SHA256; break;
	case OAKLEY_SHA2_384:  mechanism = SEC_OID_SHA384; break;
	case OAKLEY_SHA2_512:  mechanism = SEC_OID_SHA512; break;
	/*should not reach here*/
	default: DBG(DBG_CRYPT, DBG_log("NSS: key derivation mechanism not supported")); break; 
    }
    return mechanism;
}

static CK_MECHANISM_TYPE nss_hash_mech(const struct hash_desc *hasher)
{
    CK_MECHANISM_TYPE mechanism;

    switch(hasher->common.algo_id) {
	case OAKLEY_MD5:   mechanism = CKM_MD5; break;
	case OAKLEY_SHA1:  mechanism = CKM_SHA_1; break;
	case OAKLEY_SHA2_256:  mechanism = CKM_SHA256; break;
	case OAKLEY_SHA2_384:  mechanism = CKM_SHA384; break;
	case OAKLEY_SHA2_512:  mechanism = CKM_SHA512; break;
	/*should not reach here*/
	default:  DBG(DBG_CRYPT, DBG_log("NSS: key derivation mechanism not supported")); break;
    }
    return mechanism;
}

PK11SymKey *pk11_derive_wrapper_osw(PK11SymKey *base, CK_MECHANISM_TYPE mechanism
                                           , chunk_t data, CK_MECHANISM_TYPE target
                                           , CK_ATTRIBUTE_TYPE operation, int keySize)
{
    CK_KEY_DERIVATION_STRING_DATA string;
    SECItem param;

    string.pData = data.ptr;
    string.ulLen = data.len;
    param.data = (unsigned char*)&string;
    param.len = sizeof(string);

    return PK11_Derive(base, mechanism, &param, target, operation, keySize);
}

CK_MECHANISM_TYPE nss_key_derivation_mech(const struct hash_desc *hasher)
{
    CK_MECHANISM_TYPE mechanism;

    switch(hasher->common.algo_id) {
	case OAKLEY_MD5:   mechanism = CKM_MD5_KEY_DERIVATION; break;
	case OAKLEY_SHA1:  mechanism = CKM_SHA1_KEY_DERIVATION; break;
	case OAKLEY_SHA2_256:  mechanism = CKM_SHA256_KEY_DERIVATION; break;
	case OAKLEY_SHA2_384:  mechanism = CKM_SHA384_KEY_DERIVATION; break;
	case OAKLEY_SHA2_512:  mechanism = CKM_SHA512_KEY_DERIVATION; break;
	default:  DBG(DBG_CRYPT, DBG_log("NSS: key derivation mechanism not supported")); break; /*should not reach here*/
    }
    return mechanism;
}

chunk_t hmac_pads(u_char val, unsigned int len)
{
    chunk_t ret;
    unsigned int i; 

    ret.len = len;
    ret.ptr = alloc_bytes(ret.len, "hmac_pad");

    for(i=0;i<len;i++){
	ret.ptr[i]=val;
    }

    return ret;
}

void nss_symkey_log(PK11SymKey *key, char *msg)
{
    if(key!=NULL) {
	DBG(DBG_CRYPT, DBG_log("computed key %s with length =%d", msg
				,PK11_GetKeyLength(key)));
    }
    else {
	DBG_log("NULL key %s", msg);
    }

    if(!PK11_IsFIPS()) {
	if(key!=NULL) {
	   SECStatus status = PK11_ExtractKeyValue(key);
	   PR_ASSERT(status==SECSuccess);
	   SECItem *keydata = PK11_GetKeyData(key);

	   DBG(DBG_CRYPT, DBG_dump("value: ", keydata->data
					, keydata->len));

	//SECITEM_FreeItem(keydata, PR_TRUE);
	}
     }
}
#endif

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
