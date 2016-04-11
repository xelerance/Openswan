/*
 * Cryptographic helper function - calculate DH
 * Copyright (C) 2007-2008 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009-2010 Paul Wouters <paul@xelerance.com>
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
 * This code was developed with the support of IXIA communications.
 *
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
#include "crypto.h"
#include "rnd.h"
#include "state.h"
#include "pluto_crypt.h"
#include "oswlog.h"
#include "log.h"
#include "timer.h"
#include "ike_alg.h"
#include "id.h"
#include "secrets.h"
#include "keys.h"
#include "ikev2_prfplus.h"
#include "oswcrypto.h"

#ifdef HAVE_LIBNSS
# include <nss.h>
# include <pk11pub.h>
# include <keyhi.h>
# include "oswconf.h"

/* #define PK11_Derive(base, mechanism, param, target, operation, keysize) \
 *	PK11_Derive_osw(base, mechanism, param, target, operation, keysize)
 */

static PK11SymKey *pk11_extract_derive_wrapper_osw(PK11SymKey *base, CK_EXTRACT_PARAMS bs
		, CK_MECHANISM_TYPE target , CK_ATTRIBUTE_TYPE operation, int keySize)
{
      SECItem param;
      param.data = (unsigned char*)&bs;
      param.len = sizeof (bs);

    return PK11_Derive_osw(base, CKM_EXTRACT_KEY_FROM_KEY, &param, target, operation, keySize);
}
/*
static CK_MECHANISM_TYPE nss_hmac_mech(const struct hash_desc *hasher)
{
    CK_MECHANISM_TYPE mechanism;

    switch(hasher->common.algo_id) {
	case OAKLEY_MD5:   mechanism = CKM_MD5_HMAC; break;
	case OAKLEY_SHA1:  mechanism = CKM_SHA_1_HMAC; break;
	case OAKLEY_SHA2_256:  mechanism = CKM_SHA256_HMAC; break;
	case OAKLEY_SHA2_384:  mechanism = CKM_SHA384_HMAC; break;
	case OAKLEY_SHA2_512:  mechanism = CKM_SHA512_HMAC; break;
	default: loglog(RC_LOG_SERIOUS,"NSS: undefined hmac mechanism"); break;
    }
    return mechanism;
}
*/

static CK_MECHANISM_TYPE nss_encryption_mech(const struct encrypt_desc *encrypter)
{
CK_MECHANISM_TYPE mechanism=0x80000000;

    switch(encrypter->common.algo_id){
    case OAKLEY_3DES_CBC:   mechanism = CKM_DES3_CBC; break;
    case OAKLEY_AES_CBC:  mechanism = CKM_AES_CBC; break;
    default: loglog(RC_LOG_SERIOUS,"NSS: Unsupported encryption mechanism"); break; /*should not reach here*/
    }
return mechanism;
}
#endif

/** Compute DH shared secret from our local secret and the peer's public value.
 * We make the leap that the length should be that of the group
 * (see quoted passage at start of ACCEPT_KE).
 */
#ifdef HAVE_LIBNSS
static bool
calc_dh_shared(chunk_t *shared, const chunk_t g
              , chunk_t secret
              , const struct oakley_group_desc *group
               , chunk_t pubk)
{
    struct timeval tv0, tv1;
    unsigned long tv_diff;
    SECKEYPublicKey   *remote_pubk, *local_pubk;
    SECKEYPrivateKey *privk;
    SECItem nss_g;
    PK11SymKey *dhshared;
    PRArenaPool *arena;
    SECStatus status;
    unsigned int dhshared_len;

    memcpy(&local_pubk,pubk.ptr,pubk.len);
    memcpy(&privk,secret.ptr,secret.len);

    DBG(DBG_CRYPT, DBG_log("Started DH shared-secret computation in NSS:\n"));

    gettimeofday(&tv0, NULL);

    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    PR_ASSERT(arena!=NULL);


    remote_pubk = (SECKEYPublicKey *) PORT_ArenaZAlloc (arena, sizeof (SECKEYPublicKey));

    remote_pubk->arena = arena;
    remote_pubk->keyType = dhKey;
    remote_pubk->pkcs11Slot = NULL;
    remote_pubk->pkcs11ID = CK_INVALID_HANDLE;

    nss_g.data = g.ptr;
    nss_g.len = (unsigned int)g.len;
    nss_g.type = siBuffer;

    status = SECITEM_CopyItem(remote_pubk->arena, &remote_pubk->u.dh.prime, &local_pubk->u.dh.prime);
    PR_ASSERT(status==SECSuccess);

    status = SECITEM_CopyItem(remote_pubk->arena, &remote_pubk->u.dh.base, &local_pubk->u.dh.base);
    PR_ASSERT(status==SECSuccess);

    status = SECITEM_CopyItem(remote_pubk->arena, &remote_pubk->u.dh.publicValue, &nss_g);
    PR_ASSERT(status==SECSuccess);


    dhshared=PK11_PubDerive(privk,remote_pubk,PR_FALSE, NULL, NULL
                         , CKM_DH_PKCS_DERIVE, CKM_CONCATENATE_DATA_AND_BASE
                         , CKA_DERIVE, group->bytes
                         , osw_return_nss_password_file_info());
    if(dhshared == NULL) {
        openswan_log("PK11_PubDerive failed, maybe all zero g^x");
        return FALSE;
    }

    dhshared_len = PK11_GetKeyLength(dhshared);
    if( group->bytes > dhshared_len ) {
	DBG(DBG_CRYPT, DBG_log("Dropped %lu leading zeros", (long)group->bytes-dhshared_len));
	chunk_t zeros;
	PK11SymKey *newdhshared = NULL;
	CK_KEY_DERIVATION_STRING_DATA string_params;
	SECItem  params;

	zeros = hmac_pads(0x00, group->bytes-dhshared_len);
	params.data = (unsigned char *)&string_params;
	params.len = sizeof(string_params);
	string_params.pData = zeros.ptr;
	string_params.ulLen = zeros.len;

	newdhshared = PK11_Derive(dhshared, CKM_CONCATENATE_DATA_AND_BASE, &params, CKM_CONCATENATE_DATA_AND_BASE, CKA_DERIVE, 0);
	PR_ASSERT(newdhshared!=NULL);  /* XXX here? */
	PK11_FreeSymKey(dhshared);
	dhshared = newdhshared;
	freeanychunk(zeros);
    } else {
	DBG(DBG_CRYPT, DBG_log("Dropped no leading zeros %d", dhshared_len));
    }

    /* nss_symkey_log(dhshared, "dhshared"); */

    shared->len=sizeof(PK11SymKey *);
    shared->ptr = alloc_bytes(shared->len, "calculated shared secret");
    memcpy(shared->ptr, &dhshared,shared->len);

    gettimeofday(&tv1, NULL);
    tv_diff=(tv1.tv_sec  - tv0.tv_sec) * 1000000 + (tv1.tv_usec - tv0.tv_usec);
    DBG(DBG_CRYPT, DBG_log("calc_dh_shared(): time elapsed (%s): %ld usec"
               , enum_show(&oakley_group_names, group->group)
               , tv_diff);
       );

    SECKEY_DestroyPublicKey(remote_pubk);

#if 0
    /*
     * note,  a 533 MHz Xscale will exceed this test,  and that is a fast
     * processor by embedded standards.  Disabling for now so we don't
     * pollute the logs with nasty warnings that are actually perfectly
     * normal operation.
     */

    /* if took more than 200 msec ... */
    if (tv_diff > 200000) {
       loglog(RC_LOG_SERIOUS, "WARNING: calc_dh_shared(): for %s took "
                       "%ld usec"
               , enum_show(&oakley_group_names, group->group)
               , tv_diff);
    }
#endif

    DBG_cond_dump_chunk(DBG_CRYPT, "DH shared-secret pointer:\n", *shared);
    return TRUE;

}
#else
static bool
calc_dh_shared(chunk_t *shared, const chunk_t g
	       , const MP_INT *sec
	       , const struct oakley_group_desc *group)
{
    MP_INT mp_g, mp_shared;
    struct timeval tv0, tv1;
    unsigned long tv_diff;

    gettimeofday(&tv0, NULL);
    n_to_mpz(&mp_g, g.ptr, g.len);
    mpz_init(&mp_shared);
    mpz_powm(&mp_shared, &mp_g, sec, group->modulus);
    mpz_clear(&mp_g);

    *shared = mpz_to_n(&mp_shared, group->bytes);
    mpz_clear(&mp_shared);

    gettimeofday(&tv1, NULL);
    tv_diff=(tv1.tv_sec  - tv0.tv_sec) * 1000000 + (tv1.tv_usec - tv0.tv_usec);
    DBG(DBG_CRYPT,
	DBG_log("calc_dh_shared(): time elapsed (%s): %ld usec"
		, enum_show(&oakley_group_names, group->group)
		, tv_diff);
       );
#if 0
    /*
     * note,  a 533 MHz Xscale will exceed this test,  and that is a fast
     * processor by embedded standards.  Disabling for now so we don't
     * pollute the logs with nasty warnings that are actually perfectly
     * normal operation.
     */

    /* if took more than 200 msec ... */
    if (tv_diff > 200000) {
	loglog(RC_LOG_SERIOUS, "WARNING: calc_dh_shared(): for %s took "
			"%ld usec"
		, enum_show(&oakley_group_names, group->group)
		, tv_diff);
    }
#endif

    DBG_cond_dump_chunk(DBG_CRYPT, "DH shared-secret:\n", *shared);
    return TRUE;
}
#endif

/* SKEYID for preshared keys.
 * See draft-ietf-ipsec-ike-01.txt 4.1
 */

#ifdef HAVE_LIBNSS
static void
skeyid_preshared(const chunk_t pss
                 , const chunk_t ni
                 , const chunk_t nr
                 , const chunk_t shared_chunk
                 , const struct hash_desc *hasher
                 , chunk_t *skeyid_chunk)
#else
static void
skeyid_preshared(const chunk_t pss
		 , const chunk_t ni
		 , const chunk_t nr
		 , const struct hash_desc *hasher
		 , chunk_t *skeyid)
#endif
{
    struct hmac_ctx ctx;

    passert(hasher != NULL);

#ifdef HAVE_LIBNSS
    chunk_t nir;
    unsigned int k;
    CK_MECHANISM_TYPE mechanism;
    u_char buf1[HMAC_BUFSIZE], buf2[HMAC_BUFSIZE];
    chunk_t buf1_chunk, buf2_chunk;
    PK11SymKey *shared, *skeyid;

    DBG(DBG_CRYPT,
        DBG_log("NSS: skeyid inputs (pss+NI+NR+shared) hasher: %s", hasher->common.name);
        DBG_dump_chunk("shared-secret: ", shared_chunk);
        DBG_dump_chunk("ni: ", ni);
        DBG_dump_chunk("nr: ", nr));

     memcpy(&shared, shared_chunk.ptr, shared_chunk.len);

    /* We need to hmac_init with the concatenation of Ni_b and Nr_b,
     * so we have to build a temporary concatentation.
     */

    nir.len = ni.len + nr.len;
    nir.ptr = alloc_bytes(nir.len, "Ni + Nr in skeyid_preshared");
    memcpy(nir.ptr, ni.ptr, ni.len);
    memcpy(nir.ptr+ ni.len, nr.ptr, nr.len);

    memset(buf1, '\0', HMAC_BUFSIZE);

    if (pss.len <= HMAC_BUFSIZE)
    {
        memcpy(buf1, pss.ptr, pss.len);
    }
    else
    {
        hasher->hash_init(&ctx.hash_ctx);
        hasher->hash_update(&ctx.hash_ctx, pss.ptr, pss.len);
        hasher->hash_final(buf1, &ctx.hash_ctx);
    }

    memcpy(buf2, buf1, HMAC_BUFSIZE);

    for (k = 0; k < HMAC_BUFSIZE; k++)
    {
        buf1[k] ^= HMAC_IPAD;
        buf2[k] ^= HMAC_OPAD;
    }

    /* pfree(nir.ptr); */

    mechanism=nss_key_derivation_mech(hasher);
    buf1_chunk.ptr=buf1;
    buf1_chunk.len=HMAC_BUFSIZE;

    buf2_chunk.ptr=buf2;
    buf2_chunk.len=HMAC_BUFSIZE;

    PK11SymKey *tkey4 = pk11_derive_wrapper_osw(shared, CKM_CONCATENATE_DATA_AND_BASE, buf1_chunk, CKM_EXTRACT_KEY_FROM_KEY, CKA_DERIVE, 0);
    /* nss_symkey_log(tkey4, "pss+ipad+shared"); */

    CK_EXTRACT_PARAMS bs=0;
    PK11SymKey *tkey5 = pk11_extract_derive_wrapper_osw(tkey4, bs, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, HMAC_BUFSIZE);
    /* nss_symkey_log(tkey5, "pss+ipad"); */

    PK11SymKey *tkey6 = pk11_derive_wrapper_osw(tkey5, CKM_CONCATENATE_BASE_AND_DATA, nir, mechanism, CKA_DERIVE, 0);
    pfree(nir.ptr);
    /* nss_symkey_log(tkey6, "pss+ipad+nir"); */

    /* PK11SymKey *tkey1 = pk11_derive_wrapper_osw(shared, CKM_CONCATENATE_DATA_AND_BASE, buf1_chunk, mechanism, CKA_DERIVE, 0); */
    PK11SymKey *tkey2 = PK11_Derive_osw(tkey6, mechanism, NULL, CKM_CONCATENATE_DATA_AND_BASE, CKA_DERIVE, 0);
    /* nss_symkey_log(tkey2, "pss : tkey2"); */

    PK11SymKey *tkey3 = pk11_derive_wrapper_osw(tkey2, CKM_CONCATENATE_DATA_AND_BASE, buf2_chunk, mechanism, CKA_DERIVE, 0);
    skeyid = PK11_Derive_osw(tkey3, mechanism, NULL, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
    /* nss_symkey_log(tkey2, "pss : tkey3"); */

    skeyid_chunk->len = sizeof(PK11SymKey *);
    skeyid_chunk->ptr = alloc_bytes(skeyid_chunk->len, "calculated skeyid(pss)");
    memcpy(skeyid_chunk->ptr, &skeyid, skeyid_chunk->len);

    PK11_FreeSymKey(tkey4);
    PK11_FreeSymKey(tkey5);
    PK11_FreeSymKey(tkey6);
    PK11_FreeSymKey(tkey2);
    PK11_FreeSymKey(tkey3);

    DBG(DBG_CRYPT,
        DBG_dump_chunk("NSS: st_skeyid in skeyid_preshared(): ", *skeyid_chunk));
#else
    DBG(DBG_CRYPT,
	DBG_log("Skey inputs (PSK+NI+NR)");
	DBG_dump_chunk("ni: ", ni);
	DBG_dump_chunk("nr: ", nr));

    hmac_init_chunk(&ctx, hasher, pss);
    hmac_update_chunk(&ctx, ni);
    hmac_update_chunk(&ctx, nr);
    hmac_final_chunk(*skeyid, "st_skeyid in skeyid_preshared()", &ctx);
    DBG(DBG_CRYPT,
	DBG_dump_chunk("keyid: ", *skeyid));
#endif
}

static void
skeyid_digisig(const chunk_t ni
	       , const chunk_t nr
	       , const chunk_t shared_chunk
	       , const struct hash_desc *hasher
	       , chunk_t *skeyid_chunk)
{
    struct hmac_ctx ctx;
    chunk_t nir;
#ifdef HAVE_LIBNSS
    unsigned int k;
    CK_MECHANISM_TYPE mechanism;
    u_char buf1[HMAC_BUFSIZE], buf2[HMAC_BUFSIZE];
    chunk_t buf1_chunk, buf2_chunk;
    PK11SymKey *shared, *skeyid;
#endif

    DBG(DBG_CRYPT,
	DBG_log("skeyid inputs (digi+NI+NR+shared) hasher: %s", hasher->common.name);
	DBG_dump_chunk("shared-secret: ", shared_chunk);
	DBG_dump_chunk("ni: ", ni);
	DBG_dump_chunk("nr: ", nr));

#ifdef HAVE_LIBNSS
    memcpy(&shared, shared_chunk.ptr, shared_chunk.len);
#endif

    /* We need to hmac_init with the concatenation of Ni_b and Nr_b,
     * so we have to build a temporary concatentation.
     */
    nir.len = ni.len + nr.len;
    nir.ptr = alloc_bytes(nir.len, "Ni + Nr in skeyid_digisig");
    memcpy(nir.ptr, ni.ptr, ni.len);
    memcpy(nir.ptr+ ni.len, nr.ptr, nr.len);
#ifndef HAVE_LIBNSS
    hmac_init_chunk(&ctx, hasher, nir);
    pfree(nir.ptr);

    hmac_update_chunk(&ctx, shared_chunk);
    hmac_final_chunk(*skeyid_chunk, "st_skeyid in skeyid_digisig()", &ctx);
    DBG(DBG_CRYPT, DBG_dump_chunk("keyid: ", *skeyid_chunk));
#else
    memset(buf1, '\0', HMAC_BUFSIZE);
    if (nir.len <= HMAC_BUFSIZE)
    {
	memcpy(buf1, nir.ptr, nir.len);
    }
    else
    {
	hasher->hash_init(&ctx.hash_ctx);
	hasher->hash_update(&ctx.hash_ctx, nir.ptr, nir.len);
	hasher->hash_final(buf1, &ctx.hash_ctx);
    }

    memcpy(buf2, buf1, HMAC_BUFSIZE);

    for (k = 0; k < HMAC_BUFSIZE; k++)
    {
	buf1[k] ^= HMAC_IPAD;
	buf2[k] ^= HMAC_OPAD;
    }

    pfree(nir.ptr);
    mechanism=nss_key_derivation_mech(hasher);
    buf1_chunk.ptr=buf1;
    buf1_chunk.len=HMAC_BUFSIZE;

    buf2_chunk.ptr=buf2;
    buf2_chunk.len=HMAC_BUFSIZE;

    PK11SymKey *tkey1 = pk11_derive_wrapper_osw(shared, CKM_CONCATENATE_DATA_AND_BASE, buf1_chunk, mechanism, CKA_DERIVE, 0);
    PK11SymKey *tkey2 = PK11_Derive_osw(tkey1, mechanism, NULL, CKM_CONCATENATE_DATA_AND_BASE, CKA_DERIVE, 0);
    PK11SymKey *tkey3 = pk11_derive_wrapper_osw(tkey2, CKM_CONCATENATE_DATA_AND_BASE, buf2_chunk, mechanism, CKA_DERIVE, 0);
    skeyid = PK11_Derive_osw(tkey3, mechanism, NULL, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);

    skeyid_chunk->len = sizeof(PK11SymKey *);
    skeyid_chunk->ptr = alloc_bytes(skeyid_chunk->len, "calculated skeyid");
    memcpy(skeyid_chunk->ptr, &skeyid, skeyid_chunk->len);

    PK11_FreeSymKey(tkey1);
    PK11_FreeSymKey(tkey2);
    PK11_FreeSymKey(tkey3);

    DBG(DBG_CRYPT, DBG_dump_chunk("NSS: digisig skeyid pointer: ", *skeyid_chunk));
#endif
}

/* Generate the SKEYID_* and new IV
 * See draft-ietf-ipsec-ike-01.txt 4.1
 */
static void
calc_skeyids_iv(struct pcr_skeyid_q *skq
		, chunk_t shared_chunk
		, const size_t keysize     /* = st->st_oakley.enckeylen/BITS_PER_BYTE; */
		, chunk_t *skeyid_chunk    /* output */
		, chunk_t *skeyid_d_chunk  /* output */
		, chunk_t *skeyid_a_chunk  /* output */
		, chunk_t *skeyid_e_chunk  /* output */
		, chunk_t *new_iv
		, chunk_t *enc_key_chunk
    )
{
    oakley_auth_t auth = skq->auth;
    oakley_hash_t hash = skq->prf_hash;
    const struct hash_desc *hasher = crypto_get_hasher(hash);
    chunk_t pss;
    chunk_t ni;
    chunk_t nr;
    chunk_t gi;
    chunk_t gr;
    chunk_t icookie;
    chunk_t rcookie;
#ifdef HAVE_LIBNSS
    PK11SymKey *shared, *skeyid, *skeyid_d, *skeyid_a, *skeyid_e, *enc_key;
    /* const struct encrypt_desc *encrypter = crypto_get_encrypter(skq->encrypt_algo);*/
    const struct encrypt_desc *encrypter = skq->encrypter;
#endif

    /* this doesn't take any memory */
    setchunk_fromwire(gi, &skq->gi, skq);
    setchunk_fromwire(gr, &skq->gr, skq);
    setchunk_fromwire(ni, &skq->ni, skq);
    setchunk_fromwire(nr, &skq->nr, skq);
    setchunk_fromwire(icookie, &skq->icookie, skq);
    setchunk_fromwire(rcookie, &skq->rcookie, skq);

#ifdef HAVE_LIBNSS
    memcpy(&shared,shared_chunk.ptr, shared_chunk.len);
#endif

    /* Generate the SKEYID */
    switch (auth)
    {
	case OAKLEY_PRESHARED_KEY:
#ifdef HAVE_LIBNSS
	    setchunk_fromwire(pss,    &skq->pss, skq);
	    skeyid_preshared(pss, ni, nr, shared_chunk, hasher, skeyid_chunk);
#else
	    setchunk_fromwire(pss,    &skq->pss, skq);
	    skeyid_preshared(pss, ni, nr, hasher, skeyid_chunk);
#endif
	    break;

	case OAKLEY_RSA_SIG:
	    skeyid_digisig(ni, nr, shared_chunk, hasher, skeyid_chunk);
	    break;

	case OAKLEY_DSS_SIG:
	    /* XXX */

	case OAKLEY_RSA_ENC:
	case OAKLEY_RSA_ENC_REV:
	case OAKLEY_ELGAMAL_ENC:
	case OAKLEY_ELGAMAL_ENC_REV:
	    /* XXX */

	default:
	    bad_case(auth);
    }

#ifdef HAVE_LIBNSS
    memcpy(&skeyid, skeyid_chunk->ptr, skeyid_chunk->len);
    /* generate SKEYID_* from SKEYID */
    {

    chunk_t hmac_opad, hmac_ipad, hmac_pad, hmac_zerobyte, hmac_val1, hmac_val2;
    CK_OBJECT_HANDLE keyhandle;
    SECItem param, param1;

    hmac_opad = hmac_pads(HMAC_OPAD,HMAC_BUFSIZE);
    hmac_ipad = hmac_pads(HMAC_IPAD,HMAC_BUFSIZE);
    hmac_pad  = hmac_pads(0x00,HMAC_BUFSIZE-hasher->hash_digest_len);
    hmac_zerobyte = hmac_pads(0x00,1);
    hmac_val1 = hmac_pads(0x01,1);
    hmac_val2 = hmac_pads(0x02,1);

    DBG(DBG_CRYPT, DBG_log("NSS: Started key computation\n"));

    /*Deriving SKEYID_d = hmac_xxx(SKEYID, g^xy | CKY-I | CKY-R | 0) */
    PK11SymKey *tkey1 = pk11_derive_wrapper_osw(skeyid, CKM_CONCATENATE_BASE_AND_DATA
                                                , hmac_pad,CKM_XOR_BASE_AND_DATA, CKA_DERIVE, HMAC_BUFSIZE);

    PR_ASSERT(tkey1!=NULL);

    /*DBG(DBG_CRYPT, DBG_log("Started key computation: 1, length=%d\n", PK11_GetKeyLength(tkey1)));
     *nss_symkey_log(tkey1, "1");
     */

    PK11SymKey *tkey2 = pk11_derive_wrapper_osw(tkey1, CKM_XOR_BASE_AND_DATA
                                                , hmac_ipad, CKM_CONCATENATE_BASE_AND_KEY, CKA_DERIVE, 0);

    PR_ASSERT(tkey2!=NULL);

    keyhandle=PK11_GetSymKeyHandle(shared);
    param.data=(unsigned char *) &keyhandle;
    param.len=sizeof(keyhandle);
    DBG(DBG_CRYPT, DBG_log("NSS: dh shared param len=%d\n",param.len));

    PK11SymKey *tkey3 = PK11_Derive_osw(tkey2, CKM_CONCATENATE_BASE_AND_KEY, &param, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
    PR_ASSERT(tkey3!=NULL);

    PK11SymKey *tkey4 = pk11_derive_wrapper_osw(tkey3, CKM_CONCATENATE_BASE_AND_DATA
                                                , icookie, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
    PR_ASSERT(tkey4!=NULL);

    PK11SymKey *tkey5 = pk11_derive_wrapper_osw(tkey4, CKM_CONCATENATE_BASE_AND_DATA
                                                , rcookie, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);

    PR_ASSERT(tkey5!=NULL);

    PK11SymKey *tkey6 = pk11_derive_wrapper_osw(tkey5, CKM_CONCATENATE_BASE_AND_DATA
                                                , hmac_zerobyte, nss_key_derivation_mech(hasher), CKA_DERIVE, 0);

    PR_ASSERT(tkey6!=NULL);

    PK11SymKey *tkey7 = PK11_Derive_osw(tkey6, nss_key_derivation_mech(hasher), NULL, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
    PR_ASSERT(tkey7!=NULL);

    PK11SymKey *tkey8 = pk11_derive_wrapper_osw(tkey1, CKM_XOR_BASE_AND_DATA
                                                , hmac_opad, CKM_CONCATENATE_BASE_AND_KEY, CKA_DERIVE, 0);
    PR_ASSERT(tkey8!=NULL);


    keyhandle=PK11_GetSymKeyHandle(tkey7);
    param.data=(unsigned char*)&keyhandle;
    param.len=sizeof(keyhandle);

    PK11SymKey *tkey9 = PK11_Derive_osw(tkey8, CKM_CONCATENATE_BASE_AND_KEY, &param, nss_key_derivation_mech(hasher), CKA_DERIVE, 0);
    PR_ASSERT(tkey9!=NULL);

    skeyid_d = PK11_Derive_osw(tkey9, nss_key_derivation_mech(hasher), NULL, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
    PR_ASSERT(skeyid_d!=NULL);
    /* nss_symkey_log(skeyid_d, "skeyid_d"); */
     /*****End of SKEYID_d derivation***************************************/


    /*Deriving SKEYID_a = hmac_xxx(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1)*/
    keyhandle=PK11_GetSymKeyHandle(skeyid_d);
    param.data=(unsigned char*)&keyhandle;
    param.len=sizeof(keyhandle);

    PK11SymKey *tkey10 = PK11_Derive_osw(tkey2, CKM_CONCATENATE_BASE_AND_KEY, &param, CKM_CONCATENATE_BASE_AND_KEY, CKA_DERIVE, 0);
    PR_ASSERT(tkey10!=NULL);

    keyhandle=PK11_GetSymKeyHandle(shared);
    param.data=(unsigned char*)&keyhandle;
    param.len=sizeof(keyhandle);

    PK11SymKey *tkey11 = PK11_Derive_osw(tkey10, CKM_CONCATENATE_BASE_AND_KEY, &param, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
    PR_ASSERT(tkey11!=NULL);

    PK11SymKey *tkey12 = pk11_derive_wrapper_osw(tkey11, CKM_CONCATENATE_BASE_AND_DATA
                                                , icookie, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
    PR_ASSERT(tkey12!=NULL);

    PK11SymKey *tkey13 = pk11_derive_wrapper_osw(tkey12, CKM_CONCATENATE_BASE_AND_DATA
                                                , rcookie, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
    PR_ASSERT(tkey13!=NULL);

    PK11SymKey *tkey14 = pk11_derive_wrapper_osw(tkey13, CKM_CONCATENATE_BASE_AND_DATA
                                                , hmac_val1, nss_key_derivation_mech(hasher), CKA_DERIVE, 0);
    PR_ASSERT(tkey14!=NULL);

    PK11SymKey *tkey15 = PK11_Derive_osw(tkey14, nss_key_derivation_mech(hasher), NULL, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
    PR_ASSERT(tkey15!=NULL);

    keyhandle=PK11_GetSymKeyHandle(tkey15);
    param.data=(unsigned char*)&keyhandle;
    param.len=sizeof(keyhandle);

    PK11SymKey *tkey16 = PK11_Derive_osw(tkey8, CKM_CONCATENATE_BASE_AND_KEY, &param, nss_key_derivation_mech(hasher), CKA_DERIVE, 0);
    PR_ASSERT(tkey16!=NULL);

    skeyid_a = PK11_Derive_osw(tkey16, nss_key_derivation_mech(hasher), NULL, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
    PR_ASSERT(skeyid_a!=NULL);
    /* nss_symkey_log(skeyid_a, "skeyid_a"); */
    /*****End of SKEYID_a derivation***************************************/


    /*Deriving SKEYID_e = prf(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2)*/
    keyhandle=PK11_GetSymKeyHandle(skeyid_a);
    param.data=(unsigned char*)&keyhandle;
    param.len=sizeof(keyhandle);

    PK11SymKey *tkey17 = PK11_Derive_osw(tkey2, CKM_CONCATENATE_BASE_AND_KEY, &param, CKM_CONCATENATE_BASE_AND_KEY, CKA_DERIVE, 0);
    PR_ASSERT(tkey17!=NULL);

    keyhandle=PK11_GetSymKeyHandle(shared);
    param.data=(unsigned char*)&keyhandle;
    param.len=sizeof(keyhandle);

    PK11SymKey *tkey18 = PK11_Derive_osw(tkey17, CKM_CONCATENATE_BASE_AND_KEY, &param, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
    PR_ASSERT(tkey18!=NULL);

    PK11SymKey *tkey19 = pk11_derive_wrapper_osw(tkey18, CKM_CONCATENATE_BASE_AND_DATA
                                                , icookie, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
    PR_ASSERT(tkey19!=NULL);

    PK11SymKey *tkey20 = pk11_derive_wrapper_osw(tkey19, CKM_CONCATENATE_BASE_AND_DATA
                                                , rcookie, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
    PR_ASSERT(tkey20!=NULL);

    PK11SymKey *tkey21 = pk11_derive_wrapper_osw(tkey20, CKM_CONCATENATE_BASE_AND_DATA
                                                , hmac_val2, nss_key_derivation_mech(hasher), CKA_DERIVE, 0);
    PR_ASSERT(tkey21!=NULL);

    PK11SymKey *tkey22 = PK11_Derive_osw(tkey21, nss_key_derivation_mech(hasher), NULL, CKM_CONCATENATE_BASE_AND_DATA , CKA_DERIVE, 0);
    PR_ASSERT(tkey22!=NULL);

    keyhandle=PK11_GetSymKeyHandle(tkey22);
    param.data=(unsigned char*)&keyhandle;
    param.len=sizeof(keyhandle);

    PK11SymKey *tkey23 = PK11_Derive_osw(tkey8, CKM_CONCATENATE_BASE_AND_KEY, &param, nss_key_derivation_mech(hasher), CKA_DERIVE, 0);
    PR_ASSERT(tkey23!=NULL);

    DBG(DBG_CRYPT, DBG_log("NSS: enc keysize=%d\n",(int)keysize));
    /*Deriving encryption key from SKEYID_e*/
    /* Oakley Keying Material
     * Derived from Skeyid_e: if it is not big enough, generate more
     * using the PRF.
     * See RFC 2409 "IKE" Appendix B*/

      CK_EXTRACT_PARAMS bitstart = 0;
      param1.data = (unsigned char*)&bitstart;
      param1.len = sizeof (bitstart);

       if(keysize <= hasher->hash_digest_len){
       skeyid_e = PK11_Derive_osw(tkey23, nss_key_derivation_mech(hasher), NULL, CKM_EXTRACT_KEY_FROM_KEY, CKA_DERIVE, 0);
       PR_ASSERT(skeyid_e!=NULL);
       /* nss_symkey_log(skeyid_e, "skeyid_e"); */

       enc_key = PK11_DeriveWithFlags(skeyid_e, CKM_EXTRACT_KEY_FROM_KEY, &param1
                                      , nss_encryption_mech(encrypter), CKA_FLAGS_ONLY, keysize, CKF_ENCRYPT|CKF_DECRYPT);
       PR_ASSERT(enc_key!=NULL);

       /* nss_symkey_log(enc_key, "enc_key"); */
       }
       else
       {

        size_t i = 0;
       PK11SymKey *keymat;

        skeyid_e = PK11_Derive_osw(tkey23, nss_key_derivation_mech(hasher), NULL, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
        PR_ASSERT(skeyid_e!=NULL);
        /* nss_symkey_log(skeyid_e, "skeyid_e"); */

        PK11SymKey *tkey25 = pk11_derive_wrapper_osw(skeyid_e, CKM_CONCATENATE_BASE_AND_DATA
                                                , hmac_pad,CKM_XOR_BASE_AND_DATA, CKA_DERIVE, HMAC_BUFSIZE);
        PR_ASSERT(tkey25!=NULL);

        PK11SymKey *tkey26 = pk11_derive_wrapper_osw(tkey25, CKM_XOR_BASE_AND_DATA
                                                , hmac_ipad, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
        PR_ASSERT(tkey26!=NULL);

        PK11SymKey *tkey27 = pk11_derive_wrapper_osw(tkey26, CKM_CONCATENATE_BASE_AND_DATA
                                                , hmac_zerobyte, nss_key_derivation_mech(hasher), CKA_DERIVE, 0);
        PR_ASSERT(tkey27!=NULL);

        PK11SymKey *tkey28 = PK11_Derive_osw(tkey27, nss_key_derivation_mech(hasher), NULL
                                         , CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
        PR_ASSERT(tkey28!=NULL);

        PK11SymKey *tkey29 = pk11_derive_wrapper_osw(tkey25, CKM_XOR_BASE_AND_DATA
                                                , hmac_opad, CKM_CONCATENATE_BASE_AND_KEY, CKA_DERIVE, 0);
        PR_ASSERT(tkey29!=NULL);

        keyhandle=PK11_GetSymKeyHandle(tkey28);
        param.data=(unsigned char*)&keyhandle;
        param.len=sizeof(keyhandle);

        PK11SymKey *tkey30 = PK11_Derive_osw(tkey29, CKM_CONCATENATE_BASE_AND_KEY, &param, nss_key_derivation_mech(hasher), CKA_DERIVE, 0);
        PR_ASSERT(tkey30!=NULL);

       PK11SymKey *tkey31 = PK11_Derive_osw(tkey30, nss_key_derivation_mech(hasher), NULL, CKM_CONCATENATE_BASE_AND_KEY, CKA_DERIVE, 0);
       PR_ASSERT(tkey31!=NULL);

       keymat = tkey31;

       i += hasher->hash_digest_len;

        PK11SymKey *tkey32 = pk11_derive_wrapper_osw(skeyid_e, CKM_CONCATENATE_BASE_AND_DATA
                                                , hmac_pad,CKM_XOR_BASE_AND_DATA, CKA_DERIVE, HMAC_BUFSIZE);
        PR_ASSERT(tkey32!=NULL);

        PK11SymKey *tkey33 = pk11_derive_wrapper_osw(tkey32, CKM_XOR_BASE_AND_DATA
                                                , hmac_ipad, CKM_CONCATENATE_BASE_AND_KEY, CKA_DERIVE, 0);
        PR_ASSERT(tkey33!=NULL);

        PK11SymKey *tkey36 = pk11_derive_wrapper_osw(tkey32, CKM_XOR_BASE_AND_DATA
                                                , hmac_opad, CKM_CONCATENATE_BASE_AND_KEY, CKA_DERIVE, 0);
        PR_ASSERT(tkey36!=NULL);

               for(;;){

               keyhandle=PK11_GetSymKeyHandle(tkey31);
               param.data=(unsigned char*)&keyhandle;
               param.len=sizeof(keyhandle);

               PK11SymKey *tkey34 = PK11_Derive_osw(tkey33, CKM_CONCATENATE_BASE_AND_KEY, &param, nss_key_derivation_mech(hasher), CKA_DERIVE, 0);
               PR_ASSERT(tkey34!=NULL);

               PK11SymKey *tkey35 = PK11_Derive_osw(tkey34, nss_key_derivation_mech(hasher), NULL
                                         , CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
               PR_ASSERT(tkey35!=NULL);

               keyhandle=PK11_GetSymKeyHandle(tkey35);
               param.data=(unsigned char*)&keyhandle;
               param.len=sizeof(keyhandle);

               PK11SymKey *tkey37 = PK11_Derive_osw(tkey36, CKM_CONCATENATE_BASE_AND_KEY, &param, nss_key_derivation_mech(hasher), CKA_DERIVE, 0);
               PR_ASSERT(tkey37!=NULL);

               PK11SymKey *tkey38 = PK11_Derive_osw(tkey37, nss_key_derivation_mech(hasher), NULL, CKM_CONCATENATE_BASE_AND_KEY, CKA_DERIVE, 0);
               PR_ASSERT(tkey38!=NULL);

               i += hasher->hash_digest_len;

                       if(i >=keysize ){

                       /*concatenating K1 and K2 */
                       keyhandle=PK11_GetSymKeyHandle(tkey38);
                       param.data=(unsigned char*)&keyhandle;
                       param.len=sizeof(keyhandle);

                       PK11SymKey *tkey39 = PK11_Derive_osw(keymat, CKM_CONCATENATE_BASE_AND_KEY, &param, CKM_EXTRACT_KEY_FROM_KEY, CKA_DERIVE, 0);
                       PR_ASSERT(tkey39!=NULL);

                       enc_key = PK11_DeriveWithFlags(tkey39, CKM_EXTRACT_KEY_FROM_KEY, &param1
                                              , nss_encryption_mech(encrypter), CKA_FLAGS_ONLY, /*0*/ keysize, CKF_ENCRYPT|CKF_DECRYPT);

                        /* nss_symkey_log(enc_key, "enc_key"); */
                       PR_ASSERT(enc_key!=NULL);

                       PK11_FreeSymKey(tkey25);
                       PK11_FreeSymKey(tkey26);
                       PK11_FreeSymKey(tkey27);
                       PK11_FreeSymKey(tkey28);
                       PK11_FreeSymKey(tkey29);
                       PK11_FreeSymKey(tkey30);
                       PK11_FreeSymKey(tkey31);
                       PK11_FreeSymKey(tkey32);
                       PK11_FreeSymKey(tkey33);
                       PK11_FreeSymKey(tkey34);
                       PK11_FreeSymKey(tkey35);
                       PK11_FreeSymKey(tkey36);
                       PK11_FreeSymKey(tkey37);
                       PK11_FreeSymKey(tkey38);
                       PK11_FreeSymKey(tkey39);
                       PK11_FreeSymKey(keymat);

                       DBG(DBG_CRYPT, DBG_log("NSS: Freed 25-39 symkeys\n"));
                       break;
                       }
                       else{

                       keyhandle=PK11_GetSymKeyHandle(tkey38);
                       param.data=(unsigned char*)&keyhandle;
                       param.len=sizeof(keyhandle);

                       PK11SymKey *tkey39=PK11_Derive_osw(keymat,CKM_CONCATENATE_BASE_AND_KEY, &param,CKM_CONCATENATE_BASE_AND_KEY, CKA_DERIVE, 0);
                       PR_ASSERT(tkey39!=NULL);


                       keymat=tkey39;
                       PK11_FreeSymKey(tkey31);
                       tkey31=tkey38;
                       PK11_FreeSymKey(tkey34);
                       PK11_FreeSymKey(tkey35);
                       PK11_FreeSymKey(tkey37);

                       DBG(DBG_CRYPT, DBG_log("NSS: Freed symkeys 31 34 35 37\n"));
                       }
               }/*end for*/
       }/*end else skeyid_e */


    /*****End of SKEYID_e and encryption key derivation***************************************/



    /********Saving pointers of all derived keys**********************************************/
    skeyid_d_chunk->len = sizeof(PK11SymKey *);
    skeyid_d_chunk->ptr = alloc_bytes(skeyid_d_chunk->len, "calculated skeyid_d");
    memcpy(skeyid_d_chunk->ptr, &skeyid_d, skeyid_d_chunk->len);
    DBG(DBG_CRYPT, DBG_log("NSS: copied skeyid_d_chunk\n"));

    skeyid_a_chunk->len = sizeof(PK11SymKey *);
    skeyid_a_chunk->ptr = alloc_bytes(skeyid_a_chunk->len, "calculated skeyid_a");
    memcpy(skeyid_a_chunk->ptr, &skeyid_a, skeyid_a_chunk->len);
    DBG(DBG_CRYPT, DBG_log("NSS: copied skeyid_a_chunk\n"));

    skeyid_e_chunk->len = sizeof(PK11SymKey *);
    skeyid_e_chunk->ptr = alloc_bytes(skeyid_e_chunk->len, "calculated skeyid_e");
    memcpy(skeyid_e_chunk->ptr, &skeyid_e, skeyid_e_chunk->len);
    DBG(DBG_CRYPT, DBG_log("NSS: copied skeyid_e_chunk\n"));

    enc_key_chunk->len = sizeof(PK11SymKey *);
    enc_key_chunk->ptr = alloc_bytes(enc_key_chunk->len, "calculated enc_key");
    memcpy(enc_key_chunk->ptr, &enc_key, enc_key_chunk->len);
    DBG(DBG_CRYPT, DBG_log("NSS: copied enc_key_chunk\n"));


    /*****Freeing tmp keys***************************************/
   PK11_FreeSymKey(tkey1);
   PK11_FreeSymKey(tkey2);
   PK11_FreeSymKey(tkey3);
   PK11_FreeSymKey(tkey4);
   PK11_FreeSymKey(tkey5);
   PK11_FreeSymKey(tkey6);
   PK11_FreeSymKey(tkey7);
   PK11_FreeSymKey(tkey8);
   PK11_FreeSymKey(tkey9);
   PK11_FreeSymKey(tkey10);
   PK11_FreeSymKey(tkey11);
   PK11_FreeSymKey(tkey12);
   PK11_FreeSymKey(tkey13);
   PK11_FreeSymKey(tkey14);
   PK11_FreeSymKey(tkey15);
   PK11_FreeSymKey(tkey16);
   PK11_FreeSymKey(tkey17);
   PK11_FreeSymKey(tkey18);
   PK11_FreeSymKey(tkey19);
   PK11_FreeSymKey(tkey20);
   PK11_FreeSymKey(tkey21);
   PK11_FreeSymKey(tkey22);
   PK11_FreeSymKey(tkey23);

   DBG(DBG_CRYPT, DBG_log("NSS: Freed symkeys 1-23\n"));

   freeanychunk(hmac_opad);
   freeanychunk(hmac_ipad);
   freeanychunk(hmac_pad);
   freeanychunk(hmac_zerobyte);
   freeanychunk(hmac_val1);
   freeanychunk(hmac_val2);
   DBG(DBG_CRYPT, DBG_log("NSS: Freed padding chunks\n"));

    }

#else
    /* generate SKEYID_* from SKEYID */
    {
	struct hmac_ctx ctx;
	/* SKEYID_D */
	hmac_init_chunk(&ctx, hasher, *skeyid_chunk);
	hmac_update_chunk(&ctx, shared_chunk);
	hmac_update_chunk(&ctx, icookie);
	hmac_update_chunk(&ctx, rcookie);
	hmac_update(&ctx, (const u_char *)"\0", 1);
	hmac_final_chunk(*skeyid_d_chunk, "st_skeyid_d_chunk in generate_skeyids_iv()", &ctx);

	/* SKEYID_A */
	hmac_reinit(&ctx);
	hmac_update_chunk(&ctx, *skeyid_d_chunk);
	hmac_update_chunk(&ctx, shared_chunk);
	hmac_update_chunk(&ctx, icookie);
	hmac_update_chunk(&ctx, rcookie);
	hmac_update(&ctx, (const u_char *)"\1", 1);
	hmac_final_chunk(*skeyid_a_chunk, "st_skeyid_a_chunk in generate_skeyids_iv()", &ctx);

	/* SKEYID_E */
	hmac_reinit(&ctx);
	hmac_update_chunk(&ctx, *skeyid_a_chunk);
	hmac_update_chunk(&ctx, shared_chunk);
	hmac_update_chunk(&ctx, icookie);
	hmac_update_chunk(&ctx, rcookie);
	hmac_update(&ctx, (const u_char *)"\2", 1);
	hmac_final_chunk(*skeyid_e_chunk, "st_skeyid_e_chunk in generate_skeyids_iv()", &ctx);
    }
    DBG(DBG_CRYPT, DBG_log("NSS: end of key computation\n"));

#endif

    /* generate IV */
    {
	union hash_ctx hash_ctx;

	new_iv->len = hasher->hash_digest_len;
	new_iv->ptr = alloc_bytes(new_iv->len, "calculated new iv");

        DBG(DBG_CRYPT,
            DBG_dump_chunk("DH_i:", gi);
            DBG_dump_chunk("DH_r:", gr);
        );
	hasher->hash_init(&hash_ctx);
	hasher->hash_update(&hash_ctx, gi.ptr, gi.len);
	hasher->hash_update(&hash_ctx, gr.ptr, gr.len);
	hasher->hash_final(new_iv->ptr, &hash_ctx);
	DBG(DBG_CRYPT, DBG_log("end of IV generation\n"));
    }

#ifndef HAVE_LIBNSS
    /* Oakley Keying Material
     * Derived from Skeyid_e: if it is not big enough, generate more
     * using the PRF.
     * See RFC 2409 "IKE" Appendix B
     */
    {
	u_char keytemp[MAX_OAKLEY_KEY_LEN + MAX_DIGEST_LEN];
	u_char *k = skeyid_e_chunk->ptr;

	if (keysize > skeyid_e_chunk->len)
	{
	    struct hmac_ctx ctx;
	    size_t i = 0;

	    hmac_init_chunk(&ctx, hasher, *skeyid_e_chunk);
	    hmac_update(&ctx, (const u_char *)"\0", 1);
	    for (;;)
	    {
		hmac_final(&keytemp[i], &ctx);
		i += ctx.hmac_digest_len;
		if (i >= keysize)
		    break;
		hmac_reinit(&ctx);
		hmac_update(&ctx, &keytemp[i - ctx.hmac_digest_len], ctx.hmac_digest_len);
	    }
	    k = keytemp;
	}
	clonereplacechunk(*enc_key_chunk, k, keysize, "st_enc_key");
    }


    DBG(DBG_CRYPT,
	DBG_dump_chunk("Skeyid:  ", *skeyid_chunk);
	DBG_dump_chunk("Skeyid_d:", *skeyid_d_chunk);
	DBG_dump_chunk("Skeyid_a:", *skeyid_a_chunk);
	DBG_dump_chunk("Skeyid_e:", *skeyid_e_chunk);
	DBG_dump_chunk("enc key:",  *enc_key_chunk);
	DBG_dump_chunk("IV:",       *new_iv));
#endif
}

void calc_dh_iv(struct pluto_crypto_req *r)
{
    struct pcr_skeyid_q *skq = &r->pcr_d.dhq;
    struct pcr_skeyid_r *skr = &r->pcr_d.dhr;
    struct pcr_skeyid_q dhq;
    const struct oakley_group_desc *group;
    chunk_t  shared, g, ltsecret;
    chunk_t  skeyid, skeyid_d, skeyid_a, skeyid_e;
    chunk_t  new_iv, enc_key;
#ifdef HAVE_LIBNSS
    chunk_t pubk;
#else
    MP_INT  sec;
#endif

    /* copy the request, since we will use the same memory for the reply */
    memcpy(&dhq, skq, sizeof(struct pcr_skeyid_q));

    /* clear out the reply */
    memset(skr, 0, sizeof(*skr));
    skr->thespace.start = 0;
    skr->thespace.len   = sizeof(skr->space);

    group = lookup_group(dhq.oakley_group);
    passert(group != NULL);

#ifndef HAVE_LIBNSS
    pluto_crypto_allocchunk(&skr->thespace
			   , &skr->shared
			   , group->bytes);
    shared.ptr = wire_chunk_ptr(skr, &skr->shared);
    shared.len = group->bytes;

    ltsecret.ptr = wire_chunk_ptr(&dhq, &dhq.secret);
    ltsecret.len = dhq.secret.len;

    /* recover the long term secret */
    n_to_mpz(&sec, ltsecret.ptr, ltsecret.len);
#else
    setchunk_fromwire(ltsecret, &dhq.secret, &dhq);
    setchunk_fromwire(pubk, &dhq.pubk, &dhq);
#endif

    /* now calculate the (g^x)(g^y) ---
       need gi on responder, gr on initiator */

    if(dhq.init == RESPONDER) {
	setchunk_fromwire(g, &dhq.gi, &dhq);
    } else {
	setchunk_fromwire(g, &dhq.gr, &dhq);
    }

    DBG(DBG_CRYPT,
	DBG_dump_chunk("peer's g: ", g));


#ifndef HAVE_LIBNSS
    DBG(DBG_CRYPT,
    DBG_dump_chunk("long term secret: ", ltsecret));
    if(!calc_dh_shared(&shared, g, &sec, group)) {
        r->pcr_success = FALSE;
        return;
    }
    mpz_clear (&sec);
#else
    if(!calc_dh_shared(&shared, g, ltsecret, group, pubk)) {
        r->pcr_success = FALSE;
        return;
    }
#endif

    memset(&skeyid, 0, sizeof(skeyid));
    memset(&skeyid_d, 0, sizeof(skeyid_d));
    memset(&skeyid_a, 0, sizeof(skeyid_a));
    memset(&skeyid_e, 0, sizeof(skeyid_e));
    memset(&new_iv,   0, sizeof(new_iv));
    memset(&enc_key,  0, sizeof(enc_key));

    /* okay, so now calculate IV */
    calc_skeyids_iv(&dhq
		    , shared
		    , dhq.keysize
		    , &skeyid
		    , &skeyid_d
		    , &skeyid_a
		    , &skeyid_e
		    , &new_iv
		    , &enc_key);

    /* now translate it back to wire chunks, freeing the chunks */
    setwirechunk_fromchunk(skr->shared,   shared,   skr);
    setwirechunk_fromchunk(skr->skeyid,   skeyid,   skr);
    setwirechunk_fromchunk(skr->skeyid_d, skeyid_d, skr);
    setwirechunk_fromchunk(skr->skeyid_a, skeyid_a, skr);
    setwirechunk_fromchunk(skr->skeyid_e, skeyid_e, skr);
    setwirechunk_fromchunk(skr->new_iv,   new_iv,   skr);
    setwirechunk_fromchunk(skr->enc_key,  enc_key,  skr);

    freeanychunk(shared);
    freeanychunk(skeyid);
    freeanychunk(skeyid_d);
    freeanychunk(skeyid_a);
    freeanychunk(skeyid_e);
    freeanychunk(new_iv);
    freeanychunk(enc_key);

    r->pcr_success = TRUE;

    return;
}

void calc_dh(struct pluto_crypto_req *r)
{
    struct pcr_skeyid_q *skq = &r->pcr_d.dhq;
    struct pcr_skeyid_r *skr = &r->pcr_d.dhr;
    struct pcr_skeyid_q dhq;
    const struct oakley_group_desc *group;
    chunk_t  shared, g;
#ifndef HAVE_LIBNSS
    MP_INT  sec;
#else
    chunk_t ltsecret, pubk;
#endif

    /* copy the request, since we will use the same memory for the reply */
    memcpy(&dhq, skq, sizeof(struct pcr_skeyid_q));

    /* clear out the reply */
    zero(skr);
    clear_crypto_space(&skr->thespace, skr->space);

    group = lookup_group(dhq.oakley_group);
    passert(group != NULL);

#ifndef HAVE_LIBNSS
    pluto_crypto_allocchunk(&skr->thespace
			   , &skr->shared
			   , group->bytes);
    shared.ptr = wire_chunk_ptr(skr, &skr->shared);
    shared.len = group->bytes;

    /* recover the long term secret */
    n_to_mpz(&sec, wire_chunk_ptr(&dhq, &dhq.secret), dhq.secret.len);
#else
    setchunk_fromwire(ltsecret, &dhq.secret, &dhq);
    setchunk_fromwire(pubk, &dhq.pubk, &dhq);
#endif
    /* now calculate the (g^x)(g^y) */

    if(dhq.init == RESPONDER) {
      setchunk_fromwire(g, &dhq.gi, &dhq);
    } else {
      setchunk_fromwire(g, &dhq.gr, &dhq);
    }
    DBG(DBG_CRYPT, DBG_dump_chunk("peer's g: ", g));

#ifdef HAVE_LIBNSS
    r->pcr_success = calc_dh_shared(&shared, g, ltsecret, group, pubk);
#else
    r->pcr_success = calc_dh_shared(&shared, g, &sec, group);
    mpz_clear (&sec);
#endif

    /* now translate it back to wire chunks, freeing the chunks */
    setwirechunk_fromchunk(skr->shared,   shared,   skr);
    freeanychunk(shared);

    return;
}

/*
 * IKEv2 - RFC4306 SKEYSEED - calculation.
 */

static void
calc_skeyseed_v2(struct pcr_skeyid_q *skq
		 , chunk_t shared
		 , const size_t keysize
		 , chunk_t *skeyseed
		 , chunk_t *SK_d
		 , chunk_t *SK_ai
		 , chunk_t *SK_ar
		 , chunk_t *SK_ei
		 , chunk_t *SK_er
		 , chunk_t *SK_pi
		 , chunk_t *SK_pr
    )
{
    struct v2prf_stuff vpss;
    size_t total_keysize;
    memset(&vpss, 0, sizeof(vpss));

#ifdef HAVE_LIBNSS
    chunk_t hmac_opad, hmac_ipad, hmac_pad_prf, counter; /*hmac_pad_integ, hmac_zerobyte, hmac_val1, hmac_val2;*/
    CK_OBJECT_HANDLE keyhandle;
    SECItem param, param1;
    DBG(DBG_CRYPT, DBG_log("NSS: Started key computation\n"));

    PK11SymKey *skeyseed_k, *SK_d_k, *SK_ai_k, *SK_ar_k, *SK_ei_k, *SK_er_k, *SK_pi_k, *SK_pr_k;
#endif
    /* this doesn't take any memory, it's just moving pointers around */
    setchunk_fromwire(vpss.ni, &skq->ni, skq);
    setchunk_fromwire(vpss.nr, &skq->nr, skq);
    setchunk_fromwire(vpss.spii, &skq->icookie, skq);
    setchunk_fromwire(vpss.spir, &skq->rcookie, skq);

    DBG(DBG_CONTROLMORE
	, DBG_log("calculating skeyseed using prf=%s integ=%s cipherkey=%lu"
		  , enum_name(&trans_type_prf_names, skq->prf_hash)
		  , enum_name(&trans_type_integ_names, skq->integ_hash)
		  , (long unsigned)keysize));

#ifdef HAVE_LIBNSS
    const struct hash_desc *hasher = (struct hash_desc *)ike_alg_ikev2_find(IKE_ALG_HASH, skq->prf_hash, 0);
    passert(hasher);


    const struct encrypt_desc *encrypter = skq->encrypter;
    passert(encrypter);


    hmac_opad = hmac_pads(HMAC_OPAD,HMAC_BUFSIZE);
    hmac_ipad = hmac_pads(HMAC_IPAD,HMAC_BUFSIZE);
    hmac_pad_prf  = hmac_pads(0x00,HMAC_BUFSIZE-hasher->hash_digest_len);


    /* generate SKEYSEED from key=(Ni|Nr), hash of shared */
    {
       skeyid_digisig(vpss.ni, vpss.nr, shared, hasher, skeyseed);
        memcpy(&skeyseed_k, skeyseed->ptr, skeyseed->len);
    }
    passert(skeyseed_k);

#else
    vpss.prf_hasher = (struct hash_desc *)ike_alg_ikev2_find(IKE_ALG_HASH, skq->prf_hash, 0);
    passert(vpss.prf_hasher);

    /* generate SKEYSEED from key=(Ni|Nr), hash of shared */
    {
	struct hmac_ctx ctx;
	unsigned int keybytes;
	unsigned char *kb;

#if 0
	if(vpss.prf_hasher->hash_key_size == 0) {
#endif
	keybytes = vpss.ni.len + vpss.nr.len;
#if 0
	} else {
	    keybytes = vpss.prf_hasher->hash_key_size;
	}
#endif

	kb = alloc_bytes(keybytes, "skeyseed prf key");
	memset(kb, 0, keybytes);
	memcpy(kb,               vpss.ni.ptr, vpss.ni.len);
	memcpy(kb + vpss.ni.len, vpss.nr.ptr, vpss.nr.len);

	/* SKEYSEED */
	DBG(DBG_CRYPT,
	    DBG_dump("Input to SKEYSEED: ", kb, keybytes));

	hmac_init(&ctx, vpss.prf_hasher, kb, keybytes);
	hmac_update_chunk(&ctx, shared);
	hmac_final_chunk(*skeyseed, "skeyseed base", &ctx);
	vpss.skeyseed = skeyseed;
	pfree(kb);
    }
#endif

    /* now we have to generate the keys for everything */
    {
	/* need to know how many bits to generate */
	/* SK_d needs PRF hasher key bits */
	/* SK_p needs PRF hasher*2 key bits */
	/* SK_e needs keysize*2 key bits */
	/* SK_a needs hash's key bits size */
	const struct hash_desc *integ_hasher = (struct hash_desc *)ike_alg_ikev2_find(IKE_ALG_INTEG, skq->integ_hash, 0);
#ifdef HAVE_LIBNSS
       int skd_bytes = hasher->hash_key_size;
       int skp_bytes = hasher->hash_key_size;
#else
       int skd_bytes = vpss.prf_hasher->hash_key_size;
       int skp_bytes = vpss.prf_hasher->hash_key_size;
#endif
	int ska_bytes = integ_hasher->hash_key_size;
	int ske_bytes = keysize;

	vpss.counter[0]=0x01;
	vpss.t.len = 0;
	total_keysize = skd_bytes + (2*(ska_bytes + ske_bytes + skp_bytes));

	DBG(DBG_CRYPT,
	    DBG_log("PRF+ input");
	    DBG_dump_chunk("Ni", vpss.ni);
	    DBG_dump_chunk("Nr", vpss.nr);
	    DBG_dump_chunk("SPIi", vpss.spii);
	    DBG_dump_chunk("SPIr", vpss.spir);
	    DBG_log("Total keysize needed %d", (int)total_keysize);
	);
#ifdef HAVE_LIBNSS
	counter.ptr = &vpss.counter[0];
	counter.len =1;


	PK11SymKey *finalkey = NULL;
	PK11SymKey *tkey1 = pk11_derive_wrapper_osw(skeyseed_k, CKM_CONCATENATE_BASE_AND_DATA
		, hmac_pad_prf,CKM_XOR_BASE_AND_DATA, CKA_DERIVE, HMAC_BUFSIZE);
	PR_ASSERT(tkey1!=NULL);


	for(;;)
	{
	   PK11SymKey *tkey11,*tkey3;
           tkey11=NULL;

	   if(vpss.counter[0]== 0x01) {
		PK11SymKey *tkey2 = pk11_derive_wrapper_osw(tkey1, CKM_XOR_BASE_AND_DATA
			, hmac_ipad, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
		PR_ASSERT(tkey2!=NULL);

		tkey3 = pk11_derive_wrapper_osw(tkey2, CKM_CONCATENATE_BASE_AND_DATA
			, vpss.ni, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
		PK11_FreeSymKey(tkey2);
	   } else {
		PK11SymKey *tkey2 = pk11_derive_wrapper_osw(tkey1, CKM_XOR_BASE_AND_DATA
			, hmac_ipad, CKM_CONCATENATE_BASE_AND_KEY, CKA_DERIVE, 0);
		PR_ASSERT(tkey2!=NULL);


		keyhandle=PK11_GetSymKeyHandle(tkey2);
		param.data=(unsigned char*)&keyhandle;
		param.len=sizeof(keyhandle);

		PK11SymKey *tkey12 = PK11_Derive_osw(tkey2, CKM_CONCATENATE_BASE_AND_KEY
			, &param, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
		PR_ASSERT(tkey12!=NULL);

		tkey3 = pk11_derive_wrapper_osw(tkey12, CKM_CONCATENATE_BASE_AND_DATA
			, vpss.ni, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
		PK11_FreeSymKey(tkey2);
		PK11_FreeSymKey(tkey12);
	   }

	   PR_ASSERT(tkey3!=NULL);


	   PK11SymKey *tkey4 = pk11_derive_wrapper_osw(tkey3, CKM_CONCATENATE_BASE_AND_DATA
			, vpss.nr, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
	   PR_ASSERT(tkey4!=NULL);


	   PK11SymKey *tkey5 = pk11_derive_wrapper_osw(tkey4, CKM_CONCATENATE_BASE_AND_DATA
			, vpss.spii, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
	   PR_ASSERT(tkey5!=NULL);


	   PK11SymKey *tkey6 = pk11_derive_wrapper_osw(tkey5, CKM_CONCATENATE_BASE_AND_DATA
			, vpss.spir, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
	   PR_ASSERT(tkey6!=NULL);


	   PK11SymKey *tkey7 = pk11_derive_wrapper_osw(tkey6, CKM_CONCATENATE_BASE_AND_DATA
			, counter, nss_key_derivation_mech(hasher), CKA_DERIVE, 0);
	   PR_ASSERT(tkey7!=NULL);


	   PK11SymKey *tkey8 = PK11_Derive_osw(tkey7, nss_key_derivation_mech(hasher), NULL, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
	   PR_ASSERT(tkey8!=NULL);


	   PK11SymKey *tkey9 = pk11_derive_wrapper_osw(tkey1, CKM_XOR_BASE_AND_DATA
			, hmac_opad, CKM_CONCATENATE_BASE_AND_KEY, CKA_DERIVE, 0);
	   PR_ASSERT(tkey9!=NULL);


	   keyhandle=PK11_GetSymKeyHandle(tkey8);
	   param.data=(unsigned char*)&keyhandle;
	   param.len=sizeof(keyhandle);

	   PK11SymKey *tkey10 = PK11_Derive_osw(tkey9, CKM_CONCATENATE_BASE_AND_KEY, &param, nss_key_derivation_mech(hasher), CKA_DERIVE, 0);
	   PR_ASSERT(tkey10!=NULL);


	   if(vpss.counter[0]== 0x01) {
		finalkey = PK11_Derive_osw(tkey10, nss_key_derivation_mech(hasher), NULL, CKM_CONCATENATE_BASE_AND_KEY, CKA_DERIVE, 0);
		PR_ASSERT(finalkey!=NULL);


		tkey11 = PK11_Derive_osw(tkey10, nss_key_derivation_mech(hasher), NULL, CKM_CONCATENATE_BASE_AND_KEY, CKA_DERIVE, 0);
		PR_ASSERT(tkey11!=NULL);
	   } else {
		tkey11 = PK11_Derive_osw(tkey10, nss_key_derivation_mech(hasher), NULL, CKM_EXTRACT_KEY_FROM_KEY, CKA_DERIVE, 0);
		PR_ASSERT(tkey11!=NULL);


		keyhandle=PK11_GetSymKeyHandle(tkey11);
		param.data=(unsigned char*)&keyhandle;
		param.len=sizeof(keyhandle);

		if( total_keysize <= (PK11_GetKeyLength(finalkey)+PK11_GetKeyLength(tkey11)) ) {
		   finalkey = PK11_Derive_osw(finalkey, CKM_CONCATENATE_BASE_AND_KEY, &param, CKM_EXTRACT_KEY_FROM_KEY, CKA_DERIVE, 0);
		   PR_ASSERT(finalkey!=NULL);
		} else {
		   finalkey = PK11_Derive_osw(finalkey, CKM_CONCATENATE_BASE_AND_KEY, &param, CKM_CONCATENATE_BASE_AND_KEY, CKA_DERIVE, 0);
		   PR_ASSERT(finalkey!=NULL);
		}
	   }

	   PK11_FreeSymKey(tkey3);
	   PK11_FreeSymKey(tkey4);
	   PK11_FreeSymKey(tkey5);
	   PK11_FreeSymKey(tkey6);
	   PK11_FreeSymKey(tkey7);
	   PK11_FreeSymKey(tkey8);
	   PK11_FreeSymKey(tkey9);
	   PK11_FreeSymKey(tkey10);

	   if(total_keysize <= PK11_GetKeyLength(finalkey)) {
		PK11_FreeSymKey(tkey1);
		PK11_FreeSymKey(tkey11);
		break;
	   }

	   vpss.counter[0]++;
	}

	DBG(DBG_CRYPT, DBG_log("NSS ikev2: finished computing key material for IKEv2 SA\n"));
	CK_EXTRACT_PARAMS bs=0;
	SK_d_k = pk11_extract_derive_wrapper_osw(finalkey, bs, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, skd_bytes);


	bs= skd_bytes*BITS_PER_BYTE;
	SK_ai_k = pk11_extract_derive_wrapper_osw(finalkey, bs, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, ska_bytes);


	bs= (skd_bytes + ska_bytes)*BITS_PER_BYTE;
	SK_ar_k = pk11_extract_derive_wrapper_osw(finalkey, bs, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, ska_bytes);


	bs= (skd_bytes + (2*ska_bytes))*BITS_PER_BYTE;
	param1.data =(unsigned char*)&bs;
	param1.len = sizeof(bs);
	SK_ei_k = PK11_DeriveWithFlags(finalkey, CKM_EXTRACT_KEY_FROM_KEY, &param1
		, nss_encryption_mech(encrypter), CKA_FLAGS_ONLY, ske_bytes, CKF_ENCRYPT|CKF_DECRYPT);


	bs= (skd_bytes + (2*ska_bytes) + ske_bytes)*BITS_PER_BYTE;
	param1.data =(unsigned char*)&bs;
	param1.len = sizeof(bs);
	SK_er_k = PK11_DeriveWithFlags(finalkey, CKM_EXTRACT_KEY_FROM_KEY, &param1
		, nss_encryption_mech(encrypter), CKA_FLAGS_ONLY, ske_bytes, CKF_ENCRYPT|CKF_DECRYPT);


	bs= (skd_bytes + (2*ska_bytes) + (2*ske_bytes))*BITS_PER_BYTE;
	SK_pi_k = pk11_extract_derive_wrapper_osw(finalkey, bs, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, skp_bytes);


	bs= (skd_bytes + (2*ska_bytes) + (2*ske_bytes)+skp_bytes)*BITS_PER_BYTE;
	SK_pr_k = pk11_extract_derive_wrapper_osw(finalkey, bs, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, skp_bytes);



	DBG(DBG_CRYPT, DBG_log("NSS ikev2: finished computing individual keys for IKEv2 SA\n"));
	PK11_FreeSymKey(finalkey);


	SK_d->len = sizeof(PK11SymKey *);
	SK_d->ptr = alloc_bytes(SK_d->len, "SK_d");
	memcpy(SK_d->ptr, &SK_d_k, SK_d->len);


	SK_ai->len = sizeof(PK11SymKey *);
	SK_ai->ptr = alloc_bytes(SK_ai->len, "SK_ai");
	memcpy(SK_ai->ptr, &SK_ai_k, SK_ai->len);


	SK_ar->len = sizeof(PK11SymKey *);
	SK_ar->ptr = alloc_bytes(SK_ar->len, "SK_ar");
	memcpy(SK_ar->ptr, &SK_ar_k, SK_ar->len);


	SK_ei->len = sizeof(PK11SymKey *);
	SK_ei->ptr = alloc_bytes(SK_ei->len, "SK_ei");
	memcpy(SK_ei->ptr, &SK_ei_k, SK_ei->len);


	SK_er->len = sizeof(PK11SymKey *);
	SK_er->ptr = alloc_bytes(SK_er->len, "SK_er");
	memcpy(SK_er->ptr, &SK_er_k, SK_er->len);


	SK_pi->len = sizeof(PK11SymKey *);
	SK_pi->ptr = alloc_bytes(SK_pi->len, "SK_pi");
	memcpy(SK_pi->ptr, &SK_pi_k, SK_pi->len);


	SK_pr->len = sizeof(PK11SymKey *);
	SK_pr->ptr = alloc_bytes(SK_pr->len, "SK_pr");
	memcpy(SK_pr->ptr, &SK_pr_k, SK_pr->len);


	freeanychunk(hmac_opad);
	freeanychunk(hmac_ipad);
	freeanychunk(hmac_pad_prf);
#else
	/* SKEYSEED_T1 */
	v2genbytes(SK_d,  skd_bytes, "SK_d", &vpss);
	v2genbytes(SK_ai, ska_bytes, "SK_ai", &vpss);
	v2genbytes(SK_ar, ska_bytes, "SK_ar", &vpss);
	v2genbytes(SK_ei, ske_bytes, "SK_ei", &vpss);
	v2genbytes(SK_er, ske_bytes, "SK_er", &vpss);
	v2genbytes(SK_pi, skp_bytes, "SK_ei", &vpss);
	v2genbytes(SK_pr, skp_bytes, "SK_er", &vpss);

#endif
    }
    DBG(DBG_CRYPT,
	DBG_dump_chunk("shared:  ", shared);
	DBG_dump_chunk("skeyseed:", *skeyseed);
	DBG_dump_chunk("SK_d:", *SK_d);
	DBG_dump_chunk("SK_ai:", *SK_ai);
	DBG_dump_chunk("SK_ar:", *SK_ar);
	DBG_dump_chunk("SK_ei:", *SK_ei);
	DBG_dump_chunk("SK_er:", *SK_er);
	DBG_dump_chunk("SK_pi:", *SK_pi);
	DBG_dump_chunk("SK_pr:", *SK_pr));
}

void calc_dh_v2(struct pluto_crypto_req *r)
{
    struct pcr_skeyid_q    *skq = &r->pcr_d.dhq;
    struct pcr_skeycalc_v2 *skr = &r->pcr_d.dhv2;
    struct pcr_skeyid_q dhq;
    const struct oakley_group_desc *group;
    chunk_t  shared, g, ltsecret;
    chunk_t  skeyseed;
    chunk_t  SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr;
#ifndef HAVE_LIBNSS
    MP_INT  sec;
#else
    chunk_t pubk;
#endif

    /* copy the request, since we will use the same memory for the reply */
    memcpy(&dhq, skq, sizeof(struct pcr_skeyid_q));

    /* clear out the reply */
    memset(skr, 0, sizeof(*skr));
    skr->thespace.start = 0;
    skr->thespace.len   = sizeof(skr->space);

    group = lookup_group(dhq.oakley_group);
    passert(group != NULL);

#ifndef HAVE_LIBNSS
    pluto_crypto_allocchunk(&skr->thespace
			   , &skr->shared
			   , group->bytes);
    shared.ptr = wire_chunk_ptr(skr, &skr->shared);
    shared.len = group->bytes;

    ltsecret.ptr = wire_chunk_ptr(&dhq, &dhq.secret);
    ltsecret.len = dhq.secret.len;

    /* recover the long term secret */
    n_to_mpz(&sec, ltsecret.ptr, ltsecret.len);

    DBG(DBG_CRYPT,
	DBG_dump_chunk("long term secret: ", ltsecret));
#else
    setchunk_fromwire(ltsecret, &dhq.secret, &dhq);
    setchunk_fromwire(pubk, &dhq.pubk, &dhq);
#endif

    /* now calculate the (g^x)(g^y) --- need gi on responder, gr on initiator */

    if(dhq.init == RESPONDER) {
	setchunk_fromwire(g, &dhq.gi, &dhq);
    } else {
	setchunk_fromwire(g, &dhq.gr, &dhq);
    }
    DBG(DBG_CRYPT, DBG_dump_chunk("peer's g: ", g));

#ifndef HAVE_LIBNSS
    r->pcr_success = calc_dh_shared(&shared, g, &sec, group);
#else
    r->pcr_success = calc_dh_shared(&shared, g, ltsecret, group, pubk);
#endif
    if(!r->pcr_success) return;

    memset(&skeyseed,  0, sizeof(skeyseed));
    memset(&SK_d,      0, sizeof(SK_d));
    memset(&SK_ai,     0, sizeof(SK_ai));
    memset(&SK_ar,     0, sizeof(SK_ar));
    memset(&SK_ei,     0, sizeof(SK_ei));
    memset(&SK_er,     0, sizeof(SK_er));
    memset(&SK_pi,     0, sizeof(SK_pi));
    memset(&SK_pr,     0, sizeof(SK_pr));

    /* okay, so now calculate IV */
    calc_skeyseed_v2(&dhq
		     , shared
		     , dhq.keysize
		     , &skeyseed
		     , &SK_d
		     , &SK_ai
		     , &SK_ar
		     , &SK_ei
		     , &SK_er
		     , &SK_pi
		     , &SK_pr);


    /* now translate it back to wire chunks, freeing the chunks */
    setwirechunk_fromchunk(skr->shared,   shared,   skr);
    setwirechunk_fromchunk(skr->skeyseed, skeyseed, skr);
    setwirechunk_fromchunk(skr->skeyid_d, SK_d, skr);
    setwirechunk_fromchunk(skr->skeyid_ai,SK_ai, skr);
    setwirechunk_fromchunk(skr->skeyid_ar,SK_ar, skr);
    setwirechunk_fromchunk(skr->skeyid_ei,SK_ei, skr);
    setwirechunk_fromchunk(skr->skeyid_er,SK_er, skr);
    setwirechunk_fromchunk(skr->skeyid_pi,SK_pi, skr);
    setwirechunk_fromchunk(skr->skeyid_pr,SK_pr, skr);

    freeanychunk(shared);
    freeanychunk(skeyseed);
    freeanychunk(SK_d);
    freeanychunk(SK_ai);
    freeanychunk(SK_ar);
    freeanychunk(SK_ei);
    freeanychunk(SK_er);
    freeanychunk(SK_pi);
    freeanychunk(SK_pr);

    r->pcr_success = TRUE;
    return;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */

