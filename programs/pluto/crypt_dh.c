/* 
 * Cryptographic helper function - calculate DH
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
 *
 * RCSID $Id: crypt_dh.c,v 1.11 2005/08/14 21:47:29 mcr Exp $
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

/** Compute DH shared secret from our local secret and the peer's public value.
 * We make the leap that the length should be that of the group
 * (see quoted passage at start of ACCEPT_KE).
 */
static void
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
    /* if took more than 200 msec ... */
    if (tv_diff > 200000) {
	loglog(RC_LOG_SERIOUS, "WARNING: calc_dh_shared(): for %s took "
			"%ld usec"
		, enum_show(&oakley_group_names, group->group)
		, tv_diff);
    }

    DBG_cond_dump_chunk(DBG_CRYPT, "DH shared-secret:\n", *shared);
}


/* SKEYID for preshared keys.
 * See draft-ietf-ipsec-ike-01.txt 4.1
 */
static void
skeyid_preshared(const chunk_t pss
		 , const chunk_t ni
		 , const chunk_t nr
		 , const struct hash_desc *hasher
		 , chunk_t *skeyid)
{
    struct hmac_ctx ctx;

    passert(hasher != NULL);

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
}

static void
skeyid_digisig(const chunk_t ni
	       , const chunk_t nr
	       , const chunk_t shared
	       , const struct hash_desc *hasher
	       , chunk_t *skeyid)
{
    struct hmac_ctx ctx;
    chunk_t nir;

    DBG(DBG_CRYPT,
	DBG_log("skeyid inputs (digi+NI+NR+shared) hasher: %s", hasher->common.name);
	DBG_dump_chunk("shared-secret: ", shared);
	DBG_dump_chunk("ni: ", ni);
	DBG_dump_chunk("nr: ", nr));
    
    /* We need to hmac_init with the concatenation of Ni_b and Nr_b,
     * so we have to build a temporary concatentation.
     */
    nir.len = ni.len + nr.len;
    nir.ptr = alloc_bytes(nir.len, "Ni + Nr in skeyid_digisig");
    memcpy(nir.ptr, ni.ptr, ni.len);
    memcpy(nir.ptr+ ni.len, nr.ptr, nr.len);
    hmac_init_chunk(&ctx, hasher, nir);
    pfree(nir.ptr);

    hmac_update_chunk(&ctx, shared);
    hmac_final_chunk(*skeyid, "st_skeyid in skeyid_digisig()", &ctx);
    DBG(DBG_CRYPT,
	DBG_dump_chunk("keyid: ", *skeyid));
}

/* Generate the SKEYID_* and new IV
 * See draft-ietf-ipsec-ike-01.txt 4.1
 */
static void
calc_skeyids_iv(struct pcr_skeyid_q *skq
		, chunk_t shared
		, const size_t keysize     /* = st->st_oakley.enckeylen/BITS_PER_BYTE; */
		, chunk_t *skeyid          /* output */
		, chunk_t *skeyid_d        /* output */
		, chunk_t *skeyid_a        /* output */
		, chunk_t *skeyid_e        /* output */
		, chunk_t *new_iv
		, chunk_t *enc_key
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

    /* this doesn't take any memory */
    setchunk_fromwire(gi, &skq->gi, skq);
    setchunk_fromwire(gr, &skq->gr, skq);
    setchunk_fromwire(ni, &skq->ni, skq);
    setchunk_fromwire(nr, &skq->nr, skq);
    setchunk_fromwire(icookie, &skq->icookie, skq);
    setchunk_fromwire(rcookie, &skq->rcookie, skq);

    /* Generate the SKEYID */
    switch (auth)
    {
	case OAKLEY_PRESHARED_KEY:
	    setchunk_fromwire(pss,    &skq->pss, skq);
	    skeyid_preshared(pss, ni, nr, hasher, skeyid);
	    break;

	case OAKLEY_RSA_SIG:
	    skeyid_digisig(ni, nr, shared, hasher, skeyid);
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

    /* generate SKEYID_* from SKEYID */
    {
	struct hmac_ctx ctx;

	/* SKEYID_D */
	hmac_init_chunk(&ctx, hasher, *skeyid);
	hmac_update_chunk(&ctx, shared);
	hmac_update_chunk(&ctx, icookie);
	hmac_update_chunk(&ctx, rcookie);
	hmac_update(&ctx, (const u_char *)"\0", 1);
	hmac_final_chunk(*skeyid_d, "st_skeyid_d in generate_skeyids_iv()", &ctx);

	/* SKEYID_A */
	hmac_reinit(&ctx);
	hmac_update_chunk(&ctx, *skeyid_d);
	hmac_update_chunk(&ctx, shared);
	hmac_update_chunk(&ctx, icookie);
	hmac_update_chunk(&ctx, rcookie);
	hmac_update(&ctx, (const u_char *)"\1", 1);
	hmac_final_chunk(*skeyid_a, "st_skeyid_a in generate_skeyids_iv()", &ctx);

	/* SKEYID_E */
	hmac_reinit(&ctx);
	hmac_update_chunk(&ctx, *skeyid_a);
	hmac_update_chunk(&ctx, shared);
	hmac_update_chunk(&ctx, icookie);
	hmac_update_chunk(&ctx, rcookie);
	hmac_update(&ctx, (const u_char *)"\2", 1);
	hmac_final_chunk(*skeyid_e, "st_skeyid_e in generate_skeyids_iv()", &ctx);
    }

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
    }

    /* Oakley Keying Material
     * Derived from Skeyid_e: if it is not big enough, generate more
     * using the PRF.
     * See RFC 2409 "IKE" Appendix B
     */
    {
	u_char keytemp[MAX_OAKLEY_KEY_LEN + MAX_DIGEST_LEN];
	u_char *k = skeyid_e->ptr;

	if (keysize > skeyid_e->len)
	{
	    struct hmac_ctx ctx;
	    size_t i = 0;

	    hmac_init_chunk(&ctx, hasher, *skeyid_e);
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
	clonereplacechunk(*enc_key, k, keysize, "st_enc_key");
    }

    DBG(DBG_CRYPT,
	DBG_dump_chunk("Skeyid:  ", *skeyid);
	DBG_dump_chunk("Skeyid_d:", *skeyid_d);
	DBG_dump_chunk("Skeyid_a:", *skeyid_a);
	DBG_dump_chunk("Skeyid_e:", *skeyid_e);
	DBG_dump_chunk("enc key:",  *enc_key);
	DBG_dump_chunk("IV:",       *new_iv));
}

void calc_dh_iv(struct pluto_crypto_req *r)
{
    struct pcr_skeyid_q *skq = &r->pcr_d.dhq;
    struct pcr_skeyid_r *skr = &r->pcr_d.dhr;
    struct pcr_skeyid_q dhq;
    const struct oakley_group_desc *group;
    MP_INT  sec;
    chunk_t  shared, g, ltsecret;
    chunk_t  skeyid, skeyid_d, skeyid_a, skeyid_e; 
    chunk_t  new_iv, enc_key;

    /* copy the request, since we will use the same memory for the reply */
    memcpy(&dhq, skq, sizeof(struct pcr_skeyid_q));

    /* clear out the reply */
    memset(skr, 0, sizeof(*skr));
    skr->thespace.start = 0;
    skr->thespace.len   = sizeof(skr->space);

    group = lookup_group(dhq.oakley_group);
    passert(group != NULL);

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

    /* now calculate the (g^x)(g^y) --- need gi on responder, gr on initiator */

    if(dhq.init == RESPONDER) {
	setchunk_fromwire(g, &dhq.gi, &dhq);
    } else {
	setchunk_fromwire(g, &dhq.gr, &dhq);
    }

    calc_dh_shared(&shared, g, &sec, group);
    
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

    return;
}

void calc_dh(struct pluto_crypto_req *r)
{
    struct pcr_skeyid_q *skq = &r->pcr_d.dhq;
    struct pcr_skeyid_r *skr = &r->pcr_d.dhr;
    struct pcr_skeyid_q dhq;
    const struct oakley_group_desc *group;
    MP_INT  sec;
    chunk_t  shared, g;

    /* copy the request, since we will use the same memory for the reply */
    memcpy(&dhq, skq, sizeof(struct pcr_skeyid_q));

    /* clear out the reply */
    memset(skr, 0, sizeof(*skr));
    skr->thespace.start = 0;
    skr->thespace.len   = sizeof(skr->space);

    group = lookup_group(dhq.oakley_group);

    pluto_crypto_allocchunk(&skr->thespace
			   , &skr->shared
			   , group->bytes);
    shared.ptr = wire_chunk_ptr(skr, &skr->shared);
    shared.len = group->bytes;

    /* recover the long term secret */
    n_to_mpz(&sec, wire_chunk_ptr(&dhq, &dhq.secret), dhq.secret.len);

    /* now calculate the (g^x)(g^y) */

    if(dhq.init == RESPONDER) {
      setchunk_fromwire(g, &dhq.gi, &dhq);
    } else {
      setchunk_fromwire(g, &dhq.gr, &dhq);
    }
    calc_dh_shared(&shared, g, &sec, group);

    /* now translate it back to wire chunks, freeing the chunks */
    setwirechunk_fromchunk(skr->shared,   shared,   skr);
    freeanychunk(shared);

    return;
}

/* 
 * IKEv2 - RFC4306 SKEYSEED - calculation.
 */

struct v2prf_stuff {
    chunk_t t;
    const struct hash_desc *prf_hasher;
    chunk_t *skeyseed;
    chunk_t ni;
    chunk_t nr;
    chunk_t spii;
    chunk_t spir;
    u_char counter[1];
    unsigned int availbytes;
    unsigned int nextbytes;
};
    
static void
v2prfplus(struct v2prf_stuff *vps)
{
    struct hmac_ctx ctx;

    hmac_init_chunk(&ctx, vps->prf_hasher, *vps->skeyseed);
    hmac_update_chunk(&ctx, vps->t);
    hmac_update_chunk(&ctx, vps->ni);
    hmac_update_chunk(&ctx, vps->nr);
    hmac_update_chunk(&ctx, vps->spii);
    hmac_update_chunk(&ctx, vps->spir);
    hmac_update(&ctx, vps->counter, 1);
    hmac_final_chunk(vps->t, "skeyseed_t1", &ctx);
    if(DBGP(DBG_CRYPT)) {
	char b[20];
	sprintf(b, "prf+[%u]:", vps->counter[0]);
	DBG_dump_chunk(b, vps->t);
    }

    vps->counter[0]++;
    vps->availbytes  = vps->t.len;
    vps->nextbytes   = 0;
}

static void v2genbytes(chunk_t *need
		       , unsigned int needed, const char *name
		       , struct v2prf_stuff *vps)
{
    u_char *target;
    need->ptr = alloc_bytes(needed, name);
    need->len = needed;
    target = need->ptr;

    while(needed > vps->availbytes) {
	if(vps->availbytes) {
	    /* use any bytes which are presently in the buffer */
	    memcpy(target, &vps->t.ptr[vps->nextbytes], vps->availbytes);
	    target += vps->availbytes;
	    needed -= vps->availbytes;
	    vps->availbytes = 0;
	}
	/* generate more bits into t1 */
	v2prfplus(vps);
    }
    passert(needed <= vps->availbytes);

    memcpy(target, &vps->t.ptr[vps->nextbytes], needed);
    vps->availbytes -= needed;
    vps->nextbytes  += needed;
}

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
    chunk_t gi, gr;
    memset(&vpss, 0, sizeof(vpss));

    /* this doesn't take any memory, it's just moving pointers around */
    setchunk_fromwire(gi,      &skq->gi, skq);
    setchunk_fromwire(gr,      &skq->gr, skq);
    setchunk_fromwire(vpss.ni, &skq->ni, skq);
    setchunk_fromwire(vpss.nr, &skq->nr, skq);
    setchunk_fromwire(vpss.spii, &skq->icookie, skq);
    setchunk_fromwire(vpss.spir, &skq->rcookie, skq);

    DBG(DBG_CONTROLMORE
	, DBG_log("calculating skeyseed using prf=%s integ=%s cipherkey=%u"
		  , enum_name(&trans_type_prf_names, skq->prf_hash)
		  , enum_name(&trans_type_integ_names, skq->integ_hash)
		  , keysize));


    vpss.prf_hasher = crypto_get_hasher(skq->prf_hash);

    /* generate SKEYSEED from key=(Ni|Nr), hash of shared */
    {
	struct hmac_ctx ctx;
	unsigned int keybytes;
	unsigned char *kb;

	//if(vpss.prf_hasher->hash_key_size == 0) {
	keybytes = vpss.ni.len + vpss.nr.len;
	//} else {
	//keybytes = vpss.prf_hasher->hash_key_size;
	//}

	kb = alloc_bytes(keybytes, "skeyseed prf key");
	memset(kb, 0, keybytes);
	memcpy(kb,              vpss.ni.ptr, keybytes/2);
	memcpy(kb + keybytes/2, vpss.nr.ptr, keybytes/2);

	/* SKEYSEED */
	DBG(DBG_CRYPT,
	    DBG_dump("Input to SKEYSEED: ", kb, keybytes));

	hmac_init(&ctx, vpss.prf_hasher, kb, keybytes);
	hmac_update_chunk(&ctx, shared);
	hmac_final_chunk(*skeyseed, "skeyseed base", &ctx);
	vpss.skeyseed = skeyseed;
	pfree(kb);
    }

    /* now we have to generate the keys for everything */
    {
	/* need to know how many bits to generate */
	/* SK_d needs PRF hasher key bits */
	/* SK_p needs PRF hasher*2 key bits */
	/* SK_e needs keysize*2 key bits */
	/* SK_a needs hash's key bits size */
	const struct hash_desc *integ_hasher = crypto_get_hasher(skq->integ_hash);
	int skd_bytes = vpss.prf_hasher->hash_key_size;
	int ska_bytes = integ_hasher->hash_key_size;
	int ske_bytes = keysize;
	int skp_bytes = vpss.prf_hasher->hash_key_size;

	vpss.counter[0]=0x01;
	vpss.t.len = 0;

	if(DBGP(DBG_CRYPT)) {
	    DBG_log("PRF+ input");
	    DBG_dump_chunk("Ni", vpss.ni);
	    DBG_dump_chunk("Nr", vpss.nr);
	    DBG_dump_chunk("SPIi", vpss.spii);
	    DBG_dump_chunk("SPIr", vpss.spir);
	}
	
	/* SKEYSEED_T1 */
	v2genbytes(SK_d,  skd_bytes, "SK_d", &vpss);
	v2genbytes(SK_ai, ska_bytes, "SK_ai", &vpss);
	v2genbytes(SK_ar, ska_bytes, "SK_ar", &vpss);
	v2genbytes(SK_ei, ske_bytes, "SK_ei", &vpss);
	v2genbytes(SK_er, ske_bytes, "SK_er", &vpss);
	v2genbytes(SK_pi, skp_bytes, "SK_ei", &vpss);
	v2genbytes(SK_pr, skp_bytes, "SK_er", &vpss);
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
    MP_INT  sec;
    chunk_t  shared, g, ltsecret;
    chunk_t  skeyseed;
    chunk_t  SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr;

    /* copy the request, since we will use the same memory for the reply */
    memcpy(&dhq, skq, sizeof(struct pcr_skeyid_q));

    /* clear out the reply */
    memset(skr, 0, sizeof(*skr));
    skr->thespace.start = 0;
    skr->thespace.len   = sizeof(skr->space);

    group = lookup_group(dhq.oakley_group);
    passert(group != NULL);

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

    /* now calculate the (g^x)(g^y) --- need gi on responder, gr on initiator */

    if(dhq.init == RESPONDER) {
	setchunk_fromwire(g, &dhq.gi, &dhq);
    } else {
	setchunk_fromwire(g, &dhq.gr, &dhq);
    }

    calc_dh_shared(&shared, g, &sec, group);
    
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

    return;
}


/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */

