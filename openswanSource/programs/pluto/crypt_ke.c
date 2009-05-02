/* 
 * Cryptographic helper function - calculate KE and nonce
 * Copyright (C) 2004 Michael C. Richardson <mcr@xelerance.com>
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
 * This code was developed with the support of IXIA communications.
 *
 * Modifications to use OCF interface written by
 * Daniel Djamaludin <danield@cyberguard.com>
 * Copyright (C) 2004-2005 Intel Corporation. 
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

#include "oswcrypto.h"

#ifdef HAVE_LIBNSS
# include <nss.h>
# include <pk11pub.h>
# include <keyhi.h>
# include "oswconf.h"
#endif

void calc_ke(struct pluto_crypto_req *r)
{
#ifndef HAVE_LIBNSS
    MP_INT mp_g;
    MP_INT secret;
    chunk_t gi;
#else
    chunk_t  prime;
    chunk_t  base;
    SECKEYDHParams      dhp;
    PK11SlotInfo *slot = NULL;
    SECKEYPrivateKey *privk;
    SECKEYPublicKey   *pubk; 
#endif
    struct pcr_kenonce *kn = &r->pcr_d.kn;
    const struct oakley_group_desc *group;

    group = lookup_group(kn->oakley_group);

#ifndef HAVE_LIBNSS    
    pluto_crypto_allocchunk(&kn->thespace
			    , &kn->secret
			    , LOCALSECRETSIZE);
    
    get_rnd_bytes(wire_chunk_ptr(kn, &(kn->secret)), LOCALSECRETSIZE);
    
    n_to_mpz(&secret, wire_chunk_ptr(kn, &(kn->secret)), LOCALSECRETSIZE);
    
    mpz_init(&mp_g);
    oswcrypto.mod_exp(&mp_g, &groupgenerator, &secret, group->modulus);
    
    gi = mpz_to_n(&mp_g, group->bytes);
    
    pluto_crypto_allocchunk(&kn->thespace, &kn->gi, gi.len);
    
    {
	char *gip = wire_chunk_ptr(kn, &(kn->gi));
	
	memcpy(gip, gi.ptr, gi.len);
    }
    
    DBG(DBG_CRYPT,
	DBG_dump("Local DH secret:\n"
		 , wire_chunk_ptr(kn, &(kn->secret))
		 , LOCALSECRETSIZE);
	DBG_dump_chunk("Public DH value sent:\n", gi));

    /* clean up after ourselves */
    mpz_clear(&mp_g);
    mpz_clear(&secret);
    freeanychunk(gi);
#else
    base  = mpz_to_n2(&groupgenerator);
    prime = mpz_to_n2(group->modulus);

    dhp.prime.data=prime.ptr;
    dhp.prime.len=prime.len;
    dhp.base.data=base.ptr;
    dhp.base.len=base.len;

    slot = PK11_GetBestSlot(CKM_DH_PKCS_KEY_PAIR_GEN,osw_return_nss_password_file_info());
    if(!slot) {
	loglog(RC_LOG_SERIOUS, "NSS: slot for DH key gen is NULL");
    }
    PR_ASSERT(slot!=NULL);

    privk = PK11_GenerateKeyPair(slot, CKM_DH_PKCS_KEY_PAIR_GEN, &dhp, &pubk, PR_FALSE, PR_TRUE, osw_return_nss_password_file_info());
    if(!privk) {
	loglog(RC_LOG_SERIOUS, "NSS: DH private key creation failed");
    }
    PR_ASSERT(privk!=NULL);
    pluto_crypto_allocchunk(&kn->thespace, &kn->secret, sizeof(SECKEYPrivateKey*));
    {
	char *gip = wire_chunk_ptr(kn, &(kn->secret));
	memcpy(gip, &privk, sizeof(SECKEYPrivateKey *));
    }

    pluto_crypto_allocchunk(&kn->thespace, &kn->gi, pubk->u.dh.publicValue.len);
    {
	char *gip = wire_chunk_ptr(kn, &(kn->gi));
	memcpy(gip, pubk->u.dh.publicValue.data, pubk->u.dh.publicValue.len);
    }

    pluto_crypto_allocchunk(&kn->thespace, &kn->pubk, sizeof(SECKEYPublicKey*));
    {
	char *gip = wire_chunk_ptr(kn, &(kn->pubk));
	memcpy(gip, &pubk, sizeof(SECKEYPublicKey*));
    }
    
    DBG(DBG_CRYPT,
       DBG_dump("NSS: Local DH secret:\n"
                , wire_chunk_ptr(kn, &(kn->secret))
                , sizeof(SECKEYPrivateKey*));
       DBG_dump("NSS: Public DH value sent(computed in NSS):\n", wire_chunk_ptr(kn, &(kn->gi)),pubk->u.dh.publicValue.len));

    DBG(DBG_CRYPT,
        DBG_dump("NSS: Local DH public value (pointer):\n"
                 , wire_chunk_ptr(kn, &(kn->pubk))
                 , sizeof(SECKEYPublicKey*)));

    /* clean up after ourselves */
    if (slot) {
	PK11_FreeSlot(slot);
    }
    //if (privk){SECKEY_DestroyPrivateKey(privk);}
    //if (pubk){SECKEY_DestroyPublicKey(pubk);}
    freeanychunk(prime);
    freeanychunk(base);
#endif
}

void calc_nonce(struct pluto_crypto_req *r)
{
  struct pcr_kenonce *kn = &r->pcr_d.kn;

  pluto_crypto_allocchunk(&kn->thespace, &kn->n, DEFAULT_NONCE_SIZE);
  get_rnd_bytes(wire_chunk_ptr(kn, &(kn->n)), DEFAULT_NONCE_SIZE);

  DBG(DBG_CRYPT,
      DBG_dump("Generated nonce:\n"
	       , wire_chunk_ptr(kn, &(kn->n))
	       , DEFAULT_NONCE_SIZE));
}

stf_status build_ke(struct pluto_crypto_req_cont *cn
		    , struct state *st 
		    , const struct oakley_group_desc *group
		    , enum crypto_importance importance)
{
    struct pluto_crypto_req rd;
    struct pluto_crypto_req *r = &rd;
    err_t e;
    bool toomuch = FALSE;

    pcr_init(r, pcr_build_kenonce, importance);
    r->pcr_d.kn.oakley_group   = group->group;
    
    cn->pcrc_serialno = st->st_serialno;
    e= send_crypto_helper_request(r, cn, &toomuch);
    
    if(e != NULL) {
	loglog(RC_LOG_SERIOUS, "can not start crypto helper: %s", e);
	if(toomuch) {
	    return STF_TOOMUCHCRYPTO;
	} else {
	    return STF_FAIL;
	}
    } else if(!toomuch) {
	st->st_calculating = TRUE;
	delete_event(st);
	event_schedule(EVENT_CRYPTO_FAILED, EVENT_CRYPTO_FAILED_DELAY, st);
	return STF_SUSPEND;
    } else {
	/* we must have run the continuation directly, so
	 * complete_v1_state_transition already got called. 
	 */
	return STF_INLINE;
    }
}


stf_status build_nonce(struct pluto_crypto_req_cont *cn
		       , struct state *st 
		       , enum crypto_importance importance)
{
    struct pluto_crypto_req rd;
    struct pluto_crypto_req *r = &rd;
    err_t e;
    bool toomuch = FALSE;

  pcr_init(r, pcr_build_nonce, importance);

  cn->pcrc_serialno = st->st_serialno;
  e = send_crypto_helper_request(r, cn, &toomuch);

  if(e != NULL) {
      loglog(RC_LOG_SERIOUS, "can not start crypto helper: %s", e);
      if(toomuch) {
	  return STF_TOOMUCHCRYPTO;
      } else {
	  return STF_FAIL;
      }
  } else if(!toomuch) {
      st->st_calculating = TRUE;
      delete_event(st);
      event_schedule(EVENT_CRYPTO_FAILED, EVENT_CRYPTO_FAILED_DELAY, st);
      return STF_SUSPEND;
  } else {
      /* we must have run the continuation directly, so
       * complete_v1_state_transition already got called. 
       */
      return STF_INLINE;
  }
}


/*
 * Local Variables:
 * c-basic-offset: 4
 * c-style: pluto
 * End:
 */
