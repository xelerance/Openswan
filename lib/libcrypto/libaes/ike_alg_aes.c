/*
 * Copyright (C) 2019 Michael Richardson <mcr@xelerance.com>
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
 * This code is extracted from programs/pluto/ike_alg.c, and has copyright
 * that goes back to original SuperFreeswan 1.99 days.
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
#include "crypto/aes_cbc.h"
#include "alg_info.h"
#include "pluto/ike_alg.h"

#ifdef HAVE_LIBNSS
#include <pk11pub.h>
#include <prmem.h>
#include <prerror.h>
#include "oswconf.h"
#include "oswlog.h"
#endif

#define  AES_KEY_MIN_LEN	128
#define  AES_KEY_DEF_LEN	128
#define  AES_KEY_MAX_LEN	256

#ifndef HAVE_LIBNSS
static void
do_aes(u_int8_t *buf, size_t buf_len, u_int8_t *key, size_t key_size, u_int8_t *iv, bool enc)
{
    aes_context aes_ctx;
    char iv_bak[AES_CBC_BLOCK_SIZE];
    char *new_iv = NULL;	/* logic will avoid copy to NULL */

    aes_set_key(&aes_ctx, key, key_size, 0);

    /*
     *	my AES cbc does not touch passed IV (optimization for
     *	ESP handling), so I must "emulate" des-like IV
     *	crunching
     */
    if (!enc)
	    memcpy(new_iv=iv_bak,
			    (char*) buf + buf_len-AES_CBC_BLOCK_SIZE,
			    AES_CBC_BLOCK_SIZE);

    AES_cbc_encrypt(&aes_ctx, buf, buf, buf_len, iv, enc);

    if (enc)
	    new_iv = (char*) buf + buf_len-AES_CBC_BLOCK_SIZE;

    memcpy(iv, new_iv, AES_CBC_BLOCK_SIZE);
}
#endif

#ifdef HAVE_LIBNSS
static void
do_aes_libnss(u_int8_t *buf, size_t buf_len, u_int8_t *key, size_t key_size, u_int8_t *iv, bool enc)
{
    u_int8_t iv_bak[AES_CBC_BLOCK_SIZE];
    u_int8_t *new_iv = NULL;        /* logic will avoid copy to NULL */
    u_int8_t *tmp_buf;

    CK_MECHANISM_TYPE  ciphermech;
    SECItem              ivitem;
    SECItem*           secparam = NULL;
    PK11SymKey*        symkey = NULL;
    PK11Context*       enccontext = NULL;
    SECStatus          rv;
    int                outlen;

    DBG(DBG_CRYPT, DBG_log("NSS do_aes: enter"));
    ciphermech = CKM_AES_CBC; /*openswan provides padding*/

    memcpy(&symkey, key, key_size);

    if (symkey == NULL) {
	loglog(RC_LOG_SERIOUS, "do_aes: NSS derived enc key in NULL\n");
	abort();
    }

    ivitem.type = siBuffer;
    ivitem.data = iv;
    ivitem.len = AES_CBC_BLOCK_SIZE;

    secparam = PK11_ParamFromIV(ciphermech, &ivitem);
    if (secparam == NULL) {
	loglog(RC_LOG_SERIOUS, "do_aes: Failure to set up PKCS11 param (err %d)\n",PR_GetError());
	abort();
   }

   outlen = 0;
   tmp_buf= PR_Malloc((PRUint32)buf_len);

    if (!enc){
    memcpy(new_iv=iv_bak,(char*) buf + buf_len-AES_CBC_BLOCK_SIZE,AES_CBC_BLOCK_SIZE);
    }

    enccontext = PK11_CreateContextBySymKey(ciphermech, enc? CKA_ENCRYPT : CKA_DECRYPT, symkey, secparam);
    if (enccontext == NULL) {
        loglog(RC_LOG_SERIOUS, "do_aes: PKCS11 context creation failure (err %d)\n", PR_GetError());
        abort();
    }
    rv = PK11_CipherOp(enccontext, tmp_buf, &outlen, buf_len, buf, buf_len);
    if (rv != SECSuccess) {
        loglog(RC_LOG_SERIOUS, "do_aes: PKCS11 operation failure (err %d)\n", PR_GetError());
        abort();
    }
    PK11_DestroyContext(enccontext, PR_TRUE);
    memcpy(buf,tmp_buf,buf_len);

    if(enc){
    new_iv = (u_int8_t*) buf + buf_len-AES_CBC_BLOCK_SIZE;
    }

    memcpy(iv, new_iv, AES_CBC_BLOCK_SIZE);
    PR_Free(tmp_buf);

if (secparam)
    SECITEM_FreeItem(secparam, PR_TRUE);
DBG(DBG_CRYPT, DBG_log("NSS do_aes: exit"));

}
#endif

struct ike_encr_desc algo_aes =
{
	common: {
	  name: "aes",
	  officname: "aes",
	  algo_type: 	IKEv2_TRANS_TYPE_ENCR,
	  algo_id:   	OAKLEY_AES_CBC,
	  algo_v2id:    IKEv2_ENCR_AES_CBC,
	  algo_next: 	NULL, },
	enc_ctxsize: 	sizeof(aes_context),
	enc_blocksize: 	AES_CBC_BLOCK_SIZE,
	keyminlen: 	AES_KEY_MIN_LEN,
	keydeflen: 	AES_KEY_DEF_LEN,
	keymaxlen: 	AES_KEY_MAX_LEN,
#ifdef HAVE_LIBNSS
	do_crypt: 	do_aes_libnss,
#else
	do_crypt: 	do_aes,
#endif
};

int
ike_alg_aes_init(void)
{
	int ret = ike_alg_register_enc(&algo_aes);
	return ret;
}
/*
IKE_ALG_INIT_NAME: ike_alg_aes_init
*/
