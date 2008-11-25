#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
#include <openswan.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "klips-crypto/aes_cbc.h"
#include "alg_info.h"
#include "ike_alg.h"

#ifdef HAVE_LIBNSS
#include <pk11pub.h>
#include <prmem.h>
#include <prerror.h>
#endif

#define  AES_KEY_MIN_LEN	128
#define  AES_KEY_DEF_LEN	128
#define  AES_KEY_MAX_LEN	256

static void
do_aes(u_int8_t *buf, size_t buf_len, u_int8_t *key, size_t key_size, u_int8_t *iv, bool enc)
{

#ifdef HAVE_LIBNSS
    u_int8_t iv_bak[AES_CBC_BLOCK_SIZE];
    u_int8_t *new_iv = NULL;        /* logic will avoid copy to NULL */
    u_int8_t *tmp_buf; 
    
    CK_MECHANISM_TYPE  cipherMech;
    PK11SlotInfo*      slot = NULL;
    SECItem            keyItem, ivItem;
    SECItem*           SecParam = NULL;
    PK11SymKey*        SymKey = NULL;
    PK11Context*       EncContext = NULL;
    SECStatus          rv;
    int                tmp_outlen;


    cipherMech = CKM_AES_CBC; /*openswan provides padding*/
    slot = PK11_GetBestSlot(cipherMech, NULL);
	
    keyItem.type = siBuffer;
    keyItem.data = key;
    keyItem.len = key_size;

    if (slot == NULL){
      loglog(RC_LOG_SERIOUS, "do_aes: Unable to find security device (err %d)\n", PR_GetError());
      goto out;
    }

    SymKey = PK11_ImportSymKey(slot, cipherMech, PK11_OriginUnwrap,enc? CKA_ENCRYPT:CKA_DECRYPT,&keyItem, NULL);
  
    if (SymKey == NULL){
     loglog(RC_LOG_SERIOUS, "do_aes: Failure to import key into NSS (err %d)\n", PR_GetError());
     goto out;
    }

    ivItem.type = siBuffer;
    ivItem.data = iv;
    ivItem.len = AES_CBC_BLOCK_SIZE;

    SecParam = PK11_ParamFromIV(cipherMech, &ivItem);
    if (SecParam == NULL){
      loglog(RC_LOG_SERIOUS, "do_aes: Failure to set up PKCS11 param (err %d)\n",PR_GetError());
      goto out;
   }

   tmp_outlen = 0;
   tmp_buf= PR_Malloc((PRUint32)buf_len);

    if (!enc){
    memcpy(new_iv=iv_bak,(char*) buf + buf_len-AES_CBC_BLOCK_SIZE,AES_CBC_BLOCK_SIZE);
    }
	
    EncContext = PK11_CreateContextBySymKey(cipherMech, enc? CKA_ENCRYPT : CKA_DECRYPT, SymKey, SecParam); 
    rv = PK11_CipherOp(EncContext, tmp_buf, &tmp_outlen, buf_len, buf, buf_len);
    passert(rv==SECSuccess);
    PK11_DestroyContext(EncContext, PR_TRUE);
    memcpy(buf,tmp_buf,buf_len);  

    if(enc){
    new_iv = (char*) buf + buf_len-AES_CBC_BLOCK_SIZE;
    }

    memcpy(iv, new_iv, AES_CBC_BLOCK_SIZE);
    PR_Free(tmp_buf);

out:
 
 if (SymKey)
    PK11_FreeSymKey(SymKey);

 if (SecParam)
    SECITEM_FreeItem(SecParam, PR_TRUE);

#else
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
#endif

}

struct encrypt_desc algo_aes =
{
	common: {
	  name: "aes",
	  officname: "aes",
	  algo_type: 	IKE_ALG_ENCRYPT,
	  algo_id:   	OAKLEY_AES_CBC,
	  algo_v2id:    IKEv2_ENCR_AES_CBC,
	  algo_next: 	NULL, },
	enc_ctxsize: 	sizeof(aes_context),
	enc_blocksize: 	AES_CBC_BLOCK_SIZE,
	keyminlen: 	AES_KEY_MIN_LEN,
	keydeflen: 	AES_KEY_DEF_LEN,
	keymaxlen: 	AES_KEY_MAX_LEN,
	do_crypt: 	do_aes,
};
int ike_alg_aes_init(void);
int
ike_alg_aes_init(void)
{
	int ret = ike_alg_register_enc(&algo_aes);
	return ret;
}
/*
IKE_ALG_INIT_NAME: ike_alg_aes_init
*/
