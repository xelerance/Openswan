/*
 * FIXME add copyrights - double check CVS commits for origin
 */

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
#include "oswconf.h"
#include "oswlog.h"
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
	goto out;
    }

    ivitem.type = siBuffer;
    ivitem.data = iv;
    ivitem.len = AES_CBC_BLOCK_SIZE;

    secparam = PK11_ParamFromIV(ciphermech, &ivitem);
    if (secparam == NULL) {
	loglog(RC_LOG_SERIOUS, "do_aes: Failure to set up PKCS11 param (err %d)\n",PR_GetError());
	goto out;
   }

   outlen = 0;
   tmp_buf= PR_Malloc((PRUint32)buf_len);

    if (!enc){
    memcpy(new_iv=iv_bak,(char*) buf + buf_len-AES_CBC_BLOCK_SIZE,AES_CBC_BLOCK_SIZE);
    }

    enccontext = PK11_CreateContextBySymKey(ciphermech, enc? CKA_ENCRYPT : CKA_DECRYPT, symkey, secparam);
    rv = PK11_CipherOp(enccontext, tmp_buf, &outlen, buf_len, buf, buf_len);
    passert(rv==SECSuccess);
    PK11_DestroyContext(enccontext, PR_TRUE);
    memcpy(buf,tmp_buf,buf_len);

    if(enc){
    new_iv = (u_int8_t*) buf + buf_len-AES_CBC_BLOCK_SIZE;
    }

    memcpy(iv, new_iv, AES_CBC_BLOCK_SIZE);
    PR_Free(tmp_buf);

out:

if (secparam)
    SECITEM_FreeItem(secparam, PR_TRUE);
DBG(DBG_CRYPT, DBG_log("NSS do_aes: exit"));

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
