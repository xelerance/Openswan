/*
 * Kernel runtime algorithm handling interface
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 *
 * kernel_alg.c,v 1.1.2.1 2003/11/21 18:12:23 jjo Exp
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
 * Fixes by:
 *           ML:          Mathieu Lafon <mlafon@arkoon.net>
 *
 * Fixes:
 *           ML:          kernel_alg_esp_ok_final() function (make F_STRICT consider enc,auth)
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/queue.h>

#include <openswan.h>

#include <openswan/pfkeyv2.h>
#include <openswan/pfkey.h>

#include <openswan/ipsec_policy.h>

#include "constants.h"
#include "alg_info.h"
#include "kernel_alg.h"
#include "oswlog.h"
#include "oswalloc.h"

/* ALG storage */
struct pluto_sadb_alg esp_aalg[K_SADB_AALG_MAX+1];
struct pluto_sadb_alg esp_ealg[K_SADB_EALG_MAX+1];

/* intended to be maximum values, but not used this way yet */
int esp_ealg_num=0;
int esp_aalg_num=0;

/*
 * map of Linux Kernel algorithm identifiers to IKEv2 identifiers
 * The ESP encryption identifiers are identical to IKEv2.
 * The ESP integrity  identifiers are not.
 * The kernel modules should know their IKEv2 identifier and tell us, and maybe
 * they do, but it isn't known for sure.
 */
struct aalg_mapping {
    enum ipsec_authentication_algo kernel_integ;
    enum ikev2_trans_type_integ    ikev2_integ;
};

static struct aalg_mapping aalg_mapping[] = {
    {AH_NONE,     	IKEv2_AUTH_NONE},
    {AH_MD5,            IKEv2_AUTH_HMAC_MD5_96},
    {AH_SHA,            IKEv2_AUTH_HMAC_SHA1_96},
    {AH_DES,            IKEv2_AUTH_DES_MAC},
    {AH_SHA2_256,      	IKEv2_AUTH_HMAC_SHA2_256_128},
    {AH_SHA2_384, 	IKEv2_AUTH_HMAC_SHA2_384_192},
    {AH_SHA2_512,       IKEv2_AUTH_HMAC_SHA2_512_256},
    {AH_AES_XCBC_MAC,   IKEv2_AUTH_AES_XCBC_96},
    {AH_AES_128_GMAC,	IKEv2_AUTH_AES_128_GMAC},
    {AH_AES_192_GMAC,   IKEv2_AUTH_AES_192_GMAC},
    {AH_AES_256_GMAC, 	IKEv2_AUTH_AES_256_GMAC},

#if 0
    /* not sure how: */
	IKEv2_AUTH_HMAC_MD5_128      = 6,  /* RFC4595 */
	IKEv2_AUTH_HMAC_SHA1_160     = 7,  /* RFC4595 */
    /* maps to kernel, or if it even does. */
#endif
};
const static unsigned aalg_mapping_len = elemsof(aalg_mapping);


enum ikev2_trans_type_integ kernelalg2ikev2(enum ipsec_authentication_algo kernel_integ)
{
    struct aalg_mapping *am = aalg_mapping;
    int i;

    for(i=0; i<aalg_mapping_len; i++, am++) {
        if(am->kernel_integ == kernel_integ) {
            return am->ikev2_integ;
        }
    }

    /* but 0 is also AH_NONE, but integrity is always required for ESP,
     * and is never optional for AH, so it's okay */
    return 0;
}


static struct pluto_sadb_alg *
sadb_alg_ptr (int satype UNUSED, int exttype, int alg_id, int rw
              ,char **extname   /* if NON-NULL, return name of extype */
              ,const struct enum_names **alg_names /* if NON-NULL, return enum_names */
              ,unsigned int *p_ikev2_id       /* if NON-NULL, pass back IKEv2 value */
              )
{
    struct pluto_sadb_alg *wanted_structure = NULL;
    int    *counter=NULL;
    struct pluto_sadb_alg *alg_p=NULL;
    enum ikev2_trans_type_integ v2_auth_id = 0;

    switch(exttype) {
    case SADB_EXT_SUPPORTED_AUTH:
        /* translate the algorithm ID into IKEv2 space */
        v2_auth_id = alg_id = kernelalg2ikev2(alg_id);
        if(alg_id == 0) goto fail;

        if(extname)   *extname = "integ";
        if(alg_names) *alg_names = &trans_type_integ_names;
        if(p_ikev2_id) *p_ikev2_id = v2_auth_id;
        if (alg_id <= K_SADB_AALG_MAX) {
            wanted_structure = esp_aalg;
            counter = &esp_aalg_num;
            break;
        }
        goto fail;

    case SADB_EXT_SUPPORTED_ENCRYPT:
        if(extname)   *extname = "encr";
        if(alg_names) *alg_names = &trans_type_encr_names;
        if(p_ikev2_id) *p_ikev2_id = alg_id;
        if (alg_id<=K_SADB_EALG_MAX) {
            wanted_structure = esp_ealg;
            counter = &esp_ealg_num;
            break;
        }
        goto fail;

    default:
        DBG_log("kernel mentioned sadb_ext: %u, unsupported", exttype);
        goto fail;
    }
    if(!wanted_structure) goto fail;

    alg_p = &wanted_structure[alg_id];
    alg_p->exttype = exttype;   /* redundant, as structures are not shared */

    switch(exttype) {
    case SADB_EXT_SUPPORTED_AUTH:
        alg_p->integ_id = v2_auth_id;
        break;

    case SADB_EXT_SUPPORTED_ENCRYPT:
        alg_p->encr_id  = alg_id;
        break;

    default:
        goto fail;
    }

    /* get for write: increment elem count */
    if (rw) {
        (*counter)++;
    }

fail:
          return alg_p;
}

const struct pluto_sadb_alg *
kernel_alg_sadb_alg_get(int satype, int exttype, int alg_id)
{
    return sadb_alg_ptr(satype, exttype, alg_id, 0, NULL, NULL, NULL);
}

/*
 *           Forget previous registration
 */
static int alg_init = 0;

void kernel_alg_init(void)
{
    if(!alg_init) {
        memset (&esp_aalg, 0, sizeof (esp_aalg));
        memset (&esp_ealg, 0, sizeof (esp_ealg));
        esp_ealg_num=esp_aalg_num=0;
        alg_init = 1;
    }
}

/* used by test skaffolding to stub in support for algorithms without kernel telling us*/
int
kernel_alg_add(int satype, int exttype, const struct sadb_alg *sadb_alg)
{
          struct pluto_sadb_alg *alg_p=NULL;
          int  alg_id = sadb_alg->sadb_alg_id;
          char *extname = "unknown";
          const struct enum_names *en = NULL;
          unsigned int ikev2num;

          DBG(DBG_KLIPS, DBG_log("kernel_alg_add called with "
                                 "satype=%d, exttype=%d, alg_id=%d",
                                 satype, exttype, sadb_alg->sadb_alg_id));

          if (!(alg_p=sadb_alg_ptr(satype, exttype, alg_id, 1, &extname, &en, &ikev2num))) {
              DBG_log("kernel_alg_add(%d,%d,%d) fails because alg combo is invalid\n"
                        , satype, exttype, sadb_alg->sadb_alg_id);
              return -1;
          }

          /*
           * if the alg_id is already set, then do not accept additional registrations,
           * which means the first implementation registered is the one used.
           * Note that if the keylen is zero, then it's just a placeholder registration.
           */
          if (alg_p->kernel_sadb_alg.sadb_alg_id != 0
              && alg_p->kernel_sadb_alg.sadb_alg_minbits != 0) {
              DBG(DBG_KLIPS, DBG_log("kernel_alg_add(): discarding already setup "
                                     "satype=%d, exttype=%d, alg_id=%d",
                                     satype, exttype, sadb_alg->sadb_alg_id));
              return 0;
          }
          if(alg_p->kernel_sadb_alg.sadb_alg_minbits == 0) {
              openswan_log("registed kernel %s algorithm %s [%u, %u<=key<=%u]"
                           , extname
                           , enum_show(en, ikev2num)
                           , ikev2num
                           , sadb_alg->sadb_alg_minbits
                           , sadb_alg->sadb_alg_maxbits);
          }
          alg_p->kernel_sadb_alg = *sadb_alg;
          return 1;
}

err_t
kernel_alg_esp_enc_ok(int alg_id, unsigned int key_len,
                      struct alg_info_esp *alg_info)
{
    struct pluto_sadb_alg *alg_p=NULL;
    err_t ugh = NULL;

    if(alg_info == NULL) {
        alg_info=alg_info_esp_defaults();
    }

    /*
     * test #1: encrypt algo must be present
     */
    int ret=ESP_EALG_PRESENT(alg_id);
    if (!ret) goto out;

    alg_p=&esp_ealg[alg_id];

    if(alg_id == ESP_AES_GCM_8
       || alg_id == ESP_AES_GCM_12
       || alg_id == ESP_AES_GCM_16) {
        if(key_len != 128 && key_len!=192 && key_len!=256 ) {

            ugh = builddiag("kernel_alg_db_add() key_len is incorrect: alg_id=%d, "
                            "key_len=%d, alg_minbits=%d, alg_maxbits=%d",
                            alg_id, key_len,
                            alg_p->kernel_sadb_alg.sadb_alg_minbits,
                            alg_p->kernel_sadb_alg.sadb_alg_maxbits);
            goto out;
        }
        else {
            /* increase key length by 4 bytes (RFC 4106)*/
            key_len = key_len + 4 * BITS_PER_BYTE;
        }
    }

    /*
     * test #2: if key_len specified, it must be in range
     */
    if ((key_len) && ((key_len < alg_p->kernel_sadb_alg.sadb_alg_minbits) ||
                      (key_len > alg_p->kernel_sadb_alg.sadb_alg_maxbits))) {

        ugh = builddiag("kernel_alg_db_add() key_len not in range: alg_id=%d, "
                        "key_len=%d, alg_minbits=%d, alg_maxbits=%d",
                        alg_id, key_len,
                        alg_p->kernel_sadb_alg.sadb_alg_minbits,
                        alg_p->kernel_sadb_alg.sadb_alg_maxbits);
    }

 out:
    if (!ugh && alg_p != NULL) {
        DBG(DBG_KLIPS,
            DBG_log("kernel_alg_esp_enc_ok(%d,%d): "
                    "alg_id=%d, "
                    "alg_ivlen=%d, alg_minbits=%d, alg_maxbits=%d, "
                    "res=%d, ret=%d",
                    alg_id, key_len,
                    alg_p->kernel_sadb_alg.sadb_alg_id,
                    alg_p->kernel_sadb_alg.sadb_alg_ivlen,
                    alg_p->kernel_sadb_alg.sadb_alg_minbits,
                    alg_p->kernel_sadb_alg.sadb_alg_maxbits,
                    alg_p->kernel_sadb_alg.sadb_alg_reserved,
                    ret);
            );
    } else {
        DBG(DBG_KLIPS,
            DBG_log("kernel_alg_esp_enc_ok(%d,%d): NO",
                    alg_id, key_len);
            );
    }
    return ugh;
}

int
kernel_alg_esp_enc_keylen(int alg_id)
{
          int keylen=0;
          if (!ESP_EALG_PRESENT(alg_id))
                    goto none;
          keylen=esp_ealg[alg_id].kernel_sadb_alg.sadb_alg_maxbits/BITS_PER_BYTE;
          switch (alg_id) {
                    /*
                     * this is veryUgly[TM]
                     * Peer should have sent KEY_LENGTH attribute for ESP_AES
                     * but if not do force it to 128 instead of using sadb_alg_maxbits
                     * from kernel.
                     * That's the case for alg-0.7.x and earlier versions.
                     *
                     * --jjo 01-Oct-02
                     */
                    case ESP_AES:
                              keylen=128/BITS_PER_BYTE;
                              break;
          }
none:
          DBG(DBG_KLIPS, DBG_log("kernel_alg_esp_enc_keylen():"
                    "alg_id=%d, keylen=%d",
                    alg_id, keylen));

          return keylen;
}

struct pluto_sadb_alg *
kernel_alg_esp_sadb_alg(int alg_id)
{
    struct pluto_sadb_alg *sadb_alg=NULL;

    if(ESP_EALG_VALID(alg_id)) {
        sadb_alg=&esp_ealg[alg_id];
    }

#if 0
    /* disabled because dumps core addresses, very verbose */
    DBG(DBG_KLIPS, DBG_log("kernel_alg_esp_sadb_ealg():"
                           "alg_id=%d, sadb_alg=%p",
                           alg_id, sadb_alg));
#endif
    return sadb_alg;
}

struct pluto_sadb_alg *
kernel_alg_esp_sadb_aalg(int alg_id)
{
    struct pluto_sadb_alg *sadb_alg=NULL;

    if(ESP_AALG_VALID(alg_id)) {
        sadb_alg=&esp_aalg[alg_id];
    }

#if 0
    /* disabled because dumps core addresses, very verbose */
    DBG(DBG_KLIPS, DBG_log("kernel_alg_esp_sadb_aalg():"
                           "alg_id=%d, sadb_alg=%p",
                           alg_id, sadb_alg));
#endif
    return sadb_alg;
}

struct pluto_sadb_alg *
kernel_alg_esp_auth_byikev2(enum ikev2_trans_type_integ authnum)
{
    if(ESP_AALG_VALID(authnum)) {
        return &esp_aalg[authnum];
    }
    return NULL;
}

/* return number of BYTES to key auth algorithm */
int
kernel_alg_esp_auth_keylen(enum ikev2_trans_type_integ authnum)
{
    struct pluto_sadb_alg *psa = kernel_alg_esp_auth_byikev2(authnum);

    if(psa) {
        return psa->kernel_sadb_alg.sadb_alg_minbits/8;
    } else {
        return 0;
    }
}

/* AH algorithms numbers are the name as ESP AUTH numbers */
int
kernel_alg_ah_auth_keylen(enum ikev2_trans_type_integ authnum)
{
    return kernel_alg_esp_auth_keylen(authnum);
}

bool kernel_alg_ikev2_esp_info(struct esp_info *ei
                               , enum ikev2_trans_type_encr sadb_ealg
                               , u_int16_t keylen
                               , enum ikev2_trans_type_integ sadb_aalg)
{
          if (!ESP_EALG_PRESENT(sadb_ealg)) {
              DBG(DBG_PARSING,
                  DBG_log("kernel_alg_esp_info(): kernel does not have ealg=%s(%d)"
                          , enum_name(&trans_type_encr_names, sadb_ealg)
                          , sadb_ealg));
              return FALSE;
          }
          if (!ESP_AALG_PRESENT(sadb_aalg)) {
              DBG(DBG_PARSING,
                  DBG_log("kernel_alg_esp_info():"
                          "kernel does not have ealg=%s(%d)"
                          , enum_name(&trans_type_integ_names, sadb_aalg)
                          , sadb_aalg));
              return FALSE;
          }

          if(ei) {
              memset(ei, 0, sizeof (*ei));
              ei->transid = sadb_ealg;
              ei->auth    = sadb_aalg;

              ei->encr_info = kernel_alg_esp_sadb_alg(sadb_ealg);
              ei->auth_info = kernel_alg_esp_sadb_aalg(sadb_aalg);
          }

          /* don't return "default" keylen because this value is used from
           * setup_half_ipsec_sa() to "validate" keylen
           * In effect,  enckeylen will be used as "max" value
           */

          /* if no key length is given, return default */
          if(keylen == 0) {
              if(ei) {
                  ei->enckeylen = ei->encr_info->kernel_sadb_alg.sadb_alg_minbits/BITS_PER_BYTE;
              }

          } else if(keylen <= ei->encr_info->kernel_sadb_alg.sadb_alg_maxbits &&
                      keylen >= ei->encr_info->kernel_sadb_alg.sadb_alg_minbits) {
              if(ei) {
                  ei->enckeylen = keylen/BITS_PER_BYTE;
              }

          } else {
              openswan_log("ealg %s proposed keylen=%u is invalid, not %u<X<%u "
                           , enum_name(&trans_type_encr_names, sadb_ealg)
                           , keylen
                           , ei->encr_info->kernel_sadb_alg.sadb_alg_maxbits
                           , ei->auth_info->kernel_sadb_alg.sadb_alg_minbits);

              /* proposed key length is invalid! */
              return FALSE;
          }

          if(ei) {
              ei->authkeylen=ei->auth_info->kernel_sadb_alg.sadb_alg_maxbits/BITS_PER_BYTE;
              DBG(DBG_PARSING, DBG_log("kernel_alg_esp_info():"
                                       "transid=%d, auth=%d, "
                                       "enckeylen=%d, authkeylen=%d",
                                       sadb_ealg, sadb_aalg,
                                       (int)ei->enckeylen, (int)ei->authkeylen
                                       ));
          }
          return TRUE;
}

/* sadb/ESP aa attrib converters */
enum ipsec_authentication_algo
alg_info_esp_aa2sadb(enum ikev1_auth_attribute auth)
{
	switch(auth) {
        case AUTH_ALGORITHM_HMAC_MD5:
            return AH_MD5;
        case AUTH_ALGORITHM_HMAC_SHA1:
            return AH_SHA;
        case AUTH_ALGORITHM_HMAC_SHA2_256:
            return AH_SHA2_256;
        case AUTH_ALGORITHM_HMAC_SHA2_384:
            return AH_SHA2_384;
        case AUTH_ALGORITHM_HMAC_SHA2_512:
            return AH_SHA2_512;
        case AUTH_ALGORITHM_HMAC_RIPEMD:
            return AH_RIPEMD;
        case AUTH_ALGORITHM_NONE:
            return AH_NONE;

        default:
            bad_case(auth);
	}
	return 0;
}

/* libalgoparse: to be removed */
err_t
kernel_alg_esp_auth_ok(int auth, struct alg_info_esp *nfo UNUSED)
{
    if(ESP_AALG_PRESENT(alg_info_esp_aa2sadb(auth))) {
        return NULL; /* present */
    } else {
        return "bad auth alg";
    }
}

err_t
kernel_alg_ah_auth_ok(int auth,
                          struct alg_info_esp *alg_info __attribute__((unused)))
{
    int ret=(ESP_AALG_PRESENT(alg_info_esp_aa2sadb(auth)));

    if(ret) {
        return NULL;
    } else {
        return "bad auth alg";
    }
}

struct esp_info *
kernel_alg_esp_info(u_int8_t transid, u_int16_t keylen, u_int16_t auth)
{
    enum ikev2_trans_type_encr sadb_ealg  = v1tov2_encr(transid);
    enum ikev2_trans_type_integ sadb_aalg = v1tov2_integ(auth);
    static struct esp_info ei2;

    if(kernel_alg_ikev2_esp_info(&ei2, sadb_ealg, keylen, sadb_aalg)) {
        return &ei2;
    } else {
        return NULL;
    }
}


/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
