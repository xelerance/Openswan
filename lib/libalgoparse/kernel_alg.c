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
sadb_alg_ptr (int satype, int exttype, int alg_id, int rw)
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

        if (alg_id<=SADB_AALG_MAX) {
            wanted_structure = esp_aalg;
            counter = &esp_aalg_num;
            break;
        }
        goto fail;

    case SADB_EXT_SUPPORTED_ENCRYPT:
        if (alg_id<=K_SADB_EALG_MAX) {
            wanted_structure = esp_ealg;
            counter = &esp_ealg_num;
            break;
        }
        goto fail;
    default:
        goto fail;
    }
    if(!wanted_structure) goto fail;

    alg_p = &wanted_structure[alg_id];
    alg_p->exttype = exttype;   /* redundant, as structures are not shared */

    switch(satype) {
    case SADB_SATYPE_AH:
        alg_p->integ_id = v2_auth_id;
        break;

    case SADB_SATYPE_ESP:
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
          return sadb_alg_ptr(satype, exttype, alg_id, 0);
}

/*
 *           Forget previous registration
 */
static void
kernel_alg_init(void)
{
          DBG(DBG_KLIPS, DBG_log("alg_init():"
                    "memset(%p, 0, %d) "
                    "memset(%p, 0, %d) ",
                    &esp_aalg,  (int)sizeof (esp_aalg),
                    &esp_ealg,  (int)sizeof (esp_ealg)));
          memset (&esp_aalg, 0, sizeof (esp_aalg));
          memset (&esp_ealg, 0, sizeof (esp_ealg));
          esp_ealg_num=esp_aalg_num=0;
}

/* used by test skaffolding to stub in support for algorithms without kernel telling us*/
int
kernel_alg_add(int satype, int exttype, const struct sadb_alg *sadb_alg)
{
          struct pluto_sadb_alg *alg_p=NULL;
          int  alg_id = sadb_alg->sadb_alg_id;

          DBG(DBG_KLIPS, DBG_log("kernel_alg_add():"
                    "satype=%d, exttype=%d, alg_id=%d",
                    satype, exttype, sadb_alg->sadb_alg_id));

          if (!(alg_p=sadb_alg_ptr(satype, exttype, alg_id, 1))) {
              DBG_log("kernel_alg_add(%d,%d,%d) fails because alg combo is invalid\n"
                        , satype, exttype, sadb_alg->sadb_alg_id);
              return -1;
          }

          /*
           * if the alg_id is already set, then do not accept additional registrations,
           * which means the first implementation registered is the one used.
           */
          if (alg_p->kernel_sadb_alg.sadb_alg_id) {
              DBG(DBG_KLIPS, DBG_log("kernel_alg_add(): discarding already setup "
                                     "satype=%d, exttype=%d, alg_id=%d",
                                     satype, exttype, sadb_alg->sadb_alg_id));
              return 0;
          }
          alg_p->kernel_sadb_alg = *sadb_alg;
          return 1;
}

err_t
kernel_alg_esp_enc_ok(int alg_id, unsigned int key_len,
                          struct alg_info_esp *alg_info __attribute__((unused)))
{
    struct pluto_sadb_alg *alg_p=NULL;
    err_t ugh = NULL;

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

/*
 *          Load kernel_alg arrays from /proc
 *           used in manual mode from klips/utils/spi.c
 */
int
kernel_alg_proc_read(void)
{
    int satype;
    int supp_exttype;
    int alg_id, ivlen, minbits, maxbits;
    char name[20];
    struct sadb_alg sadb_alg;
    int ret;
    char buf[128];
    FILE *fp=fopen("/proc/net/pf_key_supported", "r");
    if (!fp)
        return -1;
    kernel_alg_init();
    while (fgets(buf, sizeof(buf), fp)) {
        if (buf[0] != ' ') /* skip titles */
            continue;
        sscanf(buf, "%d %d %d %d %d %d %s",
               &satype, &supp_exttype,
               &alg_id, &ivlen,
               &minbits, &maxbits, name);
        switch (satype) {
        case SADB_SATYPE_ESP:
            switch(supp_exttype) {
            case SADB_EXT_SUPPORTED_AUTH:
            case SADB_EXT_SUPPORTED_ENCRYPT:
                sadb_alg.sadb_alg_id=alg_id;
                sadb_alg.sadb_alg_ivlen=ivlen;
                sadb_alg.sadb_alg_minbits=minbits;
                sadb_alg.sadb_alg_maxbits=maxbits;
                sadb_alg.sadb_alg_reserved=0;
                ret=kernel_alg_add(satype, supp_exttype, &sadb_alg);
                DBG(DBG_CRYPT, DBG_log("kernel_alg_proc_read() alg_id=%d, "
                                       "alg_ivlen=%d, alg_minbits=%d, alg_maxbits=%d, "
                                       "ret=%d",
                                       sadb_alg.sadb_alg_id,
                                       sadb_alg.sadb_alg_ivlen,
                                       sadb_alg.sadb_alg_minbits,
                                       sadb_alg.sadb_alg_maxbits,
                                       ret));
            }
        default:
            continue;
        }
    }
    fclose(fp);
    return 0;
}

/*
 *          Load kernel_alg arrays pluto's SADB_REGISTER
 *           user by pluto/kernel.c
 */

void
kernel_alg_register_pfkey(const struct sadb_msg *msg_buf, int buflen)
{
          /*
           *          Trick: one 'type-mangle-able' pointer to
           *          ease offset/assign
           */
          union {
                    const struct sadb_msg *msg;
                    const struct sadb_supported *supported;
                    const struct sadb_ext *ext;
                    const struct sadb_alg *alg;
                    const char *ch;
          } sadb;
          int satype;
          int msglen;
          int i=0;
          /*          Initialize alg arrays           */
          kernel_alg_init();
          satype=msg_buf->sadb_msg_satype;
          sadb.msg=msg_buf;
          msglen=sadb.msg->sadb_msg_len*IPSEC_PFKEYv2_ALIGN;
          msglen-=sizeof(struct sadb_msg);
          buflen-=sizeof(struct sadb_msg);
          passert(buflen>0);
          sadb.msg++;
          while(msglen) {
                    int supp_exttype=sadb.supported->sadb_supported_exttype;
                    int supp_len;
                    supp_len=sadb.supported->sadb_supported_len*IPSEC_PFKEYv2_ALIGN;
                    DBG(DBG_KLIPS, DBG_log("kernel_alg_register_pfkey(): SADB_SATYPE_%s: "
                              "sadb_msg_len=%d sadb_supported_len=%d",
                              satype==SADB_SATYPE_ESP? "ESP" : "AH",
                              msg_buf->sadb_msg_len,
                              supp_len));
                    sadb.supported++;
                    msglen-=supp_len;
                    buflen-=supp_len;
                    passert(buflen>=0);
                    for (supp_len-=sizeof(struct sadb_supported);
                              supp_len;
                              supp_len-=sizeof(struct sadb_alg), sadb.alg++,i++) {
                              int ret;
                              ret=kernel_alg_add(satype, supp_exttype, sadb.alg);
                              DBG(DBG_KLIPS, DBG_log("kernel_alg_register_pfkey(): SADB_SATYPE_%s: "
                                        "alg[%d], exttype=%d, satype=%d, alg_id=%d, "
                                        "alg_ivlen=%d, alg_minbits=%d, alg_maxbits=%d, "
                                        "res=%d, ret=%d",
                                        satype==SADB_SATYPE_ESP? "ESP" : "AH",
                                        i,
                                        supp_exttype,
                                        satype,
                                        sadb.alg->sadb_alg_id,
                                        sadb.alg->sadb_alg_ivlen,
                                        sadb.alg->sadb_alg_minbits,
                                        sadb.alg->sadb_alg_maxbits,
                                        sadb.alg->sadb_alg_reserved,
                                        ret));
                    }
          }
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
          if (!ESP_EALG_PRESENT(alg_id))
                    goto none;
          sadb_alg=&esp_ealg[alg_id];
none:
          DBG(DBG_KLIPS, DBG_log("kernel_alg_esp_sadb_ealg():"
                    "alg_id=%d, sadb_alg=%p",
                    alg_id, sadb_alg));
          return sadb_alg;
}

struct pluto_sadb_alg *
kernel_alg_esp_sadb_aalg(int alg_id)
{
          struct pluto_sadb_alg *sadb_alg=NULL;
          if (!ESP_AALG_PRESENT(alg_id))
                    goto none;
          sadb_alg=&esp_aalg[alg_id];
none:
          DBG(DBG_KLIPS, DBG_log("kernel_alg_esp_sadb_aalg():"
                    "alg_id=%d, sadb_alg=%p",
                    alg_id, sadb_alg));
          return sadb_alg;
}


err_t
kernel_alg_esp_auth_ok(int auth,
                    struct alg_info_esp *alg_info __attribute__((unused)))
{
          int ret=(ESP_AALG_PRESENT(alg_info_esp_aa2sadb(auth)));

          if(ret) {
              return NULL;
          } else {
              return "bad auth alg";
          }
}

int
kernel_alg_esp_auth_keylen(int auth)
{
          int sadb_aalg=alg_info_esp_aa2sadb(auth);
          int a_keylen=0;
          if (sadb_aalg)
                    a_keylen=esp_aalg[sadb_aalg].kernel_sadb_alg.sadb_alg_maxbits/BITS_PER_BYTE;

          DBG(DBG_CONTROL | DBG_CRYPT | DBG_PARSING
                        , DBG_log("kernel_alg_esp_auth_keylen(auth=%d, sadb_aalg=%d): "
                        "a_keylen=%d", auth, sadb_aalg, a_keylen));
          return a_keylen;
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

int
kernel_alg_ah_auth_keylen(int auth)
{
          int sadb_aalg=alg_info_esp_aa2sadb(auth);
          int a_keylen=0;
          if (sadb_aalg)
                    a_keylen=esp_aalg[sadb_aalg].kernel_sadb_alg.sadb_alg_maxbits/BITS_PER_BYTE;

          DBG(DBG_CONTROL | DBG_CRYPT | DBG_PARSING
                        , DBG_log("kernel_alg_ah_auth_keylen(auth=%d, sadb_aalg=%d): "
                        "a_keylen=%d", auth, sadb_aalg, a_keylen));
          return a_keylen;
}

bool kernel_alg_esp_info(struct esp_info *ei
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
                  ei->enckeylen = esp_ealg[sadb_ealg].kernel_sadb_alg.sadb_alg_minbits/BITS_PER_BYTE;
              }

          } else if(keylen <= esp_ealg[sadb_ealg].kernel_sadb_alg.sadb_alg_maxbits &&
                      keylen >= esp_ealg[sadb_ealg].kernel_sadb_alg.sadb_alg_minbits) {
              if(ei) {
                  ei->enckeylen = keylen/BITS_PER_BYTE;
              }

          } else {
              DBG(DBG_PARSING, DBG_log("kernel_alg_esp_info():"
                                             "ealg=%d, proposed keylen=%u is invalid, not %u<X<%u "
                                             , sadb_ealg, keylen
                                             , esp_ealg[sadb_ealg].kernel_sadb_alg.sadb_alg_maxbits
                                             , esp_ealg[sadb_ealg].kernel_sadb_alg.sadb_alg_minbits));

              /* proposed key length is invalid! */
              return FALSE;
          }

          if(ei) {
              ei->authkeylen=esp_aalg[sadb_aalg].kernel_sadb_alg.sadb_alg_maxbits/BITS_PER_BYTE;
              DBG(DBG_PARSING, DBG_log("kernel_alg_esp_info():"
                                       "transid=%d, auth=%d, "
                                       "enckeylen=%d, authkeylen=%d",
                                       sadb_ealg, sadb_aalg,
                                       (int)ei->enckeylen, (int)ei->authkeylen
                                       ));
          }
          return TRUE;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
