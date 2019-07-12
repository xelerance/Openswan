/*
 * convert between IKEv1 and IKEv2 algorithm values
 * Copyright: Michael Richardson <mcr@xelerance.com>
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
#include "pluto/defs.h"
#include "pluto/state.h"
#include "pluto/db_ops.h"

int v2tov1_encr(enum ikev2_trans_type_encr encr)
{
    switch(encr) {
    case IKEv2_ENCR_DES:
        return OAKLEY_DES_CBC;
    case  IKEv2_ENCR_IDEA:
        return OAKLEY_IDEA_CBC;
    case  IKEv2_ENCR_BLOWFISH:
        return OAKLEY_BLOWFISH_CBC;
    case  IKEv2_ENCR_RC5:
        return OAKLEY_RC5_R16_B64_CBC;
    case  IKEv2_ENCR_3DES:
        return OAKLEY_3DES_CBC;
    case  IKEv2_ENCR_CAST:
        return OAKLEY_CAST_CBC;
    case  IKEv2_ENCR_AES_CBC:
        return OAKLEY_AES_CBC;
    default:
	return 0;
    }
}

enum ikev2_trans_type_encr v1tov2_encr(int encr)
{
    switch(encr) {
    case OAKLEY_DES_CBC:
      return IKEv2_ENCR_DES;
    case OAKLEY_IDEA_CBC:
      return IKEv2_ENCR_IDEA;
    case OAKLEY_BLOWFISH_CBC:
      return IKEv2_ENCR_BLOWFISH;
    case OAKLEY_RC5_R16_B64_CBC:
      return IKEv2_ENCR_RC5;
    case OAKLEY_3DES_CBC:
      return IKEv2_ENCR_3DES;
    case OAKLEY_CAST_CBC:
      return IKEv2_ENCR_CAST;
    case OAKLEY_AES_CBC:
      return IKEv2_ENCR_AES_CBC;
    default:
      return 0;
    }
}

int v2tov1_encr_child(enum ikev2_trans_type_encr encr)
{
    switch(encr) {
    case IKEv2_ENCR_DES:
        return ESP_DES;
    case  IKEv2_ENCR_IDEA:
        return ESP_IDEA;
    case  IKEv2_ENCR_BLOWFISH:
        return ESP_BLOWFISH;
    case  IKEv2_ENCR_RC5:
        return ESP_RC5;
    case  IKEv2_ENCR_3DES:
        return ESP_3DES;
    case  IKEv2_ENCR_CAST:
        return ESP_CAST;
    case  IKEv2_ENCR_AES_CBC:
        return ESP_AES;
    default:
	return 0;
    }
}

int v2tov1_integ(enum ikev2_trans_type_integ v2integ)
{
     switch(v2integ) {
     case IKEv2_AUTH_HMAC_MD5_96:
         return OAKLEY_MD5;
     case IKEv2_AUTH_HMAC_SHA1_96:
         return OAKLEY_SHA1;
     case IKEv2_AUTH_HMAC_SHA2_256_128:
         return OAKLEY_SHA2_256;
     case IKEv2_AUTH_HMAC_SHA2_384_192:
         return OAKLEY_SHA2_384;
     case IKEv2_AUTH_HMAC_SHA2_512_256:
         return OAKLEY_SHA2_512;
     default:
         return -1;
     }
}

enum ikev2_trans_type_integ v1tov2_integ(int integ)
{
     switch(integ) {
     case IKEv2_AUTH_HMAC_MD5_96:
         return OAKLEY_MD5;
     case IKEv2_AUTH_HMAC_SHA1_96:
         return OAKLEY_SHA1;
     case IKEv2_AUTH_HMAC_SHA2_256_128:
         return OAKLEY_SHA2_256;
     case IKEv2_AUTH_HMAC_SHA2_384_192:
         return OAKLEY_SHA2_384;
     case IKEv2_AUTH_HMAC_SHA2_512_256:
         return OAKLEY_SHA2_512;
     default:
         return -1;
     }
}

int v2tov1_integ_child(enum ikev2_trans_type_integ v2integ)
{
    switch(v2integ) {
    case IKEv2_AUTH_HMAC_MD5_96:
        return AUTH_ALGORITHM_HMAC_MD5;
    case IKEv2_AUTH_HMAC_SHA1_96:
        return AUTH_ALGORITHM_HMAC_SHA1;
    case IKEv2_AUTH_HMAC_SHA2_256_128:
        return AUTH_ALGORITHM_HMAC_SHA2_256;
    case IKEv2_AUTH_HMAC_SHA2_384_192:
        return AUTH_ALGORITHM_HMAC_SHA2_384;
    case IKEv2_AUTH_HMAC_SHA2_512_256:
        return AUTH_ALGORITHM_HMAC_SHA2_512;
    default:
        return IKEv2_AUTH_INVALID;
   }
}

static void
kernel_alg_policy_algorithms(struct esp_info *esp_info)
{
    int ealg_i=esp_info->esp_ealg_id;
    switch(ealg_i) {
        case 0:
        case ESP_DES:
        case ESP_3DES:
        case ESP_NULL:
        case ESP_CAST:
            break;
        default:
            if (!esp_info->esp_ealg_keylen) {
                /**
                 * algos that need  KEY_LENGTH
                 *
                 * Note: this is a very dirty hack ;-)
                 *
                 * XXX:jjo
                 * Idea: Add a key_length_needed attribute to
                 * esp_ealg ??
                 */
                esp_info->esp_ealg_keylen=
                    esp_ealg[ealg_i].sadb_alg_maxbits;

            }
    }
}

static bool
kernel_alg_db_add(struct db_context *db_ctx
		  , struct esp_info *esp_info
		  , lset_t policy
		  , bool logit)
{
	int ealg_i=0, aalg_i;

	if(policy & POLICY_ENCRYPT) {
	    ealg_i=esp_info->esp_ealg_id;
	    if (!ESP_EALG_PRESENT(ealg_i)) {
		if(logit) {
		    openswan_loglog(RC_LOG_SERIOUS
				    , "requested kernel enc ealg_id=%d not present"
				    , ealg_i);
		} else {
		    DBG_log("requested kernel enc ealg_id=%d not present", ealg_i);
		}
		return FALSE;
	    }
	}

	aalg_i=alg_info_esp_aa2sadb(esp_info->esp_aalg_id);
	if (!ESP_AALG_PRESENT(aalg_i)) {
	    DBG_log("kernel_alg_db_add() kernel auth "
		    "aalg_id=%d not present",
		    aalg_i);
	    return FALSE;
	}

	/* 	do algo policy */
	kernel_alg_policy_algorithms(esp_info);

	if(policy & POLICY_ENCRYPT) {
	    /*	open new transformation */
	    db_trans_add(db_ctx, ealg_i);

            /* XXX-MCR todo: needs to handle IKEV2 now as well  #3949  */
	    /* add ESP auth attr (if present) */
	    if (esp_info->esp_aalg_id != AUTH_ALGORITHM_NONE) {
		db_attr_add_values(db_ctx,
				   AUTH_ALGORITHM, esp_info->esp_aalg_id);
	    }

	    /*	add keylegth if specified in esp= string */
	    if (esp_info->esp_ealg_keylen) {

		if(esp_info->esp_ealg_id == ESP_AES_GCM_8
			|| esp_info->esp_ealg_id == ESP_AES_GCM_12
			|| esp_info->esp_ealg_id == ESP_AES_GCM_16 ) {

			db_attr_add_values(db_ctx,
				   KEY_LENGTH, esp_info->esp_ealg_keylen - 4 * BITS_PER_BYTE);
		}
		else {
			db_attr_add_values(db_ctx,
				KEY_LENGTH, esp_info->esp_ealg_keylen );
		}
	    }

	} else if(policy & POLICY_AUTHENTICATE) {
	    /*	open new transformation */
	    db_trans_add(db_ctx, aalg_i);

	    /* add ESP auth attr */
	    db_attr_add_values(db_ctx,
			       AUTH_ALGORITHM, esp_info->esp_aalg_id);

	}

	return TRUE;
}

/*
 *	Create proposal with runtime kernel algos, merging
 *	with passed proposal if not NULL
 *
 *	for now this function does free() previous returned
 *	malloced pointer (this quirk allows easier spdb.c change)
 */
struct db_context *
kernel_alg_db_new(struct alg_info_esp *alg_info, lset_t policy, bool logit)
{
    int ealg_i, aalg_i;
    unsigned int tn=0;
	int i;
	const struct esp_info *esp_info;
	struct esp_info tmp_esp_info;
	struct db_context *ctx_new=NULL;
	struct db_trans *t;
	struct db_prop  *prop;
	unsigned int trans_cnt = 0;
	bool success = TRUE;
	int protoid = 0;

	if(policy & POLICY_ENCRYPT) {
	    trans_cnt=(esp_ealg_num*esp_aalg_num);
	    protoid = PROTO_IPSEC_ESP;
	} else if(policy & POLICY_AUTHENTICATE) {
	    trans_cnt=esp_aalg_num;
	    protoid = PROTO_IPSEC_AH;
	}

	DBG(DBG_EMITTING, DBG_log("kernel_alg_db_new() "
		"initial trans_cnt=%d",
		trans_cnt));

	/*	pass aprox. number of transforms and attributes */
	ctx_new = db_prop_new(protoid, trans_cnt, trans_cnt * 2);

	/*
	 * 	Loop: for each element (struct esp_info) of
	 * 	alg_info, if kernel support is present then
	 * 	build the transform (and attrs)
	 *
	 * 	if NULL alg_info, propose everything ...
	 */

	/* passert(alg_info!=0); */
	if (alg_info) {
		ALG_INFO_ESP_FOREACH(alg_info, esp_info, i) {
		    bool thistime;
		    tmp_esp_info = *esp_info;
		    thistime = kernel_alg_db_add(ctx_new
						 , &tmp_esp_info
						 , policy, logit);
		    if(thistime == FALSE) {
			success=FALSE;
		    }
		}
	} else {
		ESP_EALG_FOR_EACH_UPDOWN(ealg_i) {
			tmp_esp_info.esp_ealg_id=ealg_i;
			tmp_esp_info.esp_ealg_keylen=0;
			ESP_AALG_FOR_EACH(aalg_i) {
				tmp_esp_info.esp_aalg_id=alg_info_esp_sadb2aa(aalg_i);
				tmp_esp_info.esp_aalg_keylen=0;
				kernel_alg_db_add(ctx_new, &tmp_esp_info
						  , policy, FALSE);
			}
		}
	}

	if(success == FALSE) {
	    /* NO algorithms were found. oops */
	    db_destroy(ctx_new);
	    return NULL;
	}


	prop=db_prop_get(ctx_new);

	DBG(DBG_CONTROL|DBG_EMITTING, DBG_log("kernel_alg_db_new() "
		"will return p_new->protoid=%d, p_new->trans_cnt=%d",
		prop->protoid, prop->trans_cnt));

	for(t=prop->trans,tn=0;
	    t!= NULL && t[tn].transid != 0 && tn<prop->trans_cnt;
	    tn++) {
	    DBG(DBG_CONTROL|DBG_EMITTING,
		DBG_log("kernel_alg_db_new() "
			"    trans[%d]: transid=%d, attr_cnt=%d, "
			"attrs[0].type=%d, attrs[0].val=%d"
			, tn
			, t[tn].transid, t[tn].attr_cnt
			, t[tn].attrs ? t[tn].attrs[0].type.ipsec : 255
			, t[tn].attrs ? t[tn].attrs[0].val : 255
			));
	}
	prop->trans_cnt = tn;

	return ctx_new;
}

