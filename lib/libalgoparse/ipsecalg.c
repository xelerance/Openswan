/*
 * Algorithm info parsing and creation functions
 * Reworked into openswan 2.x by Michael Richardson <mcr@xelerance.com>
 * (C)opyright 2017 Michael Richardson <mcr@xelerance.com>
 * (C)opyright 2012 Paul Wouters <pwouters@redhat.com>
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
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
 */
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>

#include <ctype.h>
#include <openswan.h>
#include <openswan/ipsec_policy.h>
#include <openswan/passert.h>
#include <openswan/pfkeyv2.h>

#include "constants.h"
#include "alg_info.h"
#include "oswlog.h"
#include "oswalloc.h"
#include "algparse.h"

#ifdef HAVE_LIBNSS
#include "oswconf.h"
#endif

/* abstract reference */
struct oakley_group_desc;

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

int /* __attribute__ ((unused)) */
alg_info_esp_sadb2aa(int sadb_aalg)
{
	int auth=0;
	switch(sadb_aalg) {
		/* Paul: why is this using a mix of SADB_AALG_* and AUTH_ALGORITHM_* */
		case SADB_AALG_MD5HMAC:
		case SADB_AALG_SHA1HMAC:
			auth=sadb_aalg-1;
			break;
			/* since they are the same ...  :)  */
		case AUTH_ALGORITHM_HMAC_SHA2_256:
		case AUTH_ALGORITHM_HMAC_SHA2_384:
		case AUTH_ALGORITHM_HMAC_SHA2_512:
		case AUTH_ALGORITHM_HMAC_RIPEMD:
			auth=sadb_aalg;
			break;
		default:
			/* loose ... */
			auth=sadb_aalg;
	}
	return auth;
}

/*
 *	Raw add routine: only checks for no duplicates
 */
static void
__alg_info_esp_add (struct alg_info_esp *alg_info
		    , int ealg_id, unsigned ek_bits
		    , int aalg_id, unsigned ak_bits)
{
	struct esp_info *esp_info=alg_info->esp;
	unsigned cnt=alg_info->alg_info_cnt, i;
	/* 	check for overflows 	*/
	passert(cnt < elemsof(alg_info->esp));
	/*	dont add duplicates	*/
	for (i=0;i<cnt;i++)
		if (	esp_info[i].esp_ealg_id==ealg_id &&
			(!ek_bits || esp_info[i].esp_ealg_keylen==ek_bits) &&
			esp_info[i].esp_aalg_id==aalg_id &&
			(!ak_bits || esp_info[i].esp_aalg_keylen==ak_bits))
			return;
	esp_info[cnt].esp_ealg_id=ealg_id;
	esp_info[cnt].esp_ealg_keylen=ek_bits;
	esp_info[cnt].esp_aalg_id=aalg_id;
	esp_info[cnt].esp_aalg_keylen=ak_bits;
	/* sadb values */
	alg_info->alg_info_cnt++;
	DBG(DBG_CRYPT, DBG_log("__alg_info_esp_add() "
				"ealg=%d aalg=%d cnt=%d",
				ealg_id, aalg_id, alg_info->alg_info_cnt));
}

/*
 *	Add ESP alg info _with_ logic (policy):
 */
void
alg_info_esp_add (struct alg_info *alg_info,
		  enum ikev2_trans_type_encr  ealg_id, int ek_bits,
		  enum ikev2_trans_type_integ aalg_id, int ak_bits,
                  enum ikev2_trans_type_prf   prfalg_id UNUSED,
		  enum ikev2_trans_type_dh    modp_id)
{
    /*	Policy: default to AES_CBC */
    if (ealg_id==0)
        ealg_id=IKEv2_ENCR_AES_CBC;

    if (ealg_id>0) {
        if(aalg_id > 0) {
            if (aalg_id == INT_MAX)
                aalg_id = 0;
            __alg_info_esp_add((struct alg_info_esp *)alg_info,
                               ealg_id, ek_bits,
                               aalg_id, ak_bits);
        } else  {
            /*	Policy: default to SHA256 and SHA1 */
            __alg_info_esp_add((struct alg_info_esp *)alg_info,
                               ealg_id, ek_bits,
                               IKEv2_AUTH_HMAC_SHA2_256_128, 128);
            __alg_info_esp_add((struct alg_info_esp *)alg_info,
                               ealg_id, ek_bits,
                               IKEv2_AUTH_HMAC_SHA1_96, 128);
        }
    }
}

/*
 *	Add AH alg info _with_ logic (policy):
 */
void
alg_info_ah_add (struct alg_info *alg_info,
                 enum ikev2_trans_type_encr  ealg_id, int ek_bits,
                 enum ikev2_trans_type_integ aalg_id, int ak_bits,
                 enum ikev2_trans_type_prf   prfalg_id UNUSED,
                 enum ikev2_trans_type_dh    modp_id)
{
    ealg_id = 0;  /* AH has no encryption */

    if(aalg_id > 0)
        {
            __alg_info_esp_add((struct alg_info_esp *)alg_info,
                               0, 0,
                               aalg_id, ak_bits);
        }
    else
        {
            /*	Policy: default to SHA256 and SHA1 */
            __alg_info_esp_add((struct alg_info_esp *)alg_info,
                               0,0,
                               IKEv2_AUTH_HMAC_SHA2_256_128, 128);
            __alg_info_esp_add((struct alg_info_esp *)alg_info,
                               0,0,
                               IKEv2_AUTH_HMAC_SHA1_96, 128);
    }
}

struct alg_info_esp *
alg_info_esp_defaults(void)
{
    struct alg_info_esp *esp_info;

    esp_info=alloc_thing (struct alg_info_esp, "alg_info_esp");
    if (!esp_info) goto out;
    esp_info->alg_info_protoid=PROTO_ISAKMP;

    /* call with all zeros, to get entire default permutation */
    alg_info_esp_add (ESPTOINFO(esp_info),0,0,
                      0,0,
                      0,0);
 out:
    return esp_info;
}




/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
