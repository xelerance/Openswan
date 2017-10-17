/*
 * Kernel runtime algorithm handling interface definitions
 * Originally by: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Reworked into openswan 2.x by Michael Richardson <mcr@xelerance.com>
 * (C)opyright 2017 Michael Richardson <mcr@xelerance.com>
 * (C)opyright 2012 Paul Wouters <pwouters@redhat.com>
 * (C)opyright 2012 Paul Wouters <paul@libreswan.org>
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

#include <sys/types.h>
#include <stdlib.h>
#include <openswan.h>
#include <openswan/pfkeyv2.h>
#include <openswan/passert.h>
#include <openswan/ipsec_policy.h>

#include "sysdep.h"
#include "constants.h"
#include "oswlog.h"
#include "oswalloc.h"
#include "pluto/defs.h"
#include "id.h"
#include "pluto/connections.h"
#include "kernel_alg.h"
#include "alg_info.h"
#include "pluto/ike_alg.h"
#include "pluto/plutoalg.h"
#include "pluto/crypto.h"
#include "oswlog.h"
#include "algparse.h"
#include "enum_names.h"


/**
 * 	Search  prf_hash_names for a match, eg:
 * 		"md5" <=> "PRFMD5"
 * @param str String containing Hash name (eg: MD5, SHA1)
 * @param len Length of Hash (eg: 256,512)
 * @return int Registered # of Hash ALG if loaded.
 */
static int
prfalg_getbyname_ike(const char *const str, const int len, unsigned int *auxp)
{
	int ret=-1;
        int algo=0;
	unsigned num;
	if (!str||!*str)
            goto out;

        /* look for the name by literal name, upcasing first */
	ret = enum_search_nocase(&ikev2_prf_names, str, len);
	if (ret>=0) goto out;

        ret = keyword_search(&ikev2_prf_alg_names.aliases, str);
	if (ret>=0) goto out;
        if(strncasecmp(str, "prf", 3)==0) {
            ret = keyword_search(&ikev2_prf_alg_names.aliases, str+3);
            if (ret>=0) goto out;
        }

        /* finally, try the name again with "prf" pre-pended to it */
        {
            char *prfname = alloca(len + 4);
            if(prfname) {
                strcpy(prfname, "prf");
                strncat(prfname, str, len);
                ret = enum_search_nocase(&ikev2_prf_names, prfname, strlen(prfname));
                if (ret>=0) goto out;
            }
        }

        /* let the user override with an explicit number! */
        /* extract length that was consumed to check that it fit */
	sscanf(str, "prf%d%n", &algo, &num);
	if (algo >=0 && num == len) {
            ret = algo;
        }

out:
	return ret;
}

/**
 * 	Search oakley_group_names for a match, eg:
 * 		"modp1024" <=> "OAKLEY_GROUP_MODP1024"
 * @param str String MODP Name (eg: MODP)
 * @param len Length of Hash (eg: 1024,1536,2048)
 * @return int Registered # of MODP Group, if supported.
 */
int
modp_getbyname_ike(const char *const str, int len, unsigned int *auxp)
{
	int ret=-1;
	if (!str||!*str)
		goto out;
	ret=alg_enum_search_prefix(ikev2_group_names.official_names,
                                   "OAKLEY_GROUP_",str,len);
	if (ret>=0) goto out;

        /* finally, look for aliases. */
        ret = keyword_search(&ikev2_group_names.aliases, str);
	if (ret>=0) goto out;

out:
	return ret;
}

static void
__alg_info_ike_add (struct alg_info_ike *alg_info,
                    int ealg_id, unsigned ek_bits,
                    int aalg_id, unsigned ak_bits,
                    int prfalg_id,
                    unsigned int modp_id)
{
	struct ike_info *ike_info=alg_info->ike;
	unsigned cnt=alg_info->alg_info_cnt, i;
	/* 	check for overflows 	*/
	passert(cnt < elemsof(alg_info->ike));
	/*	dont add duplicates	*/

        /* search for a duplicate entry, and if found, return immediately */
	for (i=0;i<cnt;i++) {
            if (ike_info[i].ike_ealg==ealg_id
                && (!ek_bits || ike_info[i].ike_eklen==ek_bits)
                && ike_info[i].ike_halg==aalg_id
                && (!ak_bits || ike_info[i].ike_hklen==ak_bits)
                && ike_info[i].ike_modp==modp_id) {
                return;
            }
        }

	ike_info[cnt].ike_ealg=ealg_id;
	ike_info[cnt].ike_eklen=ek_bits;
	ike_info[cnt].ike_halg=aalg_id;
	ike_info[cnt].ike_hklen=ak_bits;
	ike_info[cnt].ike_prfalg=prfalg_id;
	ike_info[cnt].ike_modp=modp_id;
	alg_info->alg_info_cnt++;

	DBG(DBG_CRYPT, DBG_log("__alg_info_ike_add() "
                               "ealg=%d aalg=%d prfalg_id=%d modp_id=%d, cnt=%d",
                               ealg_id, aalg_id, prfalg_id, modp_id,
                               alg_info->alg_info_cnt));
}

/*
 * 	Proposals will be built by looping over default_ike_groups array and
 * 	merging alg_info (ike_info) contents
 *
 * defaults according to:  https://datatracker.ietf.org/doc/RFC8247
 */
static int default_ike_groups[] = {
    OAKLEY_GROUP_MODP2048,          /* MUST */
    /* OAKLEY_GROUP_ECP256, */
#if 0
    OAKLEY_GROUP_X25519,            /* EdDSA */
#endif
    OAKLEY_GROUP_MODP1536,          /* SHOULD NOT, needed for backwards compatible */
    OAKLEY_GROUP_MODP3072,          /* included for future proofing */
    /* OAKLEY_GROUP_ECP384, */
    /* OAKLEY_GROUP_ECP512, */
};

static int default_prf_algs[] = {
    IKEv2_PRF_HMAC_SHA2_256,        /* MUST */
    IKEv2_PRF_HMAC_SHA2_512,        /* SHOULD+ */
    IKEv2_PRF_HMAC_SHA1             /* SHOULD- */
};
static int default_integ_algs[] = {
    IKEv2_AUTH_HMAC_SHA2_256_128,
    IKEv2_AUTH_HMAC_SHA1_96,
};
static int default_cipher_algs[] = {
    IKEv2_ENCR_AES_CBC,
    IKEv2_ENCR_AES_GCM_8,          /* IoT SHOULD */
};

/*
 *	Add IKE alg info _with_ logic (policy):
 */
static void
alg_info_ike_add (struct alg_info *alg_info
		  , int ealg_id, int ek_bits
		  , int aalg_id, int ak_bits
                  , int prfalg_id
		  , int modp_id)
{
    int n_groups, n_prfs, n_integs, n_ciphers;
    int i_group, i_prf, i_integ, i_cipher;
    int *groups, *prfs, *integs, *ciphers;

    n_groups=elemsof(default_ike_groups);
    groups  =default_ike_groups;
    n_prfs  =elemsof(default_prf_algs);
    prfs    =default_prf_algs;
    n_integs=elemsof(default_integ_algs);
    integs  =default_integ_algs;
    n_ciphers=elemsof(default_cipher_algs);
    ciphers =default_cipher_algs;

    /* for each item that is in fact specified, do not loop over the defaults */
    if(modp_id > 0) {
        n_groups=1;
        groups = &modp_id;
    }
    if(prfalg_id > 0) {
        n_prfs=1;
        prfs  = &prfalg_id;
    }
    if(aalg_id  > 0) {
        n_integs = 1;
        integs= &aalg_id;
    }
    if(ealg_id  > 0) {
        n_ciphers = 1;
        ciphers = &ealg_id;
    }

    for (i_group=0; i_group < n_groups; i_group++) {
        int x_modp_id = groups[i_group];

        for(i_prf=0; i_prf < n_prfs; i_prf++) {
            int x_prf_id = prfs[i_prf];

            for(i_integ=0; i_integ < n_integs; i_integ++) {
                int x_integ = integs[i_integ];

                for(i_cipher=0; i_cipher < n_ciphers; i_cipher++) {
                    int x_cipher = ciphers[i_cipher];

                    __alg_info_ike_add((struct alg_info_ike *)alg_info,
                                       x_cipher, ek_bits,
                                       x_integ,  ak_bits,
                                       x_prf_id, x_modp_id);
		}
            }
        }
    }

}


/*
 * print which ESP algorithm has actually been selected, based upon which
 * ones are actually loaded.
 */
static void
alg_info_snprint_esp(char *buf, size_t buflen, struct alg_info_esp *alg_info)
{
	char *ptr=buf;
	int ret;
	struct esp_info *esp_info;
	int cnt;
	int eklen, aklen;
	const char *sep="";

	passert(buflen >= sizeof("none"));

	ptr=buf;
	buf[0]=0;
	strncat(buf, "none", buflen - 1);

	ALG_INFO_ESP_FOREACH(alg_info, esp_info, cnt) {
	    if (kernel_alg_esp_enc_ok(esp_info->esp_ealg_id, 0, NULL)) {
		DBG_log("esp algid=%d not available", esp_info->esp_ealg_id);
		continue;
	    }

	    if (kernel_alg_esp_auth_ok(esp_info->esp_aalg_id, NULL)) {
		DBG_log("auth algid=%d not available", esp_info->esp_aalg_id);
		continue;
	    }

	    eklen=esp_info->esp_ealg_keylen;
	    if (!eklen)
		eklen=kernel_alg_esp_enc_keylen(esp_info->esp_ealg_id)*BITS_PER_BYTE;
	    aklen=esp_info->esp_aalg_keylen;
	    if (!aklen)
		aklen=kernel_alg_esp_auth_keylen(esp_info->esp_aalg_id)*BITS_PER_BYTE;

	    ret=snprintf(ptr, buflen, "%s%s(%d)_%03d-%s(%d)_%03d"
			 , sep
			 , enum_name(&esp_transformid_names, esp_info->esp_ealg_id)+sizeof("ESP")
			 , esp_info->esp_ealg_id, eklen
			 , enum_name(&auth_alg_names, esp_info->esp_aalg_id) + (esp_info->esp_aalg_id ? sizeof("AUTH_ALGORITHM_HMAC") : sizeof("AUTH_ALGORITHM"))
			 , esp_info->esp_aalg_id, aklen);

	    if ( ret < 0 || (size_t)ret >= buflen) {
		DBG_log("alg_info_snprint_esp: buffer too short for snprintf");
		break;
	    }
	    ptr+=ret;
	    buflen-=ret;
	    sep = ", ";
	}
}

/*
 * print which AH algorithm has actually been selected, based upon which
 * ones are actually loaded.
 */
static void
alg_info_snprint_ah(char *buf, size_t buflen, struct alg_info_esp *alg_info)
{
	char *ptr=buf;
	int ret;
	struct esp_info *esp_info;
	int cnt;
	int aklen;
	const char *sep="";

	passert(buflen >= sizeof("none"));
	ptr=buf;

	buf[0]=0;
	strncat(buf, "none", buflen - 1);

	ALG_INFO_ESP_FOREACH(alg_info, esp_info, cnt) {

	    if (kernel_alg_esp_auth_ok(esp_info->esp_aalg_id, NULL)) {
		DBG_log("auth algid=%d not available", esp_info->esp_aalg_id);
		continue;
	    }

	    aklen=esp_info->esp_aalg_keylen;
	    if (!aklen)
		aklen=kernel_alg_esp_auth_keylen(esp_info->esp_aalg_id)*BITS_PER_BYTE;

	    ret=snprintf(ptr, buflen, "%s%s(%d)_%03d"
			 , sep
			 , enum_name(&auth_alg_names, esp_info->esp_aalg_id)+sizeof("AUTH_ALGORITHM_HMAC")
			 , esp_info->esp_aalg_id, aklen);

	    if ( ret < 0 || (size_t)ret >= buflen) {
		DBG_log("alg_info_snprint_ah: buffer too short for snprintf");
		break;
	    }
	    ptr+=ret;
	    buflen-=ret;
	    sep = ", ";
	}
}

void
alg_info_snprint_phase2(char *buf, size_t buflen, struct alg_info_esp *alg_info)
{
    switch(alg_info->alg_info_protoid) {
    case PROTO_IPSEC_ESP:
	alg_info_snprint_esp(buf, buflen, alg_info);
	return;
    case PROTO_IPSEC_AH:
	alg_info_snprint_ah(buf, buflen, alg_info);
	return;
    default:
	bad_case(alg_info->alg_info_protoid);
    }
}


char *alg_info_snprint_ike2(struct ike_info *ike_info
			    , int eklen, int aklen
                            , int *usedsize
			    , char *buf
			    , int buflen)
{
    int ret;
    char *curbuf = buf;
    const int   totlen = buflen;
    const char *prfname  = enum_name(ikev2_prf_alg_names.official_names,ike_info->ike_prfalg);
    const char *modpname = enum_name(ikev2_group_names.official_names, ike_info->ike_modp);
    const char *encname  = enum_name(ikev2_encr_names.official_names,  ike_info->ike_ealg);
    const char *hashname = enum_name(ikev2_integ_names.official_names, ike_info->ike_halg);
    if(modpname != NULL) {
        modpname += sizeof("OAKLEY_GROUP_")-1;
    } else {
        modpname = "inv-modp";
    }
    assert(prfname != NULL);
    assert(ike_info!= NULL);
    if(eklen == 0) {
        ret = snprintf(curbuf, buflen-1, "%s(%d)"
                       , encname
                       , ike_info->ike_ealg);
    } else {
        ret = snprintf(curbuf, buflen-1, "%s(%d)_%03d"
                       , encname
                       , ike_info->ike_ealg, eklen);
    }
    if(ret <= 0)  return "invalid ikeinfo";
    curbuf += ret;
    buflen -= ret;

    if(aklen == 0) {
        ret = snprintf(curbuf, buflen-1, "-%s(%d)"
                       , hashname
                       , ike_info->ike_halg);
    } else {
        ret = snprintf(curbuf, buflen-1, "-%s(%d)_%03d"
                       , hashname
                       , ike_info->ike_halg, aklen);
    }
    if(ret <= 0)  return "invalid ikeinfo";
    curbuf += ret;
    buflen -= ret;

    ret = snprintf(curbuf, buflen-1, "-%s(%d)-%s(%d)"
                       , prfname, ike_info->ike_prfalg
                       , modpname
                       , ike_info->ike_modp);
    buflen -= ret;

    if(usedsize) *usedsize = (totlen - buflen);
    return buf;
}

void
alg_info_snprint_ike(char *buf, size_t buflen, struct alg_info_ike *alg_info)
{
	char *ptr=buf;
	int ret;
	struct ike_info *ike_info;
	int cnt;
	int eklen, aklen;
	const char *sep="";
	struct ike_encr_desc *enc_desc;
	struct ike_integ_desc *hash_desc;


	ALG_INFO_IKE_FOREACH(alg_info, ike_info, cnt) {
	    if (ike_alg_enc_present(ike_info->ike_ealg, ike_info->ike_eklen)
		&& (ike_alg_integ_present(ike_info->ike_halg, ike_info->ike_hklen))
		&& (ike_alg_prf_present(ike_info->ike_prfalg))
		&& (lookup_group(ike_info->ike_modp))) {

                passert(ike_info != NULL);

		enc_desc=ike_alg_get_encr(ike_info->ike_ealg);
		passert(enc_desc != NULL);
		hash_desc=ike_alg_get_integ(ike_info->ike_halg);
		passert(hash_desc != NULL);

		eklen=ike_info->ike_eklen;
		if (!eklen)
		    eklen=enc_desc->keydeflen;
		aklen=ike_info->ike_hklen;
		if (!aklen)
		    aklen=hash_desc->hash_digest_len * BITS_PER_BYTE;

                ret=snprintf(ptr, buflen, "%s", sep);
                if(ret >= 0 && ret <= buflen) {
                    ptr+= ret;  buflen-= ret;
                    alg_info_snprint_ike2(ike_info, eklen, aklen, &ret, ptr, buflen);
                }

		if ( ret < 0 || (size_t)ret >= buflen) {
		   DBG_log("alg_info_snprint_ike: buffer too short for algorithm list");
		   break;
		}
		ptr+=ret;
		buflen-=ret;
	    }
	}
}

/*
 *	Must be called for each "new" char, with new
 *	character in ctx.ch
 */
static void
parser_init_ike(struct parser_context *p_ctx)
{
    memset(p_ctx, 0, sizeof (*p_ctx));
    p_ctx->protoid=PROTO_ISAKMP;

    p_ctx->ealg_str=p_ctx->ealg_buf;
    p_ctx->aalg_str=p_ctx->aalg_buf;
    p_ctx->modp_str=p_ctx->modp_buf;
    p_ctx->prfalg_str=p_ctx->prfalg_buf;
    p_ctx->state=ST_INI;
    p_ctx->ealg_getbyname=ealg_getbyname;
    p_ctx->aalg_getbyname=aalg_getbyname;
    p_ctx->modp_getbyname=modp_getbyname;
    p_ctx->prfalg_getbyname=prfalg_getbyname_ike;
    p_ctx->ealg_permit=TRUE;
    p_ctx->aalg_permit=TRUE;
}

struct alg_info_ike *
alg_info_ike_defaults(void)
{
    struct alg_info_ike *ike_info;

    ike_info=alloc_thing (struct alg_info_ike, "alg_info_ike");
    if (!ike_info) goto out;
    ike_info->alg_info_protoid=PROTO_ISAKMP;

    /* call with all zeros, to get entire default permutation */
    alg_info_ike_add (IKETOINFO(ike_info),0,0,
                      0,0,
                      0,0);
 out:
    return ike_info;
}

struct alg_info_ike *
alg_info_ike_create_from_str (const char *alg_str, const char **err_p)
{
	struct alg_info_ike *alg_info_ike;
	/*
	 * 	alg_info storage should be sized dynamically
	 * 	but this may require 2passes to know
	 * 	transform count in advance.
	 */
	alg_info_ike=alloc_thing (struct alg_info_ike, "alg_info_ike");
	if (!alg_info_ike) goto out;
	alg_info_ike->alg_info_protoid=PROTO_ISAKMP;
	if (alg_info_parse_str((struct alg_info *)alg_info_ike,
			       alg_str, err_p,
			       parser_init_ike,
			       alg_info_ike_add,
			       lookup_group) < 0)
	{
		pfreeany(alg_info_ike);
		alg_info_ike=NULL;
	}
out:
	return alg_info_ike;
}

/*
 * ML: make F_STRICT logic consider enc,auth algorithms
 */
bool
kernel_alg_esp_ok_final(int ealg, unsigned int key_len, int aalg, struct alg_info_esp *alg_info)
{
	int ealg_insecure;
	/*
	 * key_len passed comes from esp_attrs read from peer
	 * For many older algoritms (eg 3DES) this key_len is fixed
	 * and get passed as 0.
	 * ... then get default key_len
	 */
	if (key_len == 0) key_len = kernel_alg_esp_enc_keylen(ealg) * BITS_PER_BYTE;

	/*
	 * simple test to toss low key_len, will accept it only
	 * if specified in "esp" string
	 */
	ealg_insecure=(key_len < 128) ;
	if (ealg_insecure ||
		(alg_info && alg_info->alg_info_flags & ALG_INFO_F_STRICT))
	{
		int i;
		struct esp_info *esp_info;
		if (alg_info) {
			ALG_INFO_ESP_FOREACH(alg_info, esp_info, i) {
				if ((esp_info->esp_ealg_id == ealg) &&
						((esp_info->esp_ealg_keylen==0) || (key_len==0) ||
						 (esp_info->esp_ealg_keylen==key_len)) &&
						(esp_info->esp_aalg_id == aalg)) {
#ifndef USE_1DES
					if (ealg_insecure)
						loglog(RC_LOG_SERIOUS, "You should NOT use insecure ESP algorithms [%s (%d)]!"
								, enum_name(&esp_transformid_names, ealg), key_len);
#endif
					return TRUE;
				}
			}
		}
		openswan_log("IPsec Transform [%s (%d), %s] refused due to %s",
			      enum_name(&esp_transformid_names, ealg), key_len,
			      enum_name(&auth_alg_names, aalg),
			      ealg_insecure ? "insecure key_len and enc. alg. not listed in \"esp\" string" : "strict flag");
		return FALSE;
	}
	return TRUE;
}


/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
