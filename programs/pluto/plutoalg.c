/*
 * Kernel runtime algorithm handling interface definitions
 * Originally by: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Reworked into openswan 2.x by Michael Richardson <mcr@xelerance.com>
 * (C)opyright 2012 Paul Wouters <pwouters@redhat.com>
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
#include "defs.h"
#include "id.h"
#include "connections.h"
#include "state.h"
#include "kernel_alg.h"
#include "alg_info.h"
#include "ike_alg.h"
#include "plutoalg.h"
#include "crypto.h"
#include "spdb.h"
#include "db_ops.h"
#include "log.h"
#include "whack.h"

/**
 * 	Search oakley_enc_names for a match, eg:
 * 		"3des_cbc" <=> "OAKLEY_3DES_CBC"
 *
 * @param str String containing ALG name (eg: AES, 3DES)
 * @param len Length of ALG (eg: 256,512)
 * @return int Registered # of ALG if loaded.
 */
static int
ealg_getbyname_ike(const char *const str, int len)
{
	int ret=-1;
	if (!str||!*str)
		goto out;
	ret=alg_enum_search_prefix(&oakley_enc_names,"OAKLEY_",str,len);
	if (ret>=0) goto out;
	ret=alg_enum_search_ppfix(&oakley_enc_names, "OAKLEY_", "_CBC", str, len);
out:
	return ret;
}
/**
 * 	Search  oakley_hash_names for a match, eg:
 * 		"md5" <=> "OAKLEY_MD5"
 * @param str String containing Hash name (eg: MD5, SHA1)
 * @param len Length of Hash (eg: 256,512)
 * @return int Registered # of Hash ALG if loaded.
 */
static int
aalg_getbyname_ike(const char *const str, int len)
{
	int ret=-1;
	unsigned num;
	if (!str||!*str)
		goto out;
	ret=alg_enum_search_prefix(&oakley_hash_names,"OAKLEY_",str,len);
	if (ret>=0) goto out;
	sscanf(str, "id%d%n", &ret, &num);
	if (ret >=0 && num!=strlen(str))
		ret=-1;
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
static int
modp_getbyname_ike(const char *const str, int len)
{
	int ret=-1;
	if (!str||!*str)
		goto out;
	ret=alg_enum_search_prefix(&oakley_group_names,"OAKLEY_GROUP_",str,len);
	if (ret>=0) goto out;
	ret=alg_enum_search_ppfix(&oakley_group_names, "OAKLEY_GROUP_", " (extension)", str, len);
out:
	return ret;
}

static void
__alg_info_ike_add (struct alg_info_ike *alg_info, int ealg_id, unsigned ek_bits, int aalg_id, unsigned ak_bits, unsigned int modp_id)
{
	struct ike_info *ike_info=alg_info->ike;
	unsigned cnt=alg_info->alg_info_cnt, i;
	/* 	check for overflows 	*/
	passert(cnt < elemsof(alg_info->ike));
	/*	dont add duplicates	*/
	for (i=0;i<cnt;i++)
		if (	ike_info[i].ike_ealg==ealg_id &&
			(!ek_bits || ike_info[i].ike_eklen==ek_bits) &&
			ike_info[i].ike_halg==aalg_id &&
			(!ak_bits || ike_info[i].ike_hklen==ak_bits) &&
			ike_info[i].ike_modp==modp_id
		   )
			return;
	ike_info[cnt].ike_ealg=ealg_id;
	ike_info[cnt].ike_eklen=ek_bits;
	ike_info[cnt].ike_halg=aalg_id;
	ike_info[cnt].ike_hklen=ak_bits;
	ike_info[cnt].ike_modp=modp_id;
	alg_info->alg_info_cnt++;
	DBG(DBG_CRYPT, DBG_log("__alg_info_ike_add() "
				"ealg=%d aalg=%d modp_id=%d, cnt=%d",
				ealg_id, aalg_id, modp_id,
				alg_info->alg_info_cnt));
}

/*
 * 	Proposals will be built by looping over default_ike_groups array and
 * 	merging alg_info (ike_info) contents
 */
static int default_ike_groups[] = {
	OAKLEY_GROUP_MODP1536,
	OAKLEY_GROUP_MODP1024
};

/*
 *	Add IKE alg info _with_ logic (policy):
 */
static void
alg_info_ike_add (struct alg_info *alg_info
		  , int ealg_id, int ek_bits
		  , int aalg_id, int ak_bits
		  , int modp_id, int permitmann UNUSED)
{
	int i=0, n_groups;
	n_groups=elemsof(default_ike_groups);
	/* if specified modp_id avoid loop over default_ike_groups */
	if (modp_id) {
		n_groups=0;
		goto in_loop;
	}

	for (;n_groups--;i++) {
		modp_id=default_ike_groups[i];
in_loop:
		/*	Policy: default to 3DES */
		if (ealg_id==0)
			ealg_id=OAKLEY_3DES_CBC;
		if (ealg_id>0) {
			if (aalg_id>0)
				__alg_info_ike_add((struct alg_info_ike *)alg_info,
						ealg_id, ek_bits,
						aalg_id, ak_bits,
						modp_id);
			else {
				/*	Policy: default to MD5 and SHA */
				__alg_info_ike_add((struct alg_info_ike *)alg_info,
						ealg_id, ek_bits, \
						OAKLEY_MD5, ak_bits, modp_id);
				__alg_info_ike_add((struct alg_info_ike *)alg_info,
						ealg_id, ek_bits, \
						OAKLEY_SHA, ak_bits, modp_id);
			}
		}
	}
}


/*
 * print which ESP algorithm has actually been selected, based upon which
 * ones are actually loaded.
 */
int
alg_info_snprint_esp(char *buf, int buflen, struct alg_info_esp *alg_info)
{
	char *ptr=buf;
	int ret;
	struct esp_info *esp_info;
	int cnt;
	int eklen, aklen;
	const char *sep="";

	ptr=buf;

	buf[0]=0; strncat(buf, "none", buflen);

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
	    ptr+=ret;
	    buflen-=ret;
	    if (buflen<0) break;

	    sep = ", ";
	}
	return ptr-buf;
}

/*
 * print which AH algorithm has actually been selected, based upon which
 * ones are actually loaded.
 */
int
alg_info_snprint_ah(char *buf, int buflen, struct alg_info_esp *alg_info)
{
	char *ptr=buf;
	int ret;
	struct esp_info *esp_info;
	int cnt;
	int aklen;
	const char *sep="";

	ptr=buf;

	buf[0]=0; strncat(buf, "none", buflen);

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
	    ptr+=ret;
	    buflen-=ret;
	    if (buflen<0) break;

	    sep = ", ";
	}
	return ptr-buf;
}

int
alg_info_snprint_phase2(char *buf, int buflen, struct alg_info_esp *alg_info)
{
    switch(alg_info->alg_info_protoid) {
    case PROTO_IPSEC_ESP:
	return alg_info_snprint_esp(buf, buflen, alg_info);
    case PROTO_IPSEC_AH:
	return alg_info_snprint_ah(buf, buflen, alg_info);
    default:
	bad_case(alg_info->alg_info_protoid);
    }
}


char *alg_info_snprint_ike1(struct ike_info *ike_info
			    , int eklen, int aklen
			    , char *buf
			    , int buflen)
{
    snprintf(buf, buflen-1, "%s(%d)_%03d-%s(%d)_%03d-%s(%d)"
	     , enum_name(&oakley_enc_names, ike_info->ike_ealg)+ sizeof("OAKLEY")
	     , ike_info->ike_ealg, eklen
	     , enum_name(&oakley_hash_names, ike_info->ike_halg)+ sizeof("OAKLEY")
	     , ike_info->ike_halg, aklen
	     , enum_name(&oakley_group_names, ike_info->ike_modp)+ sizeof("OAKLEY_GROUP")
	     , ike_info->ike_modp);
    return buf;
}

int
alg_info_snprint_ike(char *buf, int buflen, struct alg_info_ike *alg_info)
{
	char *ptr=buf;
	int ret;
	struct ike_info *ike_info;
	int cnt;
	int eklen, aklen;
	const char *sep="";
	struct encrypt_desc *enc_desc;
	struct hash_desc *hash_desc;

	ALG_INFO_IKE_FOREACH(alg_info, ike_info, cnt) {
	    if (ike_alg_enc_present(ike_info->ike_ealg)
		&& (ike_alg_hash_present(ike_info->ike_halg))
		&& (lookup_group(ike_info->ike_modp))) {

		enc_desc=ike_alg_get_encrypter(ike_info->ike_ealg);
		passert(enc_desc != NULL);
		hash_desc=ike_alg_get_hasher(ike_info->ike_halg);
		passert(hash_desc != NULL);

		eklen=ike_info->ike_eklen;
		if (!eklen)
		    eklen=enc_desc->keydeflen;
		aklen=ike_info->ike_hklen;
		if (!aklen)
		    aklen=hash_desc->hash_digest_len * BITS_PER_BYTE;
		ret=snprintf(ptr, buflen, "%s%s(%d)_%03d-%s(%d)_%03d-%s(%d)"
			     , sep
			     , enum_name(&oakley_enc_names, ike_info->ike_ealg)+sizeof("OAKLEY")
			     , ike_info->ike_ealg, eklen
			     , enum_name(&oakley_hash_names, ike_info->ike_halg)+sizeof("OAKLEY")
			     , ike_info->ike_halg, aklen
			     , enum_name(&oakley_group_names, ike_info->ike_modp)+sizeof("OAKLEY_GROUP")
			     , ike_info->ike_modp);
		ptr+=ret;
		buflen-=ret;
		if (buflen<0) break;

		sep = ", ";
	    }
	}
	return ptr-buf;
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
    p_ctx->state=ST_INI;
    p_ctx->ealg_getbyname=ealg_getbyname_ike;
    p_ctx->aalg_getbyname=aalg_getbyname_ike;
    p_ctx->modp_getbyname=modp_getbyname_ike;
    p_ctx->ealg_permit=TRUE;
    p_ctx->aalg_permit=TRUE;
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
			       lookup_group,
			       TRUE) < 0)
	{
		pfreeany(alg_info_ike);
		alg_info_ike=NULL;
	}
out:
	return alg_info_ike;
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

void kernel_alg_show_status(void)
{
	unsigned sadb_id,id;
	struct sadb_alg *alg_p;
	ESP_EALG_FOR_EACH(sadb_id) {
		id=sadb_id;
		alg_p=&esp_ealg[sadb_id];
		whack_log(RC_COMMENT, "algorithm ESP encrypt: id=%d, name=%s, "
				"ivlen=%d, keysizemin=%d, keysizemax=%d"
			, id
			, enum_name(&esp_transformid_names, id)
			, alg_p->sadb_alg_ivlen
			, alg_p->sadb_alg_minbits
			, alg_p->sadb_alg_maxbits
		 );

	}
	ESP_AALG_FOR_EACH(sadb_id) {
		id=alg_info_esp_sadb2aa(sadb_id);
		alg_p=&esp_aalg[sadb_id];
		whack_log(RC_COMMENT, "algorithm ESP auth attr: id=%d, name=%s, "
				"keysizemin=%d, keysizemax=%d"
			, id
			, enum_name(&auth_alg_names, id)
			, alg_p->sadb_alg_minbits
			, alg_p->sadb_alg_maxbits
		 );
	}
}
void
kernel_alg_show_connection(struct connection *c, const char *instance)
{
	char buf[1024];
	struct state *st;
	const char *satype;

	if(c->policy & POLICY_ENCRYPT) satype="ESP";
	else if(c->policy & POLICY_AUTHENTICATE) satype="AH";
	else satype="ESP+AH";

	if(c->alg_info_esp == NULL) return;

	if (c->alg_info_esp) {
	    alg_info_snprint(buf, sizeof(buf), (struct alg_info *)c->alg_info_esp, TRUE);
	    whack_log(RC_COMMENT
		      , "\"%s\"%s:   %s algorithms wanted: %s"
		      , c->name
		      , instance, satype
		      , buf);
	}

	if (c->alg_info_esp) {
	    alg_info_snprint_phase2(buf, sizeof(buf), c->alg_info_esp);
	    whack_log(RC_COMMENT
		      , "\"%s\"%s:   %s algorithms loaded: %s"
		      , c->name
		      , instance, satype
		      , buf);
	}

	st = state_with_serialno(c->newest_ipsec_sa);
	if (st && st->st_esp.present)
		whack_log(RC_COMMENT
		, "\"%s\"%s:   %s algorithm newest: %s_%03d-%s; pfsgroup=%s"
		, c->name
			  , instance, satype
		, enum_show(&esp_transformid_names
			    ,st->st_esp.attrs.transattrs.encrypt)
		+4 /* strlen("ESP_") */
		, st->st_esp.attrs.transattrs.enckeylen
		, enum_show(&auth_alg_names, st->st_esp.attrs.transattrs.integ_hash)+
		+15 /* strlen("AUTH_ALGORITHM_") */
		, c->policy & POLICY_PFS ?
			c->alg_info_esp->esp_pfsgroup ?
					enum_show(&oakley_group_names,
						c->alg_info_esp->esp_pfsgroup)
						+13 /*strlen("OAKLEY_GROUP_")*/
				: "<Phase1>"
			: "<N/A>"
		    );

	if (st && st->st_ah.present)
		whack_log(RC_COMMENT
		, "\"%s\"%s:   %s algorithm newest: %s; pfsgroup=%s"
		, c->name
			  , instance, satype
		, enum_show(&auth_alg_names, st->st_esp.attrs.transattrs.integ_hash)+
		+15 /* strlen("AUTH_ALGORITHM_") */
		, c->policy & POLICY_PFS ?
			c->alg_info_esp->esp_pfsgroup ?
					enum_show(&oakley_group_names,
						c->alg_info_esp->esp_pfsgroup)
						+13 /*strlen("OAKLEY_GROUP_")*/
				: "<Phase1>"
			: "<N/A>"
	);

}

struct db_sa *
kernel_alg_makedb(lset_t policy, struct alg_info_esp *ei, bool logit)
{
    struct db_context *dbnew;
    struct db_prop *p;
    struct db_prop_conj pc;
    struct db_sa t, *n;

    memset(&t, 0, sizeof(t));

    if(ei == NULL) {
	struct db_sa *sadb;
	lset_t pm = POLICY_ENCRYPT | POLICY_AUTHENTICATE;

#if 0
y	if (can_do_IPcomp)
	    pm |= POLICY_COMPRESS;
#endif

	sadb = &ipsec_sadb[(policy & pm) >> POLICY_IPSEC_SHIFT];

	/* make copy, to keep from freeing the static policies */
	sadb = sa_copy_sa(sadb, 0);
	sadb->parentSA = FALSE;

	DBG(DBG_CONTROL, DBG_log("empty esp_info, returning defaults"));
	return sadb;
    }

    dbnew=kernel_alg_db_new(ei, policy, logit);

    if(!dbnew) {
	DBG(DBG_CONTROL, DBG_log("failed to translate esp_info to proposal, returning empty"));
	return NULL;
    }

    p = db_prop_get(dbnew);

    if(!p) {
	DBG(DBG_CONTROL, DBG_log("failed to get proposal from context, returning empty"));
	db_destroy(dbnew);
	return NULL;
    }

    pc.prop_cnt = 1;
    pc.props = p;
    t.prop_conj_cnt = 1;
    t.prop_conjs = &pc;

    /* make a fresh copy */
    n = sa_copy_sa(&t, 0);
    n->parentSA = FALSE;

    db_destroy(dbnew);

    DBG(DBG_CONTROL
	, DBG_log("returning new proposal from esp_info"));
    return n;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
