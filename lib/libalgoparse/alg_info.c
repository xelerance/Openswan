/*
 * Algorithm info parsing and creation functions
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
#include "enum_names.h"

#ifdef HAVE_LIBNSS
#include "oswconf.h"
#endif

/* abstract reference */
struct oakley_group_desc;

/* translate IKEv2 INTEG algorithm into IKEv2 PRF algorithm */
enum ikev2_trans_type_prf
alg_info_ikev2_integ2prf(enum ikev2_trans_type_integ integ)
{
    switch(integ) {
    case IKEv2_AUTH_KPDK_MD5:
    case IKEv2_AUTH_HMAC_MD5_128:
    case IKEv2_AUTH_HMAC_MD5_96:
        return(IKEv2_PRF_HMAC_MD5);

    case IKEv2_AUTH_HMAC_SHA1_160:
    case IKEv2_AUTH_HMAC_SHA1_96:
        return(IKEv2_PRF_HMAC_SHA1);

    case IKEv2_AUTH_AES_CMAC_96:
    case IKEv2_AUTH_AES_128_GMAC:
    case IKEv2_AUTH_AES_192_GMAC:
    case IKEv2_AUTH_AES_256_GMAC:
    case IKEv2_AUTH_AES_XCBC_96:
        return(IKEv2_PRF_AES128_XCBC);

    case IKEv2_AUTH_HMAC_SHA2_256_128:
	return(IKEv2_PRF_HMAC_SHA2_256);
    case IKEv2_AUTH_HMAC_SHA2_384_192:
	return(IKEv2_PRF_HMAC_SHA2_384);
    case IKEv2_AUTH_HMAC_SHA2_512_256:
	return(IKEv2_PRF_HMAC_SHA2_512);

    case IKEv2_AUTH_DES_MAC:
    case IKEv2_AUTH_NONE:
    default:
        bad_case(integ);
    }
    return 0;
}

/*
 * should change all algorithms to use IKEv2 numbers, and translate
 * at edges only
 */
enum ikev1_auth_attribute
alg_info_esp_v2tov1aa(enum ikev2_trans_type_integ ti)
{
    switch(ti) {
    case IKEv2_AUTH_NONE:
	return AUTH_ALGORITHM_NONE;
    case IKEv2_AUTH_HMAC_MD5_96:
	return AUTH_ALGORITHM_HMAC_MD5;
    case IKEv2_AUTH_HMAC_SHA1_96:
	return AUTH_ALGORITHM_HMAC_SHA1;
    case IKEv2_AUTH_HMAC_SHA2_256_128:
	return AUTH_ALGORITHM_HMAC_SHA2_256;
    case IKEv2_AUTH_HMAC_SHA2_256_128_TRUNCBUG:
	return AUTH_ALGORITHM_HMAC_SHA2_256_TRUNCBUG;
    case IKEv2_AUTH_HMAC_SHA2_384_192:
	return AUTH_ALGORITHM_HMAC_SHA2_256;
    case IKEv2_AUTH_HMAC_SHA2_512_256:
	return AUTH_ALGORITHM_HMAC_SHA2_256;

    /* invalid or not yet supported */
    case IKEv2_AUTH_DES_MAC:
    case IKEv2_AUTH_KPDK_MD5:
    case IKEv2_AUTH_AES_XCBC_96:
    case IKEv2_AUTH_INVALID:
    case IKEv2_AUTH_HMAC_MD5_128:
    case IKEv2_AUTH_HMAC_SHA1_160:
    case IKEv2_AUTH_AES_CMAC_96:
    case IKEv2_AUTH_AES_128_GMAC:
    case IKEv2_AUTH_AES_192_GMAC:
    case IKEv2_AUTH_AES_256_GMAC:
	bad_case(ti);
    }
    return 0;
}

/*
 * 	Search enum_name array with in prefixed uppercase
 */
int
alg_enum_search_prefix (enum_names *ed, const char *prefix, const char *str, int str_len)
{
	char buf[64];
	char *ptr;
	int ret;
	int len=sizeof(buf)-1;	/* reserve space for final \0 */

	for (ptr=buf; len&&*prefix; *ptr++=*prefix++, len--);

	while (str_len--&&len--&&*str) *ptr++=toupper(*str++);
	*ptr=0;

	DBG(DBG_CRYPT, DBG_log("enum_search_prefix (\"%s\")", buf));

	ret=enum_search_nocase(ed, buf, strlen(buf));
	return ret;
}

/*
 * 	Search enum_name array with in prefixed and postfixed uppercase
 */
int
alg_enum_search_ppfix (enum_names *ed, const char *prefix
		   , const char *postfix, const char *str
		   , int str_len)
{
	char buf[64];
	char *ptr;
	int ret;
	int len=sizeof(buf)-1;	/* reserve space for final \0 */
	for (ptr=buf; len&&*prefix; *ptr++=*prefix++, len--);
	while (str_len--&&len--&&*str) *ptr++=toupper(*str++);
	while (len--&&*postfix) *ptr++=*postfix++;
	*ptr=0;
	DBG(DBG_CRYPT, DBG_log("enum_search_ppfixi () "
				"calling enum_search(%p, \"%s\")", ed, buf));
	ret=enum_search_nocase(ed, buf, strlen(buf));
	return ret;
}


/**
 * 	Search oakley_enc_names for a match, eg:
 * 		"3des"
 *
 * @param str String containing ALG name (eg: AES, 3DES)
 * @param len Length of ALG (eg: 256,512)
 * @return int Registered # of ALG if loaded.
 */
enum ikev2_trans_type_encr ealg_getbyname(const char *const str, int len, unsigned int *auxp)
{
    const struct keyword_enum_value *kev;
    int  search_ret = -1;
    enum ikev2_trans_type_encr ret=IKEv2_ENCR_INVALID;
    if (!str||!*str)
        goto out;

    /* look for the name by literal name, upcasing first */
    search_ret = enum_search_nocase(ikev2_encr_names.official_names, str, len);
    if (search_ret != -1) {
        ret = search_ret;
        goto out;
    }

    kev = keyword_search_aux(&ikev2_encr_names.aliases, str);
    if(kev == NULL) goto out;

    if(auxp) *auxp=kev->valueaux;
    ret = kev->value;

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
enum ikev2_trans_type_integ aalg_getbyname(const char *const str, int len, unsigned int *auxp)
{
    int  search_ret = -1;
    enum ikev2_trans_type_integ ret=IKEv2_AUTH_INVALID;
    unsigned num;
    if (!str||!*str)
        goto out;

    /* look for the name by literal name, upcasing first */
    search_ret = enum_search_nocase(ikev2_integ_names.official_names, str, len);
    if (search_ret>=0) goto out;

    search_ret = keyword_search(&ikev2_integ_names.aliases, str);
    if (search_ret>=0) goto out;

    search_ret=alg_enum_search_prefix(ikev2_integ_names.official_names,
                                      "HMAC_",str,len);
    if (search_ret>=0) goto out;

    sscanf(str, "id%d%n", &search_ret, &num);

    /* check if parsed part of a number only */
    if (search_ret >=0 && num!=strlen(str))
        search_ret=-1;

out:
    if (search_ret>=0) {
        ret = search_ret;
    }
    return ret;
}

/**
 * 	Search oakley_group_names for a match, eg:
 * 		"modp1024" <=> "OAKLEY_GROUP_MODP1024"
 * @param str String MODP Name (eg: MODP)
 * @param len Length of Hash (eg: 1024,1536,2048)
 * @return int Registered # of MODP Group, if supported.
 */
enum ikev2_trans_type_dh modp_getbyname(const char *const str, int len, unsigned int *auxp)
{
    int  search_ret = -1;
    enum ikev2_trans_type_dh ret=OAKLEY_INVALID_GROUP;

    if (!str||!*str)
        goto out;
    search_ret=alg_enum_search_prefix(ikev2_group_names.official_names,
                               "OAKLEY_GROUP_",str,len);
    if (search_ret>=0) goto out;

    /* finally, look for aliases. */
    search_ret = keyword_search(&ikev2_group_names.aliases, str);
    if (search_ret>=0) goto out;

 out:
    if (search_ret>=0) {
        ret = search_ret;
    }
    return ret;
}

void
alg_info_free(struct alg_info *alg_info) {
	pfreeany(alg_info);
}

static const char *parser_state_names[] = {
    "ST_INI",            /* start here for IKE and ESP */
    "ST_INI_AA",         /* start here for AH */
    "ST_EA",             /* Encryption Algorithm start */
    "ST_EA_END",         /* end */
    "ST_EK",             /* enc. algorithm key size */
    "ST_EK_END",         /* end of above */
    "ST_AA",             /* start of authentication/integrity algorightm */
    "ST_AA_END",         /* end */
    "ST_AK",             /* authorization key size */
    "ST_AK_END",         /* end of above */
    "ST_PRF",            /* Pseudo-random-function (PRF) start */
    "ST_PRF_END",        /* end of PRF */
    "ST_MOPD",           /* start of DH group name */
    "ST_FLAG_STRICT",    /* strict flag starts here */
    "ST_END",            /* all done */
    "ST_EOF",            /* hit end of data prematurely */
    "ST_ERR"
};

static const char *parser_state_name(enum parser_state_esp state) {
	return parser_state_names[state];
}

static inline void parser_set_state(struct parser_context *p_ctx, enum parser_state_esp state) {
	if (state!=p_ctx->state) {
		p_ctx->old_state=p_ctx->state;
		p_ctx->state=state;
	}

}

static int
parser_machine(struct parser_context *p_ctx)
{
	int ch=p_ctx->ch;
	/* special 'absolute' cases */
	p_ctx->err="No error.";

	/* chars that end algo strings */
	switch(ch){
	case 0:		/* end-of-string */
	case '!':	/* flag as strict algo list */
	case ',':	/* algo string separator */
	    switch(p_ctx->state) {
	    case ST_EA:
	    case ST_EK:
	    case ST_AA:
	    case ST_AK:
	    case ST_PRF:
	    case ST_MODP:
	    case ST_FLAG_STRICT:
		{
		    enum parser_state_esp next_state=0;
		    switch(ch) {
		    case 0:   next_state=ST_EOF;break;
		    case ',': next_state=ST_END;break;
		    case '!': next_state=ST_FLAG_STRICT;break;
		    }
		    /* ch? parser_set_state(p_ctx, ST_END) : parser_set_state(p_ctx, ST_EOF) ; */
		    parser_set_state(p_ctx, next_state);
		    goto out;
		}
	    default:
		p_ctx->err="String ended with invalid char";
		goto err;
	    }
	}
 re_eval:
	switch(p_ctx->state) {
	case ST_INI:
	    if (isspace(ch))
		break;
	    if (isalnum(ch)) {
		*(p_ctx->ealg_str++)=ch;
		parser_set_state(p_ctx, ST_EA);
		break;
	    }
	    p_ctx->err="No alphanum. char initially found";
	    goto err;

	case ST_INI_AA:
	    if (isspace(ch))
		break;
	    if (isalnum(ch)) {
		*(p_ctx->aalg_str++)=ch;
		parser_set_state(p_ctx, ST_AA);
		break;
	    }
	    p_ctx->err="No alphanum. char initially found";
	    goto err;

	case ST_EA:
	    if (isalpha(ch) || ch == '_') {
		*(p_ctx->ealg_str++)=ch;
		break;
	    }
	    if (isdigit(ch)) {
		/* bravely switch to enc keylen */
		*(p_ctx->ealg_str)=0;
		parser_set_state(p_ctx, ST_EK);
		goto re_eval;
	    }
	    if (ch=='-') {
		*(p_ctx->ealg_str)=0;
		parser_set_state(p_ctx, ST_EA_END);
		break;
	    }
	    p_ctx->err="No valid char found after enc alg string";
	    goto err;
	case ST_EA_END:
	    if (isdigit(ch)) {
		/* bravely switch to enc keylen */
		parser_set_state(p_ctx, ST_EK);
		goto re_eval;
	    }
	    if (isalpha(ch)) {
		parser_set_state(p_ctx, ST_AA);
		goto re_eval;
	    }
	    p_ctx->err="No alphanum char found after enc alg separator";
	    goto err;
	case ST_EK:
	    if (ch=='-') {
		parser_set_state(p_ctx, ST_EK_END);
		break;
	    }
	    if (isdigit(ch)) {
		p_ctx->eklen=p_ctx->eklen*10+ch-'0';
		break;
	    }
	    p_ctx->err="Non digit or valid separator found while reading enc keylen";
	    goto err;
	case ST_EK_END:
	    if (isalpha(ch)) {
		parser_set_state(p_ctx, ST_AA);
		goto re_eval;
	    }
	    p_ctx->err="Non alpha char found after enc keylen end separator";
	    goto err;
	case ST_AA:
	    if (ch=='-') {
		*(p_ctx->aalg_str++)=0;
		parser_set_state(p_ctx, ST_AA_END);
		break;
	    }
            if (ch==';') {
                *(p_ctx->aalg_str++)=0;
                parser_set_state(p_ctx, ST_AK_END);
                break;
            }
	    if (isalnum(ch) || ch=='_') {
		*(p_ctx->aalg_str++)=ch;
		break;
	    }
	    p_ctx->err="Non alphanum or valid separator found in auth string";
	    goto err;
	case ST_AA_END:
	    if (isdigit(ch)) {
		parser_set_state(p_ctx, ST_AK);
		goto re_eval;
	    }
	    /* Only allow modpXXXX or PRF string if we have
	     * a modp_getbyname method and a prfalg_getbyname
	     */
	    p_ctx->err="Invalid auth keylen found";
            goto consider_prf_modp;

	case ST_AK:
	    if (ch=='-'||ch==';') {
		parser_set_state(p_ctx, ST_AK_END);
		break;
	    }
	    if (isdigit(ch)) {
		p_ctx->aklen=p_ctx->aklen*10+ch-'0';
		break;
	    }
	    p_ctx->err="Non-numeric digit found in keylen";
	    goto err;

	case ST_AK_END:
	    p_ctx->err="Non alpha char found after auth keylen";
        consider_prf_modp:
	    if ((p_ctx->modp_getbyname) && (p_ctx->prfalg_getbyname) && isalpha(ch)) {
		parser_set_state(p_ctx, ST_PRF);
		goto re_eval;
	    }
	    if ((p_ctx->modp_getbyname) && isalpha(ch)) {
		parser_set_state(p_ctx, ST_MODP);
		goto re_eval;
	    }
	    goto err;

        case ST_PRF:
            if(ch=='-') {
                parser_set_state(p_ctx, ST_MODP);
                break;
            }
            /* assume string is PRF, and if it does not start with PRF, skip to modp */
	    if (isalnum(ch)) {
		*(p_ctx->prfalg_str++)=ch;
		break;
	    }
	    p_ctx->err="Non alphanum char found in prf string";
	    goto err;

	case ST_MODP:
	    if (isalnum(ch)) {
		*(p_ctx->modp_str++)=ch;
		break;
	    }
	    p_ctx->err="Non alphanum char found in modp string";
	    goto err;

	case ST_FLAG_STRICT:
	    if (ch == 0) {
		parser_set_state(p_ctx, ST_END);
	    }
	    p_ctx->err="Flags character(s) must be at end of whole string";
	    goto err;

	    /* XXX */
	case ST_END:
	case ST_EOF:
	case ST_ERR:
	    break;
	    /* XXX */
	}
 out:
	return p_ctx->state;
 err:
	parser_set_state(p_ctx, ST_ERR);
	return ST_ERR;
}

/*
 *	Must be called for each "new" char, with new
 *	character in ctx.ch
 */
static void
parser_init_esp(struct parser_context *p_ctx)
{
    memset(p_ctx, 0, sizeof (*p_ctx));

    p_ctx->protoid=PROTO_IPSEC_ESP;
    p_ctx->ealg_str=p_ctx->ealg_buf;
    p_ctx->aalg_str=p_ctx->aalg_buf;
    p_ctx->modp_str=p_ctx->modp_buf;
    p_ctx->ealg_permit = TRUE;
    p_ctx->aalg_permit = TRUE;
    p_ctx->state=ST_INI;

    p_ctx->ealg_getbyname=ealg_getbyname;
    p_ctx->aalg_getbyname=aalg_getbyname;
    p_ctx->modp_getbyname=modp_getbyname;
}

/*
 *	Must be called for each "new" char, with new
 *	character in ctx.ch
 */
static void
parser_init_ah(struct parser_context *p_ctx)
{
    memset(p_ctx, 0, sizeof (*p_ctx));

    p_ctx->protoid=PROTO_IPSEC_AH;
    p_ctx->ealg_str=NULL;
    p_ctx->ealg_permit = FALSE;
    p_ctx->aalg_str=p_ctx->aalg_buf;
    p_ctx->aalg_permit = TRUE;
    p_ctx->modp_str=p_ctx->modp_buf;
    p_ctx->state=ST_INI_AA;

    p_ctx->ealg_getbyname=NULL;
    p_ctx->aalg_getbyname=aalg_getbyname;
    p_ctx->modp_getbyname=modp_getbyname;
}

static int
parser_alg_info_add(struct parser_context *p_ctx
		    , struct alg_info *alg_info
		    , alg_info_adder *alg_info_add
		    , const struct oakley_group_desc *(*lookup_group)(enum ikev2_trans_type_dh group))
{
    unsigned int auxinfo;
    enum ikev2_trans_type_encr  ealg_id;
    enum ikev2_trans_type_prf   prfalg_id;
    enum ikev2_trans_type_integ aalg_id;
    enum ikev2_trans_type_dh    modp_id= OAKLEY_INVALID_GROUP;

    ealg_id = IKEv2_ENCR_INVALID;
    aalg_id = IKEv2_AUTH_INVALID;
    if (p_ctx->ealg_permit && *p_ctx->ealg_buf) {
        auxinfo = 0;
        ealg_id=p_ctx->ealg_getbyname(p_ctx->ealg_buf, strlen(p_ctx->ealg_buf), &auxinfo);
        if (ealg_id == IKEv2_ENCR_INVALID) {
            p_ctx->err="enc_alg not found";
            goto out;
        }

        /* XXX SHOULD be validated in add routine, and should be table driven */
        /* AES_GCM_128, AES_GCM_192, AES_GCM_256 */
        if(ealg_id    == IKEv2_ENCR_AES_GCM_8
           || ealg_id == IKEv2_ENCR_AES_GCM_12
           || ealg_id == IKEv2_ENCR_AES_GCM_16) {

            /* AES-GCM length key length + 4 bytes (32 bits) */
            if( p_ctx->eklen != 128
                && p_ctx->eklen != 192
                && p_ctx->eklen != 256 ) {
                p_ctx->err="wrong encryption key length with AES-GCM";
                goto out;
            }
            else {
                /* increase key length by 4 bytes, RFC 4106 */
                p_ctx->eklen = p_ctx->eklen + 4 *  BITS_PER_BYTE;
            }

        } else if(p_ctx->eklen == 0) {
            p_ctx->eklen = auxinfo;
        }

        DBG(DBG_CRYPT, DBG_log("parser_alg_info_add() "
                               "ealg_getbyname(\"%s\")=%d",
                               p_ctx->ealg_buf,
                               ealg_id));
    }
    if (p_ctx->aalg_permit && *p_ctx->aalg_buf) {
        auxinfo = 0;
        aalg_id=p_ctx->aalg_getbyname(p_ctx->aalg_buf, strlen(p_ctx->aalg_buf), &auxinfo);
        if (aalg_id == IKEv2_AUTH_INVALID) {
            p_ctx->err="hash_alg not found";
            goto out;
        }


        if(p_ctx->aklen == 0) {
            p_ctx->aklen = auxinfo;
        }

#ifdef HAVE_LIBNSS
        if ( Pluto_IsFIPS() && ((aalg_id == IKEv2_AUTH_HMAC_SHA2_256_128 ) || (aalg_id == IKEv2_AUTH_HMAC_SHA2_384_192 ) || (aalg_id == IKEv2_AUTH_HMAC_SHA2_512_256 ))  ) {
            p_ctx->err="SHA2 Not supported in FIPS mode with NSS";
            goto out;
        }
#endif
        DBG(DBG_CRYPT, DBG_log("parser_alg_info_add() "
                               "aalg_getbyname(\"%s\")=%d",
                               p_ctx->aalg_buf,
                               aalg_id));
    }

    modp_id   = OAKLEY_INVALID_GROUP;
    prfalg_id = IKEv2_PRF_INVALID;
    if(p_ctx->prfalg_getbyname && *p_ctx->prfalg_buf) {
        auxinfo = 0;
        prfalg_id = p_ctx->prfalg_getbyname(p_ctx->prfalg_buf, strlen(p_ctx->prfalg_buf), &auxinfo);

        if(prfalg_id == IKEv2_PRF_INVALID) {
            /* see if it's a modp algorithm! */
            strcpy(p_ctx->modp_buf, p_ctx->prfalg_buf);
            p_ctx->prfalg_buf[0]='\0';
            prfalg_id = IKEv2_PRF_INVALID;
        }
    }
    if(p_ctx->prfalg_getbyname && prfalg_id == IKEv2_PRF_INVALID) {
        /* only set this if caller was seeking a PRF value */
        prfalg_id = alg_info_ikev2_integ2prf(aalg_id);
    }

    if (modp_id == OAKLEY_INVALID_GROUP && p_ctx->modp_getbyname && *p_ctx->modp_buf) {
        auxinfo = 0;
        modp_id=p_ctx->modp_getbyname(p_ctx->modp_buf, strlen(p_ctx->modp_buf), &auxinfo);
        if (modp_id == OAKLEY_INVALID_GROUP) {
            p_ctx->err="modp group not found";
            goto out;
        }

        DBG(DBG_CRYPT, DBG_log("parser_alg_info_add() "
                               "modp_getbyname(\"%s\")=%d",
                               p_ctx->modp_buf,
                               modp_id));
    }

    if (modp_id != OAKLEY_INVALID_GROUP && lookup_group && !lookup_group(modp_id)) {
        p_ctx->err="found modp group id, but not supported";
        goto out;
    }

    (*alg_info_add)(alg_info
                    ,ealg_id, p_ctx->eklen
                    ,aalg_id, p_ctx->aklen
                    ,prfalg_id
                    ,modp_id);
    return 0;
 out:
    return -1;
}

int
alg_info_parse_str (struct alg_info *alg_info
		    , const char *alg_str
		    , const char **err_p
		    , void (*parser_init)(struct parser_context *p_ctx)
                    , alg_info_adder *alg_info_add
		    , const struct oakley_group_desc *(*lookup_group)(enum ikev2_trans_type_dh group))
{
	struct parser_context ctx;
	int ret;
	const char *ptr;
	static char err_buf[256];
	*err_buf=0;

	(*parser_init)(&ctx);

	if (err_p) *err_p=NULL;

	/* use default if nul esp string */
	if (!*alg_str) {
	    (*alg_info_add)(alg_info, 0, 0, 0, 0, 0, 0);
	}

	for(ret=0,ptr=alg_str;ret<ST_EOF;) {
	    ctx.ch=*ptr++;
	    ret= parser_machine(&ctx);
	    switch(ret) {
	    case ST_FLAG_STRICT:
		alg_info->alg_info_flags |= ALG_INFO_F_STRICT;
		break;

	    case ST_END:
	    case ST_EOF:
		DBG(DBG_CRYPT, DBG_log("alg_info_parse_str() "
				       "ealg_buf=%s aalg_buf=%s "
				       "eklen=%d  aklen=%d",
				       ctx.ealg_buf, ctx.aalg_buf,
				       ctx.eklen, ctx.aklen));

		if (parser_alg_info_add(&ctx, alg_info
					, alg_info_add
					, lookup_group)<0) {
		    snprintf(err_buf, sizeof(err_buf),
			     "%s, enc_alg=\"%s\", auth_alg=\"%s\", "
			     "modp=\"%s\"",
			     ctx.err,
			     ctx.ealg_buf,
			     ctx.aalg_buf,
			     ctx.modp_buf);
		    goto err;
		}
		/* zero out for next run (ST_END) */
		parser_init(&ctx);
		break;

	    case ST_ERR:
		snprintf(err_buf, sizeof(err_buf),
			 "%s, "
			 "just after \"%.*s\""
			 " (old_state=%s)",
			 ctx.err,
			 (int)(ptr-alg_str-1), alg_str ,
			 parser_state_name(ctx.old_state) );

		goto err;
	    default:
		if (!ctx.ch) break;
	    }
	}
	return 0;
 err:
	if (err_p) {
	    *err_p=err_buf;
	}
	return -1;
}

struct alg_info_esp *
alg_info_esp_create_from_str (const char *alg_str
			      , const char **err_p)
{
    struct alg_info_esp *alg_info_esp;
    int ret =0;

    /*
     * 	alg_info storage should be sized dynamically
     * 	but this may require 2passes to know
     * 	transform count in advance.
     */
    alg_info_esp=alloc_thing (struct alg_info_esp, "alg_info_esp");

    if (!alg_info_esp) goto out;

    alg_info_esp->alg_info_protoid=PROTO_IPSEC_ESP;
    ret=alg_info_parse_str((struct alg_info *)alg_info_esp
			   , alg_str, err_p
			   , parser_init_esp
			   , alg_info_esp_add
			   , NULL);

 out:
    if (ret<0)
	{
	    pfreeany(alg_info_esp);
	    alg_info_esp=NULL;
	}
    return alg_info_esp;

}

struct alg_info_esp *
alg_info_ah_create_from_str (const char *alg_str
			     , const char **err_p)
{
    struct alg_info_esp *alg_info_esp;
    int ret =0;

    /*
     * 	alg_info storage should be sized dynamically
     * 	but this may require 2passes to know
     * 	transform count in advance.
     */
    alg_info_esp=alloc_thing (struct alg_info_esp, "alg_info_esp");

    alg_info_esp->alg_info_protoid=PROTO_IPSEC_AH;
    ret=alg_info_parse_str((struct alg_info *)alg_info_esp
			   , alg_str, err_p
			   , parser_init_ah
			   , alg_info_ah_add
			   , NULL);

    if (ret<0)
	{
	    pfreeany(alg_info_esp);
	    alg_info_esp=NULL;
	}
    return alg_info_esp;
}

/*
 * 	alg_info struct can be shared by
 * 	several connections instances,
 * 	handle free() with ref_cnts
 */
void
alg_info_addref(struct alg_info *alg_info)
{
    if (alg_info != NULL) {
	alg_info->ref_cnt++;
	DBG(DBG_CONTROL, DBG_log("alg_info_addref() "
			       "alg_info->ref_cnt=%d", alg_info->ref_cnt));
    }
}
void
alg_info_delref(struct alg_info **alg_info_p)
{
    struct alg_info *alg_info=*alg_info_p;

#if 0
    DBG(DBG_CONTROL, DBG_log("alg_info_delref(%p) "
			   , alg_info));
#endif

    if (alg_info != NULL) {
	DBG(DBG_CONTROL, DBG_log("alg_info_delref(%p) "
			       "alg_info->ref_cnt=%d"
			       , alg_info, alg_info->ref_cnt));
	passert(alg_info->ref_cnt != 0);
	alg_info->ref_cnt--;
	if (alg_info->ref_cnt==0) {
	    DBG(DBG_CONTROL, DBG_log("alg_info_delref(%p) "
				   "freeing alg_info", alg_info));
	    alg_info_free(alg_info);
	}
	*alg_info_p=NULL;
    }
}

/*	snprint already parsed transform list (alg_info)	*/
int
alg_info_snprint(char *buf, int buflen
		 , struct alg_info *alg_info)
{
    char *ptr=buf;
    struct esp_info *esp_info;
    struct ike_info *ike_info;

    passert(buflen > 0);

    int cnt;
    ptr=buf;
    switch(alg_info->alg_info_protoid) {
    case PROTO_IPSEC_ESP:
	{
	    struct alg_info_esp *alg_info_esp=(struct alg_info_esp *)alg_info;
	    ALG_INFO_ESP_FOREACH(alg_info_esp, esp_info, cnt) {
		snprintf(ptr, buflen, "%s(%d)_%03d-%s(%d)_%03d"
			    , enum_name(&trans_type_encr_names, esp_info->esp_ealg_id)
			    , esp_info->esp_ealg_id
			    , (int)esp_info->esp_ealg_keylen
			    , enum_name(&trans_type_integ_names, esp_info->esp_aalg_id)
			    , esp_info->esp_aalg_id
			    , (int)esp_info->esp_aalg_keylen);
		size_t np = strlen(ptr);
		ptr += np;
		buflen -= np;

                if (esp_info->pfs_group != OAKLEY_INVALID_GROUP) {
                    snprintf(ptr, buflen, "-%s(%d)"
                             , alg_info_modp_shortname(esp_info->pfs_group)
                             , esp_info->pfs_group);
                    size_t np = strlen(ptr);
                    ptr += np;
                    buflen -= np;
                    if(buflen <= 0) goto out;
                }
		if ( cnt > 0) {
			snprintf(ptr, buflen, ", ");
			np = strlen(ptr);
			ptr += np;
			buflen -= np;
		}
		if(buflen <= 0) goto out;
            }
	    break;
	}

    case PROTO_IPSEC_AH:
        {
	    struct alg_info_esp *alg_info_esp=(struct alg_info_esp *)alg_info;
	    ALG_INFO_ESP_FOREACH(alg_info_esp, esp_info, cnt) {
		snprintf(ptr, buflen, "%s(%d)_%03d"
			    , enum_name(&trans_type_integ_names, esp_info->esp_aalg_id)
			    , esp_info->esp_aalg_id
			    , (int)esp_info->esp_aalg_keylen);
		size_t np = strlen(ptr);
		ptr += np;
		buflen -= np;
                if (esp_info->pfs_group != OAKLEY_INVALID_GROUP) {
                    snprintf(ptr, buflen, "-%s(%d)"
                             , alg_info_modp_shortname(esp_info->pfs_group)
                             , esp_info->pfs_group);
                    size_t np = strlen(ptr);
                    ptr += np;
                    buflen -= np;
                    if(buflen <= 0) goto out;
                }
		if ( cnt > 0) {
			snprintf(ptr, buflen, ", ");
			np = strlen(ptr);
			ptr += np;
			buflen -= np;
		}
		if(buflen <= 0) goto out;
                }
	    break;
        }

    case PROTO_ISAKMP:
        ALG_INFO_IKE_FOREACH((struct alg_info_ike *)alg_info, ike_info, cnt) {
            int np;
            alg_info_snprint_ike2(ike_info,
                                  ike_info->ike_eklen,
                                  ike_info->ike_hklen,
                                  &np, ptr, buflen);
            ptr += np;
            buflen -= np;
            if ( cnt > 0) {
                snprintf(ptr, buflen, ", ");
                np = strlen(ptr);
                ptr += np;
                buflen -= np;
            }
            if(buflen <= 0) goto out;
        }
        break;

    default:
	snprintf(buf, buflen, "INVALID protoid=%d\n",
		 alg_info->alg_info_protoid);
	size_t np = strlen(ptr);
	ptr += np;
	buflen -= np;
	goto out;
    }
    if(buflen > 0){
	snprintf(ptr, buflen, "; flags=%s",
		alg_info->alg_info_flags&ALG_INFO_F_STRICT?
		"strict":"-strict");
	size_t np = strlen(ptr);
	ptr += np;
	buflen -= np;
    }

 out:
    passert(buflen >= 0);

    return ptr-buf;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
