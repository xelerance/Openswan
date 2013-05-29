/* tables of names for values defined in constants.h
 * Copyright (C) 2012 Paul Wouteirs <pwouters@redhat.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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

/*
 * Note that the array sizes are all specified; this is to enable range
 * checking by code that only includes constants.h.
 */

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>
#include <openswan/passert.h>

#include "constants.h"
#include "enum_names.h"
#include "oswlog.h"

/* version */

static const char *const version_name_1[] = {
	"ISAKMP Version 1.0 (rfc2407)",
};
static const char *const version_name_2[] = {
	"IKEv2 version 2.0 (rfc4306/rfc5996)",
	"IKEv2 version 2.0 (rfc4306/rfc5996)",
	"IKEv2 version 2.0 (rfc4306/rfc5996)",
	"IKEv2 version 2.0 (rfc4306/rfc5996)",
	"IKEv2 version 2.0 (rfc4306/rfc5996)",
	"IKEv2 version 2.0 (rfc4306/rfc5996)",
	"IKEv2 version 2.0 (rfc4306/rfc5996)",
	"IKEv2 version 2.0 (rfc4306/rfc5996)",
	"IKEv2 version 2.0 (rfc4306/rfc5996)",
	"IKEv2 version 2.0 (rfc4306/rfc5996)",
	"IKEv2 version 2.0 (rfc4306/rfc5996)",
	"IKEv2 version 2.0 (rfc4306/rfc5996)",
	"IKEv2 version 2.0 (rfc4306/rfc5996)",
	"IKEv2 version 2.0 (rfc4306/rfc5996)",
	"IKEv2 version 2.0 (rfc4306/rfc5996)",
	"IKEv2 version 2.0 (rfc4306/rfc5996)",
};

enum_names version_names_1 =
    { ISAKMP_MAJOR_VERSION<<ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION,
	ISAKMP_MAJOR_VERSION<<ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION,
	version_name_1, NULL };

/* To ignore or (in other words, accept) all IKEv2 minor versions*/
enum_names version_names =
    { IKEv2_MAJOR_VERSION<<ISA_MAJ_SHIFT | 0x0,
	IKEv2_MAJOR_VERSION<<ISA_MAJ_SHIFT | 0xf,
	version_name_2, &version_names_1 };

/* Domain of Interpretation */

static const char *const doi_name[] = {
	"ISAKMP_DOI_ISAKMP",
	"ISAKMP_DOI_IPSEC",
};

enum_names doi_names = { ISAKMP_DOI_ISAKMP, ISAKMP_DOI_IPSEC, doi_name, NULL };

/* debugging settings: a set of selections for reporting
 * These would be more naturally situated in log.h,
 * but they are shared with whack.
 * It turns out that "debug-" is clutter in all contexts this is used,
 * so we leave it off.
 */
const char *const debug_bit_names[] = {
	"raw",
	"crypt",
	"parsing",
	"emitting",
	"control",
	"lifecycle",
	"klips",
	"dns",
	"oppo",
	"controlmore",
	"pfkey",
	"nattraversal",
	"x509",               /* 12 */
	"dpd",
	"oppoinfo",           /* 14 */
	"whackwatch",
	"res16",
	"res17",
	"res18",
	"res19",

	"private",            /* 20 */

	"impair-delay-adns-key-answer", /* 21 */
	"impair-delay-adns-txt-answer", /* 22 */
	"impair-bust-mi2",   /* 23 */
	"impair-bust-mr2",   /* 24 */
	"impair-sa-creation", /* 25 */
	"impair-die-oninfo",  /* 26 */
	"impair-jacob-two-two",  /* 27 */
	"impair-major-version-bump", /* 28 */
	"impair-minor-version-bump", /* 29 */
	"impair-retransmits", /* 30 */
	"impair-send-bogus-isakmp-flag", /* 31 */
	NULL
    };

/* kind of struct connection */

static const char *const connection_kind_name[] = {
    "CK_GROUP",		/* policy group: instantiates to template */
    "CK_TEMPLATE",	/* abstract connection, with wildcard */
    "CK_PERMANENT",	/* normal connection */
    "CK_INSTANCE",	/* instance of template, created for a particular attempt */
    "CK_GOING_AWAY"	/* instance being deleted -- don't delete again */
};

enum_names connection_kind_names =
    { CK_GROUP, CK_GOING_AWAY, connection_kind_name, NULL };

/* Payload types (RFC 2408 "ISAKMP" section 3.1) */

const char *const payload_name[] = {
	"ISAKMP_NEXT_NONE",
	"ISAKMP_NEXT_SA",       /* 1 */
	"ISAKMP_NEXT_P",
	"ISAKMP_NEXT_T",
	"ISAKMP_NEXT_KE",
	"ISAKMP_NEXT_ID",       /* 5 */
	"ISAKMP_NEXT_CERT",
	"ISAKMP_NEXT_CR",
	"ISAKMP_NEXT_HASH",
	"ISAKMP_NEXT_SIG",
	"ISAKMP_NEXT_NONCE",    /* 10 */
	"ISAKMP_NEXT_N",
	"ISAKMP_NEXT_D",
	"ISAKMP_NEXT_VID",
	"ISAKMP_NEXT_MODECFG",  /* 14 */
	"ISAKMP_NEXT_NAT-D",
	"ISAKMP_NEXT_16",
	"ISAKMP_NEXT_17",
	"ISAKMP_NEXT_18",
	"ISAKMP_NEXT_19",
	"ISAKMP_NEXT_NAT-D",
	"ISAKMP_NEXT_NAT-OA",
	NULL
    };

const char *const payload_names_ikev2[] = {
    "ISAKMP_NEXT_v2SA",            /* 33 */
    "ISAKMP_NEXT_v2KE",
    "ISAKMP_NEXT_v2IDi",
    "ISAKMP_NEXT_v2IDr",
    "ISAKMP_NEXT_v2CERT",
    "ISAKMP_NEXT_v2CERTREQ",
    "ISAKMP_NEXT_v2AUTH",
    "ISAKMP_NEXT_v2Ni",
    "ISAKMP_NEXT_v2N",
    "ISAKMP_NEXT_v2D",
    "ISAKMP_NEXT_v2V",
    "ISAKMP_NEXT_v2TSi",
    "ISAKMP_NEXT_v2TSr",
    "ISAKMP_NEXT_v2E",
    "ISAKMP_NEXT_v2CP",
    "ISAKMP_NEXT_v2EAP",
    NULL
};

const char *const payload_name_nat_d[] = {
    "ISAKMP_NEXT_NAT-D",
    "ISAKMP_NEXT_NAT-OA",
    NULL
};

static enum_names payload_names_nat_d =
{ ISAKMP_NEXT_NATD_DRAFTS, ISAKMP_NEXT_NATOA_DRAFTS, payload_name_nat_d, NULL };
static enum_names payload_names_ikev2_d =
{ ISAKMP_NEXT_v2SA, ISAKMP_NEXT_v2EAP, payload_names_ikev2, &payload_names_nat_d };

enum_names payload_names =
{ ISAKMP_NEXT_NONE, ISAKMP_NEXT_NATOA_RFC, payload_name, &payload_names_ikev2_d };


/* Exchange types (note: two discontinuous ranges) */

static const char *const exchange_name[] = {
	"ISAKMP_XCHG_NONE",
	"ISAKMP_XCHG_BASE",
	"ISAKMP_XCHG_IDPROT",
	"ISAKMP_XCHG_AO",
	"ISAKMP_XCHG_AGGR",
	"ISAKMP_XCHG_INFO",
	"ISAKMP_XCHG_MODE_CFG",
    };

static const char *const exchange_name2[] = {
	"ISAKMP_XCHG_QUICK",
	"ISAKMP_XCHG_NGRP",
	"ISAKMP_v2_SA_INIT",
	"ISAKMP_v2_AUTH",
	"ISAKMP_v2_CHILD_SA",
	"ISAKMP_v2_INFORMATIONAL",
    };

static enum_names exchange_desc2 =
    { ISAKMP_XCHG_QUICK, ISAKMP_v2_INFORMATIONAL, exchange_name2, NULL };

enum_names exchange_names =
    { ISAKMP_XCHG_NONE, ISAKMP_XCHG_MODE_CFG, exchange_name, &exchange_desc2 };
/* Flag BITS */
const char *const flag_bit_names[] = {
    "ISAKMP_FLAG_ENCRYPTION",         /* bit 0 */
    "ISAKMP_FLAG_COMMIT",             /* bit 1 */
    "bit 2",                          /* bit 2 */
    "ISAKMP_FLAG_INIT",               /* bit 3 */
    "ISAKMP_FLAG_VERSION",            /* bit 4 */
    "ISAKMP_FLAG_RESPONSE",           /* bit 5 */
    NULL
    };

/* Situation BITS definition for IPsec DOI */

const char *const sit_bit_names[] = {
	"SIT_IDENTITY_ONLY",
	"SIT_SECRECY",
	"SIT_INTEGRITY",
	NULL
    };

/* Protocol IDs (RFC 2407 "IPsec DOI" section 4.4.1) */

static const char *const protocol_name[] = {
    	"PROTO_RESERVED",
	"PROTO_ISAKMP",
	"PROTO_IPSEC_AH",
	"PROTO_IPSEC_ESP",
	"PROTO_IPCOMP",
    };

enum_names protocol_names =
    { PROTO_RESERVED, PROTO_IPCOMP, protocol_name, NULL };

static const char *const ikev2_protocol_name[] = {
    	"PROTO_v2_RESERVED"
	"PROTO_v2_IKE",
	"PROTO_v2_AH",
	"PROTO_v2_ESP",
    };

enum_names ikev2_protocol_names =
    { 0, PROTO_IPSEC_ESP, ikev2_protocol_name, NULL };





/* IPsec ISAKMP transform values */

static const char *const isakmp_transform_name[] = {
	"KEY_IKE",
    };

enum_names isakmp_transformid_names =
    { KEY_IKE, KEY_IKE, isakmp_transform_name, NULL };

/* IPsec AH transform values */

static const char *const ah_transform_name_private_use[] = {
	"AH_NULL", /* verify with kame source? 251 */
    };

enum_names ah_transformid_names_private_use =
    { AH_NULL, AH_NULL, ah_transform_name_private_use, NULL };


static const char *const ah_transform_name[] = {
	/* 0-1 RESERVED */
	"AH_MD5",
	"AH_SHA",
	"AH_DES",
	"AH_SHA2_256",
	"AH_SHA2_384",
	"AH_SHA2_512",
	"AH_RIPEMD",
	"AH_AES_XCBC_MAC",
	"AH_RSA",
	"AH_AES_128_GMAC", /* RFC4543 Errata1821  */
	"AH_AES_192_GMAC", /* RFC4543 Errata1821  */
	"AH_AES_256_GMAC", /* RFC4543 Errata1821  */
	/* 14-248 Unassigned */
	/* 249-255 Reserved for private use */
    };

enum_names ah_transformid_names =
    { AH_MD5, AH_AES_256_GMAC, ah_transform_name, &ah_transformid_names_private_use};

/* IPsec ESP transform values */

/*
 * ipsec drafts suggest "high" ESP ids values for testing,
 * assign generic ESP_ID<num> if not officially defined
 */
static const char *const esp_transform_name_private_use[] = {
	/* id=249 */
	"ESP_MARS",
	"ESP_RC6",
	"ESP_KAME_NULL",
	"ESP_SERPENT",
	"ESP_TWOFISH",
	"ESP_ID254",
	"ESP_ID255",
    };

enum_names esp_transformid_names_private_use =
    { ESP_MARS, ESP_ID255, esp_transform_name_private_use, NULL };

static const char *const esp_transform_name[] = {
        "ESP_DES_IV64",              /* old DES */
	"ESP_DES",
	"ESP_3DES",
	"ESP_RC5",
	"ESP_IDEA",
	"ESP_CAST",
	"ESP_BLOWFISH",
	"ESP_3IDEA",
	"ESP_DES_IV32",
	"ESP_RC4",
	"ESP_NULL",
	"ESP_AES",
	"ESP_AES_CTR",
	"ESP_AES_CCM_A",
	"ESP_AES_CCM_B",
	"ESP_AES_CCM_C",
	"ESP_UNASSIGNED_ID17",
	"ESP_AES_GCM_A",
	"ESP_AES_GCM_B",
	"ESP_AES_GCM_C",
	"ESP_SEED_CBC",
	"ESP_CAMELLIA",
	"ESP_NULL_AUTH_AES_GMAC", /* RFC4543 [Errata1821] */
	/* 24-248    Unassigned */
	/* 249-255   Reserved for private use */
};


enum_names esp_transformid_names =
    { ESP_DES_IV64, ESP_NULL_AUTH_AES_GMAC, esp_transform_name, &esp_transformid_names_private_use };

/* IPCOMP transform values */

static const char *const ipcomp_transform_name[] = {
	"IPCOMP_OUI",
	"IPCOMP_DEFLAT",
	"IPCOMP_LZS",
	"IPCOMP_V42BIS",
    };

enum_names ipcomp_transformid_names =
    { IPCOMP_OUI, IPCOMP_V42BIS, ipcomp_transform_name, NULL };

/* Identification type values */

static const char *const ident_name[] = {
	"ID_IPV4_ADDR",
	"ID_FQDN",
	"ID_USER_FQDN",
	"ID_IPV4_ADDR_SUBNET",
	"ID_IPV6_ADDR",
	"ID_IPV6_ADDR_SUBNET",
	"ID_IPV4_ADDR_RANGE",
	"ID_IPV6_ADDR_RANGE",
	"ID_DER_ASN1_DN",
	"ID_DER_ASN1_GN",
	"ID_KEY_ID",
    };

enum_names ident_names =
    { ID_IPV4_ADDR, ID_KEY_ID, ident_name, NULL };

/* Certificate type values */

static const char *const cert_type_name[] = {
	"CERT_NONE",
	"CERT_PKCS7_WRAPPED_X509",
	"CERT_PGP",
	"CERT_DNS_SIGNED_KEY",
	"CERT_X509_SIGNATURE",
	"CERT_X509_KEY_EXCHANGE",
	"CERT_KERBEROS_TOKENS",
	"CERT_CRL",
	"CERT_ARL",
	"CERT_SPKI",
	"CERT_X509_ATTRIBUTE",
    };

enum_names cert_type_names =
    { CERT_NONE, CERT_X509_ATTRIBUTE, cert_type_name, NULL };

/* Certificate type values RFC 4306 3.6 */
/* TBD AA don't know how to add v2 sepecific ones, now it is mix of v1 & v2 */

static const char *const ikev2_cert_type_name[] = {
        "CERT_RESERVED",
        "CERT_PKCS7_WRAPPED_X509",
        "CERT_PGP",
        "CERT_DNS_SIGNED_KEY",
	"CERT_X509_SIGNATURE",
	"CERT_UNUSED", /* 5 is missing did IETF drop it ? it was in IKEv1 RFC2408 */
	"CERT_KERBEROS_TOKENS",
	"CERT_CRL",
	"CERT_ARL",
	"CERT_SPKI",
	"CERT_X509_ATTRIBUTE",
	"CERT_RAW_RSA",
	"CERT_X509_CERT_URL",
	"CERT_X509_BUNDLE_URL", /* 13 */

	/* AA How do I add thse ?
	   RESERVED to IANA                  14 - 200
           PRIVATE USE                      201 - 255
	*/
};

enum_names ikev2_cert_type_names =
    { CERT_NONE, CERT_RAW_RSA, ikev2_cert_type_name, NULL };

/*
 * certificate request payload policy
 */
static const char *const certpolicy_type_name[] = {
    "CERT_NEVERSEND",
    "CERT_SENDIFASKED",
    "CERT_ALWAYSSEND",
    "CERT_FORCEDTYPE"
};

enum_names certpolicy_type_names =
    { cert_neversend, cert_alwayssend, certpolicy_type_name, NULL };

/* Oakley transform attributes
 * oakley_attr_bit_names does double duty: it is used for enum names
 * and bit names.
 */

const char *const oakley_attr_bit_names[] = {
	"OAKLEY_ENCRYPTION_ALGORITHM",
	"OAKLEY_HASH_ALGORITHM",
	"OAKLEY_AUTHENTICATION_METHOD",
	"OAKLEY_GROUP_DESCRIPTION",
	"OAKLEY_GROUP_TYPE",
	"OAKLEY_GROUP_PRIME",
	"OAKLEY_GROUP_GENERATOR_ONE",
	"OAKLEY_GROUP_GENERATOR_TWO",
	"OAKLEY_GROUP_CURVE_A",
	"OAKLEY_GROUP_CURVE_B",
	"OAKLEY_LIFE_TYPE",
	"OAKLEY_LIFE_DURATION",
	"OAKLEY_PRF",
	"OAKLEY_KEY_LENGTH",
	"OAKLEY_FIELD_SIZE",
	"OAKLEY_GROUP_ORDER",
	"OAKLEY_BLOCK_SIZE",
	NULL
    };

static const char *const oakley_var_attr_name[] = {
	"OAKLEY_GROUP_PRIME (variable length)",
	"OAKLEY_GROUP_GENERATOR_ONE (variable length)",
	"OAKLEY_GROUP_GENERATOR_TWO (variable length)",
	"OAKLEY_GROUP_CURVE_A (variable length)",
	"OAKLEY_GROUP_CURVE_B (variable length)",
	NULL,
	"OAKLEY_LIFE_DURATION (variable length)",
	NULL,
	NULL,
	NULL,
	"OAKLEY_GROUP_ORDER (variable length)",
    };

static enum_names oakley_attr_desc_tv = {
    OAKLEY_ENCRYPTION_ALGORITHM + ISAKMP_ATTR_AF_TV,
    OAKLEY_GROUP_ORDER + ISAKMP_ATTR_AF_TV, oakley_attr_bit_names, NULL };

enum_names oakley_attr_names = {
    OAKLEY_GROUP_PRIME, OAKLEY_GROUP_ORDER,
    oakley_var_attr_name, &oakley_attr_desc_tv };

/* for each Oakley attribute, which enum_names describes its values? */
enum_names *oakley_attr_val_descs[] = {
	NULL,			/* (none) */
	&oakley_enc_names,	/* OAKLEY_ENCRYPTION_ALGORITHM */
	&oakley_hash_names,	/* OAKLEY_HASH_ALGORITHM */
	&oakley_auth_names,	/* OAKLEY_AUTHENTICATION_METHOD */
	&oakley_group_names,	/* OAKLEY_GROUP_DESCRIPTION */
	&oakley_group_type_names,/* OAKLEY_GROUP_TYPE */
	NULL,			/* OAKLEY_GROUP_PRIME */
	NULL,			/* OAKLEY_GROUP_GENERATOR_ONE */
	NULL,			/* OAKLEY_GROUP_GENERATOR_TWO */
	NULL,			/* OAKLEY_GROUP_CURVE_A */
	NULL,			/* OAKLEY_GROUP_CURVE_B */
	&oakley_lifetime_names,	/* OAKLEY_LIFE_TYPE */
	NULL,			/* OAKLEY_LIFE_DURATION */
	&oakley_prf_names,	/* OAKLEY_PRF */
	NULL,			/* OAKLEY_KEY_LENGTH */
	NULL,			/* OAKLEY_FIELD_SIZE */
	NULL,			/* OAKLEY_GROUP_ORDER */
    };
const unsigned int oakley_attr_val_descs_size = elemsof(oakley_attr_val_descs);

/* IPsec DOI attributes (RFC 2407 "IPsec DOI" section 4.5) */

static const char *const ipsec_attr_name[] = {
	"SA_LIFE_TYPE",
	"SA_LIFE_DURATION",
	"GROUP_DESCRIPTION",
	"ENCAPSULATION_MODE",
	"AUTH_ALGORITHM",
	"KEY_LENGTH",
	"KEY_ROUNDS",
	"COMPRESS_DICT_SIZE",
	"COMPRESS_PRIVATE_ALG",
#ifdef HAVE_LABELED_IPSEC
	"ECN_TUNNEL",
#endif
    };

static const char *const ipsec_var_attr_name[] = {
	"SA_LIFE_DURATION (variable length)",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	"COMPRESS_PRIVATE_ALG (variable length)",
#ifdef HAVE_LABELED_IPSEC
	"NULL", /*ECN TUNNEL*/
#endif
    };

#ifdef HAVE_LABELED_IPSEC
static const char *const ipsec_private_attr_name[] = {
	"SECCTX" /*32001*/
};

enum_names ipsec_private_attr_names_tv = {
  SECCTX + ISAKMP_ATTR_AF_TV, SECCTX + ISAKMP_ATTR_AF_TV, ipsec_private_attr_name, NULL};

enum_names ipsec_private_attr_names = {
  SECCTX, SECCTX, ipsec_private_attr_name, &ipsec_private_attr_names_tv};
#endif

static enum_names ipsec_attr_desc_tv = {
    SA_LIFE_TYPE + ISAKMP_ATTR_AF_TV,
#ifdef HAVE_LABELED_IPSEC
    ECN_TUNNEL + ISAKMP_ATTR_AF_TV,
#else
    COMPRESS_PRIVATE_ALG + ISAKMP_ATTR_AF_TV,
#endif
    ipsec_attr_name,
#ifdef HAVE_LABELED_IPSEC
    &ipsec_private_attr_names};
#else
    NULL };
#endif

enum_names ipsec_attr_names = {
#ifdef HAVE_LABELED_IPSEC
    SA_LIFE_TYPE,
#else
    SA_LIFE_DURATION,
#endif
#ifdef HAVE_LABELED_IPSEC
    ECN_TUNNEL,
#else
    COMPRESS_PRIVATE_ALG,
#endif
#ifdef HAVE_LABELED_IPSEC
    ipsec_attr_name,
#else
     ipsec_var_attr_name,
#endif
      &ipsec_attr_desc_tv };

/* for each IPsec attribute, which enum_names describes its values? */
enum_names *ipsec_attr_val_descs[] = {
	NULL,			/* (none) */
	&sa_lifetime_names,	/* SA_LIFE_TYPE */
	NULL,			/* SA_LIFE_DURATION */
	&oakley_group_names,	/* GROUP_DESCRIPTION */
	&enc_mode_names,		/* ENCAPSULATION_MODE */
	&auth_alg_names,		/* AUTH_ALGORITHM */
	NULL,			/* KEY_LENGTH */
	NULL,			/* KEY_ROUNDS */
	NULL,			/* COMPRESS_DICT_SIZE */
	NULL,			/* COMPRESS_PRIVATE_ALG */
#ifdef HAVE_LABELED_IPSEC
	NULL,			/*ECN_TUNNEL*/
#endif
    };
const unsigned int ipsec_attr_val_descs_size=elemsof(ipsec_attr_val_descs);

/* SA Lifetime Type attribute */

static const char *const sa_lifetime_name[] = {
	"SA_LIFE_TYPE_SECONDS",
	"SA_LIFE_TYPE_KBYTES",
    };

enum_names sa_lifetime_names =
    { SA_LIFE_TYPE_SECONDS, SA_LIFE_TYPE_KBYTES, sa_lifetime_name, NULL };


/* Encapsulation Mode attribute */

static const char *const enc_rfc_mode_name[] = {
	"ENCAPSULATION_MODE_TUNNEL",
	"ENCAPSULATION_MODE_TRANSPORT",
	"ENCAPSULATION_MODE_UDP_TUNNEL_RFC",
	"ENCAPSULATION_MODE_UDP_TRANSPORT_RFC",
    };

static const char *const enc_draft_mode_name[] = {
	"ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS",
	"ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS",
    };

static enum_names enc_rfc_mode_names =
    { ENCAPSULATION_MODE_TUNNEL, ENCAPSULATION_MODE_UDP_TRANSPORT_RFC, enc_rfc_mode_name, NULL };

enum_names enc_mode_names =
    { ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS, ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS, enc_draft_mode_name, &enc_rfc_mode_names };


/* Auth Algorithm attribute */

static const char *const auth_alg_name_stolen_use[] = {
	"AUTH_ALGORITHM_NULL_KAME", /* according to our source code comments from jjo, needs verification */
};

enum_names
    auth_alg_names_stolen_use =
       { AUTH_ALGORITHM_NULL_KAME, AUTH_ALGORITHM_NULL_KAME , auth_alg_name_stolen_use, NULL };


static const char *const auth_alg_name[] = {
	"AUTH_ALGORITHM_NONE", /* our own value, not standard */
	"AUTH_ALGORITHM_HMAC_MD5",
	"AUTH_ALGORITHM_HMAC_SHA1",
	"AUTH_ALGORITHM_DES_MAC",
	"AUTH_ALGORITHM_KPDK",
	"AUTH_ALGORITHM_HMAC_SHA2_256",
	"AUTH_ALGORITHM_HMAC_SHA2_384",
	"AUTH_ALGORITHM_HMAC_SHA2_512",
	"AUTH_ALGORITHM_HMAC_RIPEMD",
	"AUTH_ALGORITHM_AES_CBC",
	"AUTH_ALGORITHM_SIG_RSA", /* RFC4359 */
	"AUTH_ALGORITHM_AES_128_GMAC", /* RFC4543 [Errata1821] */
	"AUTH_ALGORITHM_AES_192_GMAC", /* RFC4543 [Errata1821] */
	"AUTH_ALGORITHM_AES_256_GMAC", /* RFC4543 [Errata1821] */
	/* 14-61439      Unassigned */
	/* 61440-65535   Reserved for private use */
    };

enum_names
    auth_alg_names =
	{ AUTH_ALGORITHM_NONE, AUTH_ALGORITHM_AES_CBC , auth_alg_name, &auth_alg_names_stolen_use };

const char *const modecfg_cisco_attr_name[] = {
        "CISCO_BANNER",
        "CISCO_SAVE_PW",
        "CISCO_DEF_DOMAIN",
        "CISCO_SPLIT_DNS",
        "CISCO_SPLIT_INC",
        "CISCO_UDP_ENCAP_PORT",
        "CISCO_UNKNOWN",
        "CISCO_DO_PFS",
        "CISCO_FW_TYPE",
        "CISCO_BACKUP_SERVER",
        "CISCO_DDNS_HOSTNAME",
        NULL
    };

enum_names modecfg_cisco_attr_names_tv =
    { CISCO_BANNER + ISAKMP_ATTR_AF_TV , CISCO_DDNS_HOSTNAME + ISAKMP_ATTR_AF_TV, modecfg_cisco_attr_name , NULL };

enum_names modecfg_cisco_attr_names =
    { CISCO_BANNER, CISCO_DDNS_HOSTNAME, modecfg_cisco_attr_name , &modecfg_cisco_attr_names_tv };

/* From draft-beaulieu-ike-xauth */
const char *const xauth_attr_name[] = {
	"XAUTH-TYPE",
	"XAUTH-USER-NAME",
	"XAUTH-USER-PASSWORD",
	"XAUTH-PASSCODE",
	"XAUTH-MESSAGE",
	"XAUTH-CHALLENGE",
	"XAUTH-DOMAIN",
	"XAUTH-STATUS",
	"XAUTH-NEXT-PIN",
	"XAUTH-ANSWER",
	NULL
    };

enum_names xauth_attr_names_tv =
    { XAUTH_TYPE + ISAKMP_ATTR_AF_TV , XAUTH_ANSWER + ISAKMP_ATTR_AF_TV, xauth_attr_name , &modecfg_cisco_attr_names };

enum_names xauth_attr_names =
    { XAUTH_TYPE , XAUTH_ANSWER, xauth_attr_name , &xauth_attr_names_tv };

/* for XAUTH-TYPE attribute */
const char *const xauth_type_name[] = {
  "Generic",
  "RADIUS-CHAP",
  "OTP",
  "S/KEY",
  NULL
};
enum_names xauth_type_names =
  { XAUTH_TYPE_GENERIC, XAUTH_TYPE_SKEY, xauth_type_name, NULL};

const char *const modecfg_attr_name[] = {
	"INTERNAL_IP4_ADDRESS",
	"INTERNAL_IP4_NETMASK",
	"INTERNAL_IP4_DNS",
	"INTERNAL_IP4_NBNS",
	"INTERNAL_ADDRESS_EXPIRY",
	"INTERNAL_IP4_DHCP",
	"APPLICATION_VERSION",
	"INTERNAL_IP6_ADDRESS",
	"INTERNAL_IP6_NETMASK",
	"INTERNAL_IP6_DNS",
	"INTERNAL_IP6_NBNS",
	"INTERNAL_IP6_DHCP",
	"INTERNAL_IP4_SUBNET",
	"SUPPORTED_ATTRIBUTES",
	"INTERNAL_IP6_SUBNET",
	NULL
    };

enum_names modecfg_attr_names_tv =
    { INTERNAL_IP4_ADDRESS + ISAKMP_ATTR_AF_TV , INTERNAL_IP6_SUBNET + ISAKMP_ATTR_AF_TV, modecfg_attr_name , &xauth_attr_names };

enum_names modecfg_attr_names =
    { INTERNAL_IP4_ADDRESS , INTERNAL_IP6_SUBNET, modecfg_attr_name , &modecfg_attr_names_tv };

/* Oakley Lifetime Type attribute */

static const char *const oakley_lifetime_name[] = {
	"OAKLEY_LIFE_SECONDS",
	"OAKLEY_LIFE_KILOBYTES",
    };

enum_names oakley_lifetime_names =
    { OAKLEY_LIFE_SECONDS, OAKLEY_LIFE_KILOBYTES, oakley_lifetime_name, NULL };

/* Oakley PRF attribute (none defined) */

enum_names oakley_prf_names =
    { 1, 0, NULL, NULL };

/* Oakley Encryption Algorithm attribute */

static const char *const oakley_enc_name[] = {
	"OAKLEY_DES_CBC",
	"OAKLEY_IDEA_CBC",
	"OAKLEY_BLOWFISH_CBC",
	"OAKLEY_RC5_R16_B64_CBC",
	"OAKLEY_3DES_CBC",
	"OAKLEY_CAST_CBC",
	"OAKLEY_AES_CBC",
    };

#ifdef NO_EXTRA_IKE
enum_names oakley_enc_names =
    { OAKLEY_DES_CBC, OAKLEY_AES_CBC, oakley_enc_name, NULL };
#else
static const char *const oakley_enc_name_draft_aes_cbc_02[] = {
	"OAKLEY_MARS_CBC"	/*	65001	*/,
	"OAKLEY_RC6_CBC"     	/*	65002	*/,
	"OAKLEY_ID_65003"	/*	65003	*/,
	"OAKLEY_SERPENT_CBC"	/*	65004	*/,
	"OAKLEY_TWOFISH_CBC"	/*	65005	*/,
};
static const char *const oakley_enc_name_ssh[] = {
	"OAKLEY_TWOFISH_CBC_SSH",
};
enum_names oakley_enc_names_ssh =
    { 65289, 65289, oakley_enc_name_ssh, NULL };
enum_names oakley_enc_names_draft_aes_cbc_02 =
    { 65001, 65005, oakley_enc_name_draft_aes_cbc_02, &oakley_enc_names_ssh };
enum_names oakley_enc_names =
    { OAKLEY_DES_CBC, OAKLEY_AES_CBC, oakley_enc_name, &oakley_enc_names_draft_aes_cbc_02 };
#endif

/* Oakley Hash Algorithm attribute */

static const char *const oakley_hash_name2[] = {
	"OAKLEY_SHA",
    };

enum_names oakley_hash_names2 =
    { OAKLEY_SHA, OAKLEY_SHA, oakley_hash_name2, NULL };

static const char *const oakley_hash_name[] = {
	"OAKLEY_MD5",
	"OAKLEY_SHA1",
	"OAKLEY_TIGER",
	"OAKLEY_SHA2_256",
	"OAKLEY_SHA2_384",
	"OAKLEY_SHA2_512",
    };

enum_names oakley_hash_names =
    { OAKLEY_MD5, OAKLEY_SHA2_512, oakley_hash_name, &oakley_hash_names2};

/* Oakley Authentication Method attribute */

static const char *const oakley_auth_name1[] = {
	"OAKLEY_PRESHARED_KEY",
	"OAKLEY_DSS_SIG",
	"OAKLEY_RSA_SIG",
	"OAKLEY_RSA_ENC",
	"OAKLEY_RSA_ENC_REV",
	"OAKLEY_ELGAMAL_ENC",
	"OAKLEY_ELGAMAL_ENC_REV",
    };

static const char *const oakley_auth_name2[] = {
	"HybridInitRSA",
	"HybridRespRSA",
	"HybridInitDSS",
	"HybridRespDSS",
    };

static const char *const oakley_auth_name3[] = {
	"XAUTHInitPreShared",
	"XAUTHRespPreShared",
	"XAUTHInitDSS",
	"XAUTHRespDSS",
	"XAUTHInitRSA",
	"XAUTHRespRSA",
	"XAUTHInitRSAEncryption",
	"XAUTHRespRSAEncryption",
	"XAUTHInitRSARevisedEncryption",
	"XAUTHRespRSARevisedEncryption",
    };

static enum_names oakley_auth_names1 =
    { OAKLEY_PRESHARED_KEY, OAKLEY_ELGAMAL_ENC_REV
	, oakley_auth_name1, NULL };

static enum_names oakley_auth_names2 =
    { HybridInitRSA, HybridRespDSS
	, oakley_auth_name2, &oakley_auth_names1 };

enum_names oakley_auth_names =
    { XAUTHInitPreShared, XAUTHRespRSARevisedEncryption
	, oakley_auth_name3, &oakley_auth_names2 };

/* ikev2 auth methods */
static const char *const ikev2_auth_strings[]={
	"v2_AUTH_RSA",
	"v2_AUTH_SHARED",
	"v2_AUTH_DSA",
};
enum_names ikev2_auth_names =
{ v2_AUTH_RSA, v2_AUTH_DSA, ikev2_auth_strings, NULL};


/* Oakley Group Description attribute */

static const char *const oakley_group_name[] = {
	"OAKLEY_GROUP_MODP768",
	"OAKLEY_GROUP_MODP1024",
	"OAKLEY_GROUP_GP155",
	"OAKLEY_GROUP_GP185",
	"OAKLEY_GROUP_MODP1536",
    };

static const char *const oakley_group_name_rfc3526[] = {
	"OAKLEY_GROUP_MODP2048",
	"OAKLEY_GROUP_MODP3072",
	"OAKLEY_GROUP_MODP4096",
	"OAKLEY_GROUP_MODP6144",
	"OAKLEY_GROUP_MODP8192"
};

#ifdef USE_MODP_RFC5114
static const char *const oakley_group_name_rfc5114[] = {
        "OAKLEY_GROUP_DH22",
        "OAKLEY_GROUP_DH23",
        "OAKLEY_GROUP_DH24"
};
#endif

#ifdef USE_MODP_RFC5114
enum_names oakley_group_names_rfc5114 =
    { OAKLEY_GROUP_DH22, OAKLEY_GROUP_DH24,
            oakley_group_name_rfc5114, NULL };
#endif

enum_names oakley_group_names_rfc3526 =
    { OAKLEY_GROUP_MODP2048, OAKLEY_GROUP_MODP8192,
	    oakley_group_name_rfc3526,
#ifdef USE_MODP_RFC5114
	    &oakley_group_names_rfc5114 };
#else
	    NULL };
#endif

enum_names oakley_group_names =
    { OAKLEY_GROUP_MODP768, OAKLEY_GROUP_MODP1536,
	    oakley_group_name, &oakley_group_names_rfc3526 };

/* Oakley Group Type attribute */

static const char *const oakley_group_type_name[] = {
	"OAKLEY_GROUP_TYPE_MODP",
	"OAKLEY_GROUP_TYPE_ECP",
	"OAKLEY_GROUP_TYPE_EC2N",
    };

enum_names oakley_group_type_names =
    { OAKLEY_GROUP_TYPE_MODP, OAKLEY_GROUP_TYPE_EC2N, oakley_group_type_name, NULL };

/* Notify messages -- error types */

static const char *const notification_name[] = {
	"INVALID_PAYLOAD_TYPE",

	"DOI_NOT_SUPPORTED",
	"SITUATION_NOT_SUPPORTED",
	"INVALID_COOKIE",
	"INVALID_MAJOR_VERSION",
	"INVALID_MINOR_VERSION",
	"INVALID_EXCHANGE_TYPE",
	"INVALID_FLAGS",
	"INVALID_MESSAGE_ID",
	"INVALID_PROTOCOL_ID",
	"INVALID_SPI",
	"INVALID_TRANSFORM_ID",
	"ATTRIBUTES_NOT_SUPPORTED",
	"NO_PROPOSAL_CHOSEN",
	"BAD_PROPOSAL_SYNTAX",
	"PAYLOAD_MALFORMED",
	"INVALID_KEY_INFORMATION",
	"INVALID_ID_INFORMATION",
	"INVALID_CERT_ENCODING",
	"INVALID_CERTIFICATE",
	"CERT_TYPE_UNSUPPORTED",
	"INVALID_CERT_AUTHORITY",
	"INVALID_HASH_INFORMATION",
	"AUTHENTICATION_FAILED",
	"INVALID_SIGNATURE",
	"ADDRESS_NOTIFICATION",
	"NOTIFY_SA_LIFETIME",
	"CERTIFICATE_UNAVAILABLE",
	"UNSUPPORTED_EXCHANGE_TYPE",
	"UNEQUAL_PAYLOAD_LENGTHS",
    };

static const char *const notification_status_name[] = {
	"CONNECTED",
    };

static const char *const ipsec_notification_name[] = {
	"IPSEC_RESPONDER_LIFETIME",
	"IPSEC_REPLAY_STATUS",
	"IPSEC_INITIAL_CONTACT",
    };

static const char *const notification_dpd_name[] = {
        "R_U_THERE",
        "R_U_THERE_ACK",
};

static const char *const notification_cisco_chatter_name[] = {
	"ISAKMP_N_CISCO_HELLO", /* 30000 */
	"ISAKMP_N_CISCO_WWTEBR",
	"ISAKMP_N_CISCO_SHUT_UP",
    };

static const char *const notification_ios_alives_name[] = {
	"ISAKMP_N_IOS_KEEP_ALIVE_REQ", /* 32768*/
	"ISAKMP_N_IOS_KEEP_ALIVE_ACK",
    };

static const char *const notification_juniper_name[] = {
        /* Next Hop Tunnel Binding */
	"NETSCREEN_NHTB_INFORM", /* 40001 */
};

static const char *const notification_cisco_more_name[] = {
        "ISAKMP_N_CISCO_LOAD_BALANCE", /* 40501 */
	"ISAKMP_N_CISCO_UNKNOWN_40502",
	"ISAKMP_N_CISCO_PRESHARED_KEY_HASH",
    };

enum_names notification_juniper_names =
    { NETSCREEN_NHTB_INFORM, NETSCREEN_NHTB_INFORM,
     notification_juniper_name, NULL };

enum_names notification_cisco_more_names =
    {  ISAKMP_N_CISCO_LOAD_BALANCE, ISAKMP_N_CISCO_PRESHARED_KEY_HASH,
      notification_cisco_more_name, &notification_juniper_names };

enum_names notification_ios_alives_names =
    { ISAKMP_N_IOS_KEEP_ALIVE_REQ, ISAKMP_N_IOS_KEEP_ALIVE_ACK,
      notification_ios_alives_name, &notification_cisco_more_names };

enum_names notification_cisco_chatter_names =
    { ISAKMP_N_CISCO_HELLO, ISAKMP_N_CISCO_SHUT_UP,
      notification_cisco_chatter_name, &notification_ios_alives_names };

enum_names notification_dpd_names =
    { R_U_THERE, R_U_THERE_ACK,
      notification_dpd_name, &notification_cisco_chatter_names };

enum_names notification_names =
    { INVALID_PAYLOAD_TYPE, UNEQUAL_PAYLOAD_LENGTHS,
        notification_name, &notification_dpd_names };

enum_names notification_status_names =
    { CONNECTED, CONNECTED,
	notification_status_name, &notification_names };

enum_names ipsec_notification_names =
    { IPSEC_RESPONDER_LIFETIME, IPSEC_INITIAL_CONTACT,
	ipsec_notification_name, &notification_status_names };

/* http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xml#ikev2-parameters-13 */
static const char *const ikev2_notify_name_16384[] = {
	   "v2N_INITIAL_CONTACT", /* 16384 */
	   "v2N_SET_WINDOW_SIZE",
	   "v2N_ADDITIONAL_TS_POSSIBLE",
	   "v2N_IPCOMP_SUPPORTED",
	   "v2N_NAT_DETECTION_SOURCE_IP",
	   "v2N_NAT_DETECTION_DESTINATION_IP",
	   "v2N_COOKIE",
	   "v2N_USE_TRANSPORT_MODE",
	   "v2N_HTTP_CERT_LOOKUP_SUPPORTED",
	   "v2N_REKEY_SA",
	   "v2N_ESP_TFC_PADDING_NOT_SUPPORTED",
	   "v2N_NON_FIRST_FRAGMENTS_ALSO",
	   "v2N_MOBIKE_SUPPORTED",
	   "v2N_ADDITIONAL_IP4_ADDRESS",
	   "v2N_ADDITIONAL_IP6_ADDRESS",
	   "v2N_NO_ADDITIONAL_ADDRESSES",
	   "v2N_UPDATE_SA_ADDRESSES",
	   "v2N_COOKIE2",
	   "v2N_NO_NATS_ALLOWED",
	   "v2N_AUTH_LIFETIME",
	   "v2N_MULTIPLE_AUTH_SUPPORTED",
	   "v2N_ANOTHER_AUTH_FOLLOWS",
	   "v2N_REDIRECT_SUPPORTED",
	   "v2N_REDIRECT",
	   "v2N_REDIRECTED_FROM",
	   "v2N_TICKET_LT_OPAQUE",
	   "v2N_TICKET_REQUEST",
	   "v2N_TICKET_ACK",
	   "v2N_TICKET_NACK",
	   "v2N_TICKET_OPAQUE",
	   "v2N_LINK_ID",
	   "v2N_USE_WESP_MODE",
	   "v2N_ROHC_SUPPORTED",
	   "v2N_EAP_ONLY_AUTHENTICATION",
	   "v2N_CHILDLESS_IKEV2_SUPPORTED",
	   "v2N_QUICK_CRASH_DETECTION",
	   "v2N_IKEV2_MESSAGE_ID_SYNC_SUPPORTED",
	   "v2N_IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED",
	   "v2N_IKEV2_MESSAGE_ID_SYNC",
	   "v2N_IPSEC_REPLAY_COUNTER_SYNC",
	   "v2N_SECURE_PASSWORD_METHODS", /* 16423 */
 	};

static const char *const ikev2_notify_name[] = {
	   "v2N_RESERVED", /* unofficial "OK" */
	   "v2N_UNSUPPORTED_CRITICAL_PAYLOAD",
	   "v2N_UNUSED_2",
	   "v2N_UNUSED_3",
	   "v2N_INVALID_IKE_SPI",
	   "v2N_INVALID_MAJOR_VERSION",
	   "v2N_UNUSED_6",
	   "v2N_INVALID_SYNTAX",
	   "v2N_UNUSED_8",
	   "v2N_INVALID_MESSAGE_ID",
	   "v2N_UNUSED_10",
	   "v2N_INVALID_SPI",
	   "v2N_UNUSED_12",
	   "v2N_UNUSED_13",
	   "v2N_NO_PROPOSAL_CHOSEN",
	   "v2N_UNUSED_15",
	   "v2N_UNUSED_16",
	   "v2N_INVALID_KE_PAYLOAD",
	   "v2N_UNUSED_18",
	   "v2N_UNUSED_19",
	   "v2N_UNUSED_20",
	   "v2N_UNUSED_21",
	   "v2N_UNUSED_22",
	   "v2N_UNUSED_23",
	   "v2N_AUTHENTICATION_FAILED",
	   "v2N_UNUSED_25",
	   "v2N_UNUSED_26",
	   "v2N_UNUSED_27",
	   "v2N_UNUSED_28",
	   "v2N_UNUSED_29",
	   "v2N_UNUSED_30",
	   "v2N_UNUSED_31",
	   "v2N_UNUSED_32",
	   "v2N_UNUSED_33",
	   "v2N_SINGLE_PAIR_REQUIRED",
	   "v2N_NO_ADDITIONAL_SAS",
	   "v2N_INTERNAL_ADDRESS_FAILURE",
	   "v2N_FAILED_CP_REQUIRED",
	   "v2N_TS_UNACCEPTABLE",
	   "v2N_INVALID_SELECTORS",
	   "v2N_UNACCEPTABLE_ADDRESSES",
	   "v2N_UNEXPECTED_NAT_DETECTED",
	   "v2N_USE_ASSIGNED_HoA",
	   "v2N_TEMPORARY_FAILURE",
	   "v2N_CHILD_SA_NOT_FOUND", /* 45 */
	};

enum_names ikev2_notify_names_16384 =
    { v2N_INITIAL_CONTACT, v2N_SECURE_PASSWORD_METHODS, ikev2_notify_name_16384, NULL};

enum_names ikev2_notify_names =
    { 0, v2N_CHILD_SA_NOT_FOUND, ikev2_notify_name, &ikev2_notify_names_16384};

/* http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xml#ikev2-parameters-19 */
static const char *const ikev2_ts_type_name[] = {
	   "IKEv2_TS_IPV4_ADDR_RANGE",
	   "IKEv2_TS_IPV6_ADDR_RANGE",
	   "IKEv2_TS_FC_ADDR_RANGE", /* not implemented */
	};

enum_names ikev2_ts_type_names =
    { IKEv2_TS_IPV4_ADDR_RANGE, IKEv2_TS_FC_ADDR_RANGE, ikev2_ts_type_name, NULL };


/* MODECFG */
/*
 * From draft-dukes-ike-mode-cfg
*/
const char *const attr_msg_type_name[] = {
	"ISAKMP_CFG_RESERVED",
	"ISAKMP_CFG_REQUEST",
	"ISAKMP_CFG_REPLY",
	"ISAKMP_CFG_SET",
	"ISAKMP_CFG_ACK",
	NULL
    };

enum_names attr_msg_type_names =
    { 0 , ISAKMP_CFG_ACK, attr_msg_type_name , NULL };

/*
 * IKEv2 Critical bit and RESERVED (7) bits
 */
const char *const critical_names[] = {
    "RESERVED",         /* bit 0 */
    "RESERVED",         /* bit 1 */
    "RESERVED",         /* bit 2 */
    "RESERVED",         /* bit 3 */
    "RESERVED",         /* bit 4 */
    "RESERVED",         /* bit 5 */
    "RESERVED",         /* bit 6 */
    "PAYLOAD_CRITICAL",      /* bit 7*/
    };

/* Transform-type Encryption */
const char *const trans_type_encr_name[]={
    "des-iv64",
    "des",
    "3des",
    "rc5",
    "idea",
    "cast",
    "blowfish",
    "3idea",
    "des-iv32",
    "res10",
    "null",
    "aes-cbc",
    "aes-ctr",
};
enum_names trans_type_encr_names =
{ IKEv2_ENCR_DES_IV64, IKEv2_ENCR_AES_CTR, trans_type_encr_name, NULL};

/* Transform-type PRF */
const char *const trans_type_prf_name[]={
    "prf-hmac-md5",
    "prf-hmac-sha1",
    "prf-hmac-tiger",
    "prf-hmac-aes128-xcbc",
    /* RFC 4868 Section 4 */
    "prf-hmac-sha2-256",
    "prf-hmac-sha2-384",
    "prf-hmac-sha2-512",
};
enum_names trans_type_prf_names =
{ IKEv2_PRF_HMAC_MD5, IKEv2_PRF_HMAC_SHA2_512, trans_type_prf_name, NULL};

/* Transform-type Integrity */
const char *const trans_type_integ_name[]={
    "auth-none",
    "auth-hmac-md5-96",
    "auth-hmac-sha1-96",
    "auth-des-mac",
    "auth-kpdk-md5",
    "auth-aes-xcbc-96",
    "AUTH_HMAC_MD5_128",
    "AUTH_HMAC_SHA1_160",
    "AUTH_AES_CMAC_96",
    "AUTH_AES_128_GMAC",
    "AUTH_AES_192_GMAC",
    "AUTH_AES_256_GMAC",
    "AUTH_HMAC_SHA2_256_128",
    "AUTH_HMAC_SHA2_384_192",
    "AUTH_HMAC_SHA2_512_256",
};
enum_names trans_type_integ_names =
{ IKEv2_AUTH_NONE, IKEv2_AUTH_HMAC_SHA2_512_256, trans_type_integ_name, NULL};

/* Transform-type Integrity */
const char *const trans_type_esn_name[]={
    "esn-disabled",
    "esn-enabled",
};
enum_names trans_type_esn_names =
{ IKEv2_ESN_DISABLED, IKEv2_ESN_ENABLED, trans_type_esn_name, NULL};

/* Transform Type */
const char *const trans_type_name[]={
    "trans-type-encr",
    "trans-type-prf",
    "trans-type-integ",
    "trans-type-dh",
    "trans-type-esn"
};
enum_names trans_type_names =
{ IKEv2_TRANS_TYPE_ENCR, IKEv2_TRANS_TYPE_ESN, trans_type_name, NULL};

/* for each IKEv2 transform attribute,which enum_names describes its values? */
enum_names *ikev2_transid_val_descs[] = {
    NULL,
    &trans_type_encr_names, /* 1 */
    &trans_type_prf_names,  /* 2 */
    &trans_type_integ_names, /* 3 */
    &oakley_group_names,    /* 4 */
    &trans_type_esn_names,  /* 5 */
};
const unsigned int ikev2_transid_val_descs_size = elemsof(ikev2_transid_val_descs);

/* Transform Attributes */
const char *const ikev2_trans_attr_name[]={
    "KEY_LENGTH",
};

enum_names ikev2_trans_attr_descs = {
    IKEv2_KEY_LENGTH + ISAKMP_ATTR_AF_TV,
    IKEv2_KEY_LENGTH + ISAKMP_ATTR_AF_TV,
    ikev2_trans_attr_name, NULL };

/* for each IKEv2 attribute, which enum_names describes its values? */
enum_names *ikev2_trans_attr_val_descs[] = {
	NULL,			/* 0 */
	NULL,			/* 1 */
	NULL,			/* 2 */
	NULL,			/* 3 */
	NULL,			/* 4 */
	NULL,			/* 5 */
	NULL,			/* 6 */
	NULL,			/* 7 */
	NULL,			/* 8 */
	NULL,			/* 9 */
	NULL,			/* 10 */
	NULL,			/* 11 */
	NULL,			/* 12 */
	NULL,			/* 13 */
	&ikev2_trans_attr_descs,/* KEY_LENGTH */
    };
const unsigned int ikev2_trans_attr_val_descs_size=elemsof(ikev2_trans_attr_val_descs);


/* socket address family info */

static const char *const af_inet_name[] = {
	"AF_INET",
    };

static const char *const af_inet6_name[] = {
	"AF_INET6",
    };

static enum_names af_names6 = { AF_INET6, AF_INET6, af_inet6_name, NULL };

enum_names af_names = { AF_INET, AF_INET, af_inet_name, &af_names6 };

static ip_address ipv4_any, ipv6_any;
static ip_subnet ipv4_wildcard, ipv6_wildcard;
static ip_subnet ipv4_all, ipv6_all;

const struct af_info af_inet4_info = {
	AF_INET,
	"AF_INET",
	sizeof(struct in_addr),
	sizeof(struct sockaddr_in),
	32,
	ID_IPV4_ADDR, ID_IPV4_ADDR_SUBNET, ID_IPV4_ADDR_RANGE,
	&ipv4_any, &ipv4_wildcard, &ipv4_all,
    };

const struct af_info af_inet6_info = {
	AF_INET6,
	"AF_INET6",
	sizeof(struct in6_addr),
	sizeof(struct sockaddr_in6),
	128,
	ID_IPV6_ADDR, ID_IPV6_ADDR_SUBNET, ID_IPV6_ADDR_RANGE,
	&ipv6_any, &ipv6_wildcard, &ipv6_all,
    };

const struct af_info *
aftoinfo(int af)
{
    switch (af)
    {
	case AF_INET:
	    return &af_inet4_info;
	case AF_INET6:
	    return &af_inet6_info;
	default:
	    return NULL;
    }
}

bool
subnetisnone(const ip_subnet *sn)
{
    ip_address base;

    networkof(sn, &base);
    return isanyaddr(&base) && subnetishost(sn);
}

/* BIND enumerated types */

#include <arpa/nameser.h>

static const char *const rr_type_name[] = {
	"T_A",	/* 1 host address */
	"T_NS",	/* 2 authoritative server */
	"T_MD",	/* 3 mail destination */
	"T_MF",	/* 4 mail forwarder */
	"T_CNAME",	/* 5 canonical name */
	"T_SOA",	/* 6 start of authority zone */
	"T_MB",	/* 7 mailbox domain name */
	"T_MG",	/* 8 mail group member */
	"T_MR",	/* 9 mail rename name */
	"T_NULL",	/* 10 null resource record */
	"T_WKS",	/* 11 well known service */
	"T_PTR",	/* 12 domain name pointer */
	"T_HINFO",	/* 13 host information */
	"T_MINFO",	/* 14 mailbox information */
	"T_MX",	/* 15 mail routing information */
	"T_TXT",	/* 16 text strings */
	"T_RP",	/* 17 responsible person */
	"T_AFSDB",	/* 18 AFS cell database */
	"T_X25",	/* 19 X_25 calling address */
	"T_ISDN",	/* 20 ISDN calling address */
	"T_RT",	/* 21 router */
	"T_NSAP",	/* 22 NSAP address */
	"T_NSAP_PTR",	/* 23 reverse NSAP lookup (deprecated) */
	"T_SIG",	/* 24 security signature */
	"T_KEY",	/* 25 security key */
	"T_PX",	/* 26 X.400 mail mapping */
	"T_GPOS",	/* 27 geographical position (withdrawn) */
	"T_AAAA",	/* 28 IP6 Address */
	"T_LOC",	/* 29 Location Information */
	"T_NXT",	/* 30 Next Valid Name in Zone */
	"T_EID",	/* 31 Endpoint identifier */
	"T_NIMLOC",	/* 32 Nimrod locator */
	"T_SRV",	/* 33 Server selection */
	"T_ATMA",	/* 34 ATM Address */
	"T_NAPTR",	/* 35 Naming Authority PoinTeR */
	NULL
    };

enum_names rr_type_names = { ns_t_a, ns_t_naptr, rr_type_name, NULL };

/* Query type values which do not appear in resource records */
static const char *const rr_qtype_name[] = {
    "T_TKEY",           /* 249 transaction key */
    "TSIG",             /* 250 transaction signature */
	"T_IXFR",	/* 251 incremental zone transfer */
	"T_AXFR",	/* 252 transfer zone of authority */
	"T_MAILB",	/* 253 transfer mailbox records */
	"T_MAILA",	/* 254 transfer mail agent records */
	"T_ANY",	/* 255 wildcard match */
	NULL
    };

enum_names rr_qtype_names = { ns_t_tkey, ns_t_any
			      , rr_qtype_name, &rr_type_names };

static const char *const rr_class_name[] = {
	"C_IN",	/* 1 the arpa internet */
	NULL
    };

enum_names rr_class_names = { ns_c_in, ns_c_in, rr_class_name, NULL };

static const char *const ppk_name[] = {
  "PPK_PSK",
  "PPK_DSS",
  "PPK_RSA",
  "PPK_PIN",
  "PPK_XAUTH",
  NULL
};

enum_names ppk_names = { PPK_PSK, PPK_XAUTH, ppk_name, NULL };

/*
 * NAT-Traversal defines for nat_traveral type from nat_traversal.h
 *
 */
const char *const natt_type_bitnames[] = {
  "draft-ietf-ipsec-nat-t-ike-00/01",    /* 0 */
  "draft-ietf-ipsec-nat-t-ike-02/03",
  "draft-ietf-ipsec-nat-t-ike-05",
  "draft-ietf-ipsec-nat-t-ike (MacOS X)",
  "RFC 3947 (NAT-Traversal)",		/* 4 */
  "4",   "5",   "6",   "7",
  "8",   "9",   "10",  "11",
  "12",  "13",  "14",  "15",
  "16",  "17",  "18",  "19",
  "20",  "21",  "22",  "23",
  "24",  "25",  "26",  "27",
  "28",  "29",
  "nat is behind me",
  "nat is behind peer"
};


/*
 * Values for right= and left=
 */
struct keyword_enum_value kw_host_values[]={
    { "%defaultroute",  KH_DEFAULTROUTE },
    { "%any",           KH_ANY },
    { "%",              KH_IFACE },
    { "%oppo",          KH_OPPO },
    { "%opportunistic", KH_OPPO },
    { "%opportunisticgroup", KH_OPPOGROUP },
    { "%oppogroup",     KH_OPPOGROUP },
    { "%group",         KH_GROUP },
    { "%hostname",      KH_IPHOSTNAME },  /* makes no sense on input */
};

struct keyword_enum_values kw_host_list=
    { kw_host_values, sizeof(kw_host_values)/sizeof(struct keyword_enum_value)};


/* look up enum names in an enum_names */

const char *
enum_name(enum_names *ed, unsigned long val)
{
    enum_names	*p;

    for (p = ed; p != NULL; p = p->en_next_range)
	if (p->en_first <= val && val <= p->en_last)
	    return p->en_names[val - p->en_first];
    return NULL;
}

/* look up an enum in a starter friendly way */
const char *keyword_name(struct keyword_enum_values *kevs, unsigned int value)
{
    int kevcount;
    struct keyword_enum_value *kev;

    for(kevcount = kevs->valuesize, kev = kevs->values;
        kevcount > 0 && kev->value != value;
        kev++, kevcount--);

    passert(kevcount != 0);  /* for now */

    return kev->name;
}




/* find or construct a string to describe an enum value
 * Result may be in STATIC buffer!
 */
const char *
enum_show(enum_names *ed, unsigned long val)
{
    const char *p = enum_name(ed, val);

    if (p == NULL)
    {
	static char buf[12];	/* only one!  I hope that it is big enough */

	snprintf(buf, sizeof(buf), "%lu??", val);
	p = buf;
    }
    return p;
}


static char bitnamesbuf[200];   /* only one!  I hope that it is big enough! */

int
enum_search(enum_names *ed, const char *str)
{
    enum_names	*p;
    const char *ptr;
    unsigned en;

    for (p = ed; p != NULL; p = p->en_next_range)
	for (en=p->en_first; en<=p->en_last; en++) {
	    ptr=p->en_names[en - p->en_first];
	    if (ptr==0) continue;
	    /* if (strncmp(ptr, str, strlen(ptr))==0) */
	    if (strcmp(ptr, str)==0)
		    return en;
	}
    return -1;
}

/* construct a string to name the bits on in a set
 * Result may be in STATIC buffer!
 * Note: prettypolicy depends on internal details.
 */
const char *
bitnamesofb(const char *const table[], lset_t val
	    , char *b, size_t blen)
{
    char *p = b;
    lset_t bit;
    const char *const *tp;

    if (val == 0)
	return "none";

    for (tp = table, bit = 01; val != 0; bit <<= 1)
    {
	if (val & bit)
	{
	    const char *n = *tp;
	    size_t nl;

	    if (n == NULL || *n == '\0')
	    {
		/* no name for this bit, so use hex */
		static char flagbuf[sizeof("0x80000000")];

		snprintf(flagbuf, sizeof(flagbuf), "0x%llx", bit);
		n = flagbuf;
	    }

	    nl = strlen(n);

	    if (p != b && p < b+blen - 1)
		*p++ = '+';

	    if (b+blen - p > (ptrdiff_t)nl)
	    {
		strcpy(p, n);
		p += nl;
	    }
	    val -= bit;
	}
	if (*tp != NULL)
	    tp++;   /* move on, but not past end */
    }
    *p = '\0';
    return b;
}

const char *
bitnamesof(const char *const table[], lset_t val)
{
    return bitnamesofb(table, val, bitnamesbuf, sizeof(bitnamesbuf));
}

/* test a set by seeing if all bits have names */

bool
testset(const char *const table[], lset_t val)
{
    lset_t bit;
    const char *const *tp;

    for (tp = table, bit = 01; val != 0; bit <<= 1, tp++)
    {
	const char *n = *tp;

	if (n == NULL || ((val & bit) && *n == '\0'))
	    return FALSE;
	val &= ~bit;
    }
    return TRUE;
}


const char sparse_end[] = "end of sparse names";

/* look up enum names in a sparse_names */
const char *sparse_name(sparse_names sd, unsigned long val)
{
    const struct sparse_name *p;

    for (p = sd; p->name != sparse_end; p++)
	if (p->val == val)
	    return p->name;
    return NULL;
}

/* find or construct a string to describe an sparse value
 * Result may be in STATIC buffer!
 */
const char *
sparse_val_show(sparse_names sd, unsigned long val)
{
    const char *p = sparse_name(sd, val);

    if (p == NULL)
    {
	static char buf[12];	/* only one!  I hope that it is big enough */

	snprintf(buf, sizeof(buf), "%lu??", val);
	p = buf;
    }
    return p;
}

void init_constants(void)
{
    happy(anyaddr(AF_INET, &ipv4_any));
    happy(anyaddr(AF_INET6, &ipv6_any));

    happy(addrtosubnet(&ipv4_any, &ipv4_wildcard));
    happy(addrtosubnet(&ipv6_any, &ipv6_wildcard));

    happy(initsubnet(&ipv4_any, 0, '0', &ipv4_all));
    happy(initsubnet(&ipv6_any, 0, '0', &ipv6_all));
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
