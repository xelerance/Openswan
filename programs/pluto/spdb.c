/* Security Policy Data Base (such as it is)
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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
 * RCSID $Id: spdb.c,v 1.98.2.2 2004/04/16 12:33:10 mcr Exp $
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/queue.h>

#include <freeswan.h>
#include <freeswan/ipsec_policy.h>

#include "constants.h"
#include "defs.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "smartcard.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "connections.h"	/* needs id.h */
#include "state.h"
#include "packet.h"
#include "keys.h"
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "spdb.h"
#include "whack.h"	/* for RC_LOG_SERIOUS */

#include "sha1.h"
#include "md5.h"
#include "crypto.h" /* requires sha1.h and md5.h */

#define AD(x) x, elemsof(x)	/* Array Description */
#define AD_NULL NULL, 0

#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

/**************** Oakely (main mode) SA database ****************/

/*
 * the XAUTH server/client stuff is a bit confusing.
 * 
 * XAUTH overloads the RSA/PSK types with four more types which
 * mean RSA or PSK, but also include whether one is negotiating
 * that the inititator with be the XAUTH client, or the responder will be
 * XAUTH client. It seems unusual that the responder would be the one
 * to undergo XAUTH, since usually it is a roadwarrior to a gateway,
 *
 * however, the gateway may decide it needs to do a new phase 1, for
 * instance.
 *
 * So, when reading this, say "I'm an XAUTH client and I'm initiating",
 * or "I'm an XAUTH server and I'm initiating". Responses for the responder
 * (and validation of the response by the initiator) are determined by the
 * parse_sa_isakmp() part, which folds the XAUTH types into their native
 * types to figure out if it is acceptable to us.
 *
 */

/* arrays of attributes for transforms, preshared key */

static struct db_attr otpsk1024des3md5[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, OAKLEY_PRESHARED_KEY },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};

static struct db_attr otpsk1536des3md5[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, OAKLEY_PRESHARED_KEY },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otpsk1024des3sha[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA },
	{ OAKLEY_AUTHENTICATION_METHOD, OAKLEY_PRESHARED_KEY },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};

static struct db_attr otpsk1536des3sha[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA },
	{ OAKLEY_AUTHENTICATION_METHOD, OAKLEY_PRESHARED_KEY },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

/* arrays of attributes for transforms, preshared key, Xauth version */

#ifdef XAUTH
static struct db_attr otpsk1024des3md5_xauthc[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHInitPreShared },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};

static struct db_attr otpsk1536des3md5_xauthc[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHInitPreShared },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otpsk1024des3sha_xauthc[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHInitPreShared },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};

static struct db_attr otpsk1536des3sha_xauthc[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHInitPreShared },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otpsk1024des3md5_xauths[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHRespPreShared },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};

static struct db_attr otpsk1536des3md5_xauths[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHRespPreShared },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otpsk1024des3sha_xauths[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHRespPreShared },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};

static struct db_attr otpsk1536des3sha_xauths[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHRespPreShared },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};
#endif

/* arrays of attributes for transforms, RSA signatures */

static struct db_attr otrsasig1024des3md5[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, OAKLEY_RSA_SIG },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};

static struct db_attr otrsasig1536des3md5[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, OAKLEY_RSA_SIG },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otrsasig1024des3sha[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA },
	{ OAKLEY_AUTHENTICATION_METHOD, OAKLEY_RSA_SIG },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};

static struct db_attr otrsasig1536des3sha[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA },
	{ OAKLEY_AUTHENTICATION_METHOD, OAKLEY_RSA_SIG },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

#ifdef XAUTH
/* arrays of attributes for transforms, RSA signatures, with/Xauth */
/* xauth c is when Initiator will be the xauth client */
static struct db_attr otrsasig1024des3md5_xauthc[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHInitRSA },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};

static struct db_attr otrsasig1536des3md5_xauthc[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHInitRSA },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otrsasig1024des3sha_xauthc[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHInitRSA },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};

static struct db_attr otrsasig1536des3sha_xauthc[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHInitRSA },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

/* arrays of attributes for transforms, RSA signatures, with/Xauth */
/*
 * xauth s is when the Responder will be the xauth client
 * the only time we do this is when we are initiating to a client
 * that we lost contact with. this is rare.
 */
static struct db_attr otrsasig1024des3md5_xauths[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHRespRSA },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};

static struct db_attr otrsasig1536des3md5_xauths[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHInitRSA },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otrsasig1024des3sha_xauths[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHRespRSA },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};

static struct db_attr otrsasig1536des3sha_xauths[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHRespRSA },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};
#endif

/* We won't accept this, but by proposing it, we get to test
 * our rejection.  We better not propose it to an IKE daemon
 * that will accept it!
 */
#ifdef TEST_INDECENT_PROPOSAL
static struct db_attr otpsk1024des3tiger[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_TIGER },
	{ OAKLEY_AUTHENTICATION_METHOD, OAKLEY_PRESHARED_KEY },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};
#endif /* TEST_INDECENT_PROPOSAL */

/* tables of transforms, in preference order (select based on AUTH) */

static struct db_trans oakley_trans_psk[] = {
#ifdef TEST_INDECENT_PROPOSAL
	{ KEY_IKE, AD(otpsk1024des3tiger) },
#endif
	{ KEY_IKE, AD(otpsk1536des3md5) },
	{ KEY_IKE, AD(otpsk1536des3sha) },
	{ KEY_IKE, AD(otpsk1024des3sha) },
	{ KEY_IKE, AD(otpsk1024des3md5) },
    };

#ifdef XAUTH
static struct db_trans oakley_trans_psk_xauthc[] = {
	{ KEY_IKE, AD(otpsk1536des3md5_xauthc) },
	{ KEY_IKE, AD(otpsk1536des3sha_xauthc) },
	{ KEY_IKE, AD(otpsk1024des3sha_xauthc) },
	{ KEY_IKE, AD(otpsk1024des3md5_xauthc) },
    };
static struct db_trans oakley_trans_psk_xauths[] = {
	{ KEY_IKE, AD(otpsk1536des3md5_xauths) },
	{ KEY_IKE, AD(otpsk1536des3sha_xauths) },
	{ KEY_IKE, AD(otpsk1024des3sha_xauths) },
	{ KEY_IKE, AD(otpsk1024des3md5_xauths) },
    };
#endif

static struct db_trans oakley_trans_rsasig[] = {
	{ KEY_IKE, AD(otrsasig1536des3md5) },
	{ KEY_IKE, AD(otrsasig1536des3sha) },
	{ KEY_IKE, AD(otrsasig1024des3sha) },
	{ KEY_IKE, AD(otrsasig1024des3md5) },
    };

#ifdef XAUTH
static struct db_trans oakley_trans_rsasig_xauthc[] = {
	{ KEY_IKE, AD(otrsasig1536des3md5_xauthc) },
	{ KEY_IKE, AD(otrsasig1536des3sha_xauthc) },
	{ KEY_IKE, AD(otrsasig1024des3sha_xauthc) },
	{ KEY_IKE, AD(otrsasig1024des3md5_xauthc) },
    };
static struct db_trans oakley_trans_rsasig_xauths[] = {
	{ KEY_IKE, AD(otrsasig1536des3md5_xauths) },
	{ KEY_IKE, AD(otrsasig1536des3sha_xauths) },
	{ KEY_IKE, AD(otrsasig1024des3sha_xauths) },
	{ KEY_IKE, AD(otrsasig1024des3md5_xauths) },
    };
#endif

/* In this table, either PSK or RSA sig is accepted.
 * The order matters, but I don't know what would be best.
 */
static struct db_trans oakley_trans_pskrsasig[] = {
#ifdef TEST_INDECENT_PROPOSAL
	{ KEY_IKE, AD(otpsk1024des3tiger) },
#endif
	{ KEY_IKE, AD(otrsasig1536des3md5) },
	{ KEY_IKE, AD(otpsk1536des3md5) },
	{ KEY_IKE, AD(otrsasig1536des3sha) },
	{ KEY_IKE, AD(otpsk1536des3sha) },
	{ KEY_IKE, AD(otrsasig1024des3sha) },
	{ KEY_IKE, AD(otpsk1024des3sha) },
	{ KEY_IKE, AD(otrsasig1024des3md5) },
	{ KEY_IKE, AD(otpsk1024des3md5) },
    };

#ifdef XAUTH
static struct db_trans oakley_trans_pskrsasig_xauthc[] = {
	{ KEY_IKE, AD(otrsasig1536des3md5_xauthc) },
	{ KEY_IKE, AD(otpsk1536des3md5_xauthc) },
	{ KEY_IKE, AD(otrsasig1536des3sha_xauthc) },
	{ KEY_IKE, AD(otpsk1536des3sha_xauthc) },
	{ KEY_IKE, AD(otrsasig1024des3sha_xauthc) },
	{ KEY_IKE, AD(otpsk1024des3sha_xauthc) },
	{ KEY_IKE, AD(otrsasig1024des3md5_xauthc) },
	{ KEY_IKE, AD(otpsk1024des3md5_xauthc) },
    };

static struct db_trans oakley_trans_pskrsasig_xauths[] = {
	{ KEY_IKE, AD(otrsasig1536des3md5_xauths) },
	{ KEY_IKE, AD(otpsk1536des3md5_xauths) },
	{ KEY_IKE, AD(otrsasig1536des3sha_xauths) },
	{ KEY_IKE, AD(otpsk1536des3sha_xauths) },
	{ KEY_IKE, AD(otrsasig1024des3sha_xauths) },
	{ KEY_IKE, AD(otpsk1024des3sha_xauths) },
	{ KEY_IKE, AD(otrsasig1024des3md5_xauths) },
	{ KEY_IKE, AD(otpsk1024des3md5_xauths) },
    };
#endif

/* array of proposals to be conjoined (can only be one for Oakley) */

static struct db_prop oakley_pc_psk[] =
    { { PROTO_ISAKMP, AD(oakley_trans_psk) } };

static struct db_prop oakley_pc_rsasig[] =
    { { PROTO_ISAKMP, AD(oakley_trans_rsasig) } };

static struct db_prop oakley_pc_pskrsasig[] =
    { { PROTO_ISAKMP, AD(oakley_trans_pskrsasig) } };

#ifdef XAUTH
static struct db_prop oakley_pc_psk_xauths[] =
    { { PROTO_ISAKMP, AD(oakley_trans_psk_xauths) } };

static struct db_prop oakley_pc_rsasig_xauths[] =
    { { PROTO_ISAKMP, AD(oakley_trans_rsasig_xauths) } };

static struct db_prop oakley_pc_pskrsasig_xauths[] =
    { { PROTO_ISAKMP, AD(oakley_trans_pskrsasig_xauths) } };

static struct db_prop oakley_pc_psk_xauthc[] =
    { { PROTO_ISAKMP, AD(oakley_trans_psk_xauthc) } };

static struct db_prop oakley_pc_rsasig_xauthc[] =
    { { PROTO_ISAKMP, AD(oakley_trans_rsasig_xauthc) } };

static struct db_prop oakley_pc_pskrsasig_xauthc[] =
    { { PROTO_ISAKMP, AD(oakley_trans_pskrsasig_xauthc) } };
#endif

/* array of proposal conjuncts (can only be one) */

static struct db_prop_conj oakley_props_psk[] = { { AD(oakley_pc_psk) } };

static struct db_prop_conj oakley_props_rsasig[] = { { AD(oakley_pc_rsasig) } };

static struct db_prop_conj oakley_props_pskrsasig[] = { { AD(oakley_pc_pskrsasig) } };

#ifdef XAUTH
static struct db_prop_conj oakley_props_psk_xauthc[] = { { AD(oakley_pc_psk_xauthc) } };

static struct db_prop_conj oakley_props_rsasig_xauthc[] = { { AD(oakley_pc_rsasig_xauthc) } };

static struct db_prop_conj oakley_props_pskrsasig_xauthc[] = { { AD(oakley_pc_pskrsasig_xauthc) } };

static struct db_prop_conj oakley_props_psk_xauths[] = { { AD(oakley_pc_psk_xauths) } };

static struct db_prop_conj oakley_props_rsasig_xauths[] = { { AD(oakley_pc_rsasig_xauths) } };

static struct db_prop_conj oakley_props_pskrsasig_xauths[] = { { AD(oakley_pc_pskrsasig_xauths) } };
#endif

/* the sadb entry, subscripted by POLICY_PSK and POLICY_RSASIG bits */
struct db_sa oakley_sadb[] = {
    { AD_NULL },	                /* none */
    { AD(oakley_props_psk) },	        /* POLICY_PSK */
    { AD(oakley_props_rsasig) },	/* POLICY_RSASIG */
    { AD(oakley_props_pskrsasig) },	/* POLICY_PSK + POLICY_RSASIG */
#ifdef XAUTH
    { AD_NULL },                        /* POLICY_XAUTHSERVER + none */
    { AD(oakley_props_psk_xauths) },    /* POLICY_XAUTHSERVER + PSK */
    { AD(oakley_props_rsasig_xauths) }, /* POLICY_XAUTHSERVER + RSA */
    { AD(oakley_props_pskrsasig_xauths)},/* POLICY_XAUTHSERVER + RSA+PSK */
    { AD_NULL },                        /* POLICY_XAUTHCLIENT + none */
    { AD(oakley_props_psk_xauthc) },    /* POLICY_XAUTHCLIENT + PSK */
    { AD(oakley_props_rsasig_xauthc)},  /* POLICY_XAUTHCLIENT + RSA */
    { AD(oakley_props_pskrsasig_xauthc)},/* POLICY_XAUTHCLIENT + RSA+PSK */
    { AD_NULL },                        /* XAUTHCLIENT+XAUTHSERVER + none */
    { AD_NULL },                        /* XAUTHCLIENT+XAUTHSERVER + PSK */
    { AD_NULL },                        /* XAUTHCLIENT+XAUTHSERVER + RSA */
    { AD_NULL },                        /* XAUTHCLIENT+XAUTHSERVER + RSA+PSK */
#else /* XAUTH */
    { AD_NULL },                        /* POLICY_XAUTHSERVER + none */
    { AD_NULL },                        /* POLICY_XAUTHSERVER + PSK */
    { AD_NULL },                        /* POLICY_XAUTHSERVER + RSA */
    { AD_NULL },                        /* POLICY_XAUTHSERVER + RSA+PSK */
    { AD_NULL },                        /* POLICY_XAUTHCLIENT + none */
    { AD_NULL },                        /* POLICY_XAUTHCLIENT + PSK */
    { AD_NULL },                        /* POLICY_XAUTHCLIENT + RSA */
    { AD_NULL },                        /* POLICY_XAUTHCLIENT + RSA+PSK */
    { AD_NULL },                        /* XAUTHCLIENT+XAUTHSERVER + none */
    { AD_NULL },                        /* XAUTHCLIENT+XAUTHSERVER + PSK */
    { AD_NULL },                        /* XAUTHCLIENT+XAUTHSERVER + RSA */
    { AD_NULL },                        /* XAUTHCLIENT+XAUTHSERVER + RSA+PSK */
#endif /* XAUTH */
    };

/**************** IPsec (quick mode) SA database ****************/

/* arrays of attributes for transforms */

static struct db_attr espmd5_attr[] = {
    { AUTH_ALGORITHM, AUTH_ALGORITHM_HMAC_MD5 },
    };

static struct db_attr espsha1_attr[] = {
    { AUTH_ALGORITHM, AUTH_ALGORITHM_HMAC_SHA1 },
    };

static struct db_attr ah_HMAC_MD5_attr[] = {
    { AUTH_ALGORITHM, AUTH_ALGORITHM_HMAC_MD5 },
    };

static struct db_attr ah_HMAC_SHA1_attr[] = {
    { AUTH_ALGORITHM, AUTH_ALGORITHM_HMAC_SHA1 },
    };

/* arrays of transforms, each in in preference order */

static struct db_trans espa_trans[] = {
    { ESP_3DES, AD(espmd5_attr) },
    { ESP_3DES, AD(espsha1_attr) },
    };

static struct db_trans esp_trans[] = {
    { ESP_3DES, AD_NULL },
    };

#ifdef SUPPORT_ESP_NULL
static struct db_trans espnull_trans[] = {
    { ESP_NULL, AD(espmd5_attr) },
    { ESP_NULL, AD(espsha1_attr) },
    };
#endif /* SUPPORT_ESP_NULL */

static struct db_trans ah_trans[] = {
    { AH_MD5, AD(ah_HMAC_MD5_attr) },
    { AH_SHA, AD(ah_HMAC_SHA1_attr) },
    };

static struct db_trans ipcomp_trans[] = {
    { IPCOMP_DEFLATE, AD_NULL },
    };

/* arrays of proposals to be conjoined */

static struct db_prop ah_pc[] = {
    { PROTO_IPSEC_AH, AD(ah_trans) },
    };

#ifdef SUPPORT_ESP_NULL
static struct db_prop espnull_pc[] = {
    { PROTO_IPSEC_ESP, AD(espnull_trans) },
    };
#endif /* SUPPORT_ESP_NULL */

static struct db_prop esp_pc[] = {
    { PROTO_IPSEC_ESP, AD(espa_trans) },
    };

static struct db_prop ah_esp_pc[] = {
    { PROTO_IPSEC_AH, AD(ah_trans) },
    { PROTO_IPSEC_ESP, AD(esp_trans) },
    };

static struct db_prop compress_pc[] = {
    { PROTO_IPCOMP, AD(ipcomp_trans) },
    };

static struct db_prop ah_compress_pc[] = {
    { PROTO_IPSEC_AH, AD(ah_trans) },
    { PROTO_IPCOMP, AD(ipcomp_trans) },
    };

#ifdef SUPPORT_ESP_NULL
static struct db_prop espnull_compress_pc[] = {
    { PROTO_IPSEC_ESP, AD(espnull_trans) },
    { PROTO_IPCOMP, AD(ipcomp_trans) },
    };
#endif /* SUPPORT_ESP_NULL */

static struct db_prop esp_compress_pc[] = {
    { PROTO_IPSEC_ESP, AD(espa_trans) },
    { PROTO_IPCOMP, AD(ipcomp_trans) },
    };

static struct db_prop ah_esp_compress_pc[] = {
    { PROTO_IPSEC_AH, AD(ah_trans) },
    { PROTO_IPSEC_ESP, AD(esp_trans) },
    { PROTO_IPCOMP, AD(ipcomp_trans) },
    };

/* arrays of proposal alternatives (each element is a conjunction) */

static struct db_prop_conj ah_props[] = {
    { AD(ah_pc) },
#ifdef SUPPORT_ESP_NULL
    { AD(espnull_pc) }
#endif
    };

static struct db_prop_conj esp_props[] =
    { { AD(esp_pc) } };

static struct db_prop_conj ah_esp_props[] =
    { { AD(ah_esp_pc) } };

static struct db_prop_conj compress_props[] = {
    { AD(compress_pc) },
    };

static struct db_prop_conj ah_compress_props[] = {
    { AD(ah_compress_pc) },
#ifdef SUPPORT_ESP_NULL
    { AD(espnull_compress_pc) }
#endif
    };

static struct db_prop_conj esp_compress_props[] =
    { { AD(esp_compress_pc) } };

static struct db_prop_conj ah_esp_compress_props[] =
    { { AD(ah_esp_compress_pc) } };

/* The IPsec sadb is subscripted by a bitset (subset of policy)
 * with members from { POLICY_ENCRYPT, POLICY_AUTHENTICATE, POLICY_COMPRESS }
 * shifted right by POLICY_IPSEC_SHIFT.
 */
struct db_sa ipsec_sadb[1 << 3] = {
    { AD_NULL },	/* none */
    { AD(esp_props) },	/* POLICY_ENCRYPT */
    { AD(ah_props) },	/* POLICY_AUTHENTICATE */
    { AD(ah_esp_props) },	/* POLICY_ENCRYPT+POLICY_AUTHENTICATE */
    { AD(compress_props) },	/* POLICY_COMPRESS */
    { AD(esp_compress_props) },	/* POLICY_ENCRYPT+POLICY_COMPRESS */
    { AD(ah_compress_props) },	/* POLICY_AUTHENTICATE+POLICY_COMPRESS */
    { AD(ah_esp_compress_props) },	/* POLICY_ENCRYPT+POLICY_AUTHENTICATE+POLICY_COMPRESS */
    };

#undef AD
#undef AD_NULL

/* output an attribute (within an SA) */
static bool
out_attr(int type
, unsigned long val
, struct_desc *attr_desc
, enum_names **attr_val_descs USED_BY_DEBUG
, pb_stream *pbs)
{
    struct isakmp_attribute attr;

    if (val >> 16 == 0)
    {
	/* short value: use TV form */
	attr.isaat_af_type = type | ISAKMP_ATTR_AF_TV;
	attr.isaat_lv = val;
	if (!out_struct(&attr, attr_desc, pbs, NULL))
	    return FALSE;
    }
    else
    {
	/* This is a real fudge!  Since we rarely use long attributes
	 * and since this is the only place where we can cause an
	 * ISAKMP message length to be other than a multiple of 4 octets,
	 * we force the length of the value to be a multiple of 4 octets.
	 * Furthermore, we only handle values up to 4 octets in length.
	 * Voila: a fixed format!
	 */
	pb_stream val_pbs;
	u_int32_t nval = htonl(val);

	attr.isaat_af_type = type | ISAKMP_ATTR_AF_TLV;
	if (!out_struct(&attr, attr_desc, pbs, &val_pbs)
	|| !out_raw(&nval, sizeof(nval), &val_pbs, "long attribute value"))
	    return FALSE;
	close_output_pbs(&val_pbs);
    }
    DBG(DBG_EMITTING,
	enum_names *d = attr_val_descs[type];

	if (d != NULL)
	    DBG_log("    [%lu is %s]"
		, val, enum_show(d, val)));
    return TRUE;
}

/* Output an SA, as described by a db_sa.
 * This has the side-effect of allocating SPIs for us.
 */
bool
out_sa(pb_stream *outs
, struct db_sa *sadb
, struct state *st
, bool oakley_mode
, u_int8_t np)
{
    pb_stream sa_pbs;
    int pcn;
    bool ah_spi_generated = FALSE
	, esp_spi_generated = FALSE
	, ipcomp_cpi_generated = FALSE;

    /* SA header out */
    {
	struct isakmp_sa sa;

	sa.isasa_np = np;
	st->st_doi = sa.isasa_doi = ISAKMP_DOI_IPSEC;	/* all we know */
	if (!out_struct(&sa, &isakmp_sa_desc, outs, &sa_pbs))
	    return FALSE;
    }

    /* within SA: situation out */
    st->st_situation = SIT_IDENTITY_ONLY;
    if (!out_struct(&st->st_situation, &ipsec_sit_desc, &sa_pbs, NULL))
	return FALSE;

    /* within SA: Proposal Payloads
     *
     * Multiple Proposals with the same number are simultaneous
     * (conjuncts) and must deal with different protocols (AH or ESP).
     * Proposals with different numbers are alternatives (disjuncts),
     * in preference order.
     * Proposal numbers must be monotonic.
     * See RFC 2408 "ISAKMP" 4.2
     */

    for (pcn = 0; pcn != sadb->prop_conj_cnt; pcn++)
    {
	struct db_prop_conj *pc = &sadb->prop_conjs[pcn];
	int pn;

	for (pn = 0; pn != pc->prop_cnt; pn++)
	{
	    struct db_prop *p = &pc->props[pn];
	    pb_stream proposal_pbs;
	    struct isakmp_proposal proposal;
	    struct_desc *trans_desc;
	    struct_desc *attr_desc;
	    enum_names **attr_val_descs;
	    int tn;
	    bool tunnel_mode;

	    tunnel_mode = (pn == pc->prop_cnt-1)
		&& (st->st_policy & POLICY_TUNNEL);

	    /* Proposal header */
	    proposal.isap_np = pcn == sadb->prop_conj_cnt-1 && pn == pc->prop_cnt-1
		? ISAKMP_NEXT_NONE : ISAKMP_NEXT_P;
	    proposal.isap_proposal = pcn;
	    proposal.isap_protoid = p->protoid;
	    proposal.isap_spisize = oakley_mode ? 0
		: p->protoid == PROTO_IPCOMP ? IPCOMP_CPI_SIZE
		: IPSEC_DOI_SPI_SIZE;
	    proposal.isap_notrans = p->trans_cnt;
	    if (!out_struct(&proposal, &isakmp_proposal_desc, &sa_pbs, &proposal_pbs))
		return FALSE;

	    /* Per-protocols stuff:
	     * Set trans_desc.
	     * Set attr_desc.
	     * Set attr_val_descs.
	     * If not oakley_mode, emit SPI.
	     * We allocate SPIs on demand.
	     * All ESPs in an SA will share a single SPI.
	     * All AHs in an SAwill share a single SPI.
	     * AHs' SPI will be distinct from ESPs'.
	     * This latter is needed because KLIPS doesn't
	     * use the protocol when looking up a (dest, protocol, spi).
	     * ??? If multiple ESPs are composed, how should their SPIs
	     * be allocated?
	     */
	    {
		ipsec_spi_t *spi_ptr = NULL;
		int proto = 0;
		bool *spi_generated;

		switch (p->protoid)
		{
		case PROTO_ISAKMP:
		    passert(oakley_mode);
		    trans_desc = &isakmp_isakmp_transform_desc;
		    attr_desc = &isakmp_oakley_attribute_desc;
		    attr_val_descs = oakley_attr_val_descs;
		    /* no SPI needed */
		    break;
		case PROTO_IPSEC_AH:
		    passert(!oakley_mode);
		    trans_desc = &isakmp_ah_transform_desc;
		    attr_desc = &isakmp_ipsec_attribute_desc;
		    attr_val_descs = ipsec_attr_val_descs;
		    spi_ptr = &st->st_ah.our_spi;
		    spi_generated = &ah_spi_generated;
		    proto = IPPROTO_AH;
		    break;
		case PROTO_IPSEC_ESP:
		    passert(!oakley_mode);
		    trans_desc = &isakmp_esp_transform_desc;
		    attr_desc = &isakmp_ipsec_attribute_desc;
		    attr_val_descs = ipsec_attr_val_descs;
		    spi_ptr = &st->st_esp.our_spi;
		    spi_generated = &esp_spi_generated;
		    proto = IPPROTO_ESP;
		    break;
		case PROTO_IPCOMP:
		    passert(!oakley_mode);
		    trans_desc = &isakmp_ipcomp_transform_desc;
		    attr_desc = &isakmp_ipsec_attribute_desc;
		    attr_val_descs = ipsec_attr_val_descs;

		    /* a CPI isn't quite the same as an SPI
		     * so we use specialized code to emit it.
		     */
		    if (!ipcomp_cpi_generated)
		    {
			st->st_ipcomp.our_spi = get_my_cpi(
			    &st->st_connection->spd, tunnel_mode);
			if (st->st_ipcomp.our_spi == 0)
			    return FALSE;	/* problem generating CPI */

			ipcomp_cpi_generated = TRUE;
		    }
		    /* CPI is stored in network low order end of an
		     * ipsec_spi_t.  So we start a couple of bytes in.
		     */
		    if (!out_raw((u_char *)&st->st_ipcomp.our_spi
		     + IPSEC_DOI_SPI_SIZE - IPCOMP_CPI_SIZE
		    , IPCOMP_CPI_SIZE
		    , &proposal_pbs, "CPI"))
			return FALSE;
		    break;
		default:
		    bad_case(p->protoid);
		}
		if (spi_ptr != NULL)
		{
		    if (!*spi_generated)
		    {
			*spi_ptr = get_ipsec_spi(0
			    , proto
			    , &st->st_connection->spd
			    , tunnel_mode);
			if (*spi_ptr == 0)
			    return FALSE;
			*spi_generated = TRUE;
		    }
		    if (!out_raw((u_char *)spi_ptr, IPSEC_DOI_SPI_SIZE
		    , &proposal_pbs, "SPI"))
			return FALSE;
		}
	    }

	    /* within proposal: Transform Payloads */
	    for (tn = 0; tn != p->trans_cnt; tn++)
	    {
		struct db_trans *t = &p->trans[tn];
		pb_stream trans_pbs;
		struct isakmp_transform trans;
		int an;

		trans.isat_np = (tn == p->trans_cnt - 1)
		    ? ISAKMP_NEXT_NONE : ISAKMP_NEXT_T;
		trans.isat_transnum = tn;
		trans.isat_transid = t->transid;
		if (!out_struct(&trans, trans_desc, &proposal_pbs, &trans_pbs))
		    return FALSE;

		/* Within tranform: Attributes. */

		/* For Phase 2 / Quick Mode, GROUP_DESCRIPTION is
		 * automatically generated because it must be the same
		 * in every transform.  Except IPCOMP.
		 */
		if (p->protoid != PROTO_IPCOMP
		&& st->st_pfs_group != NULL)
		{
		    passert(!oakley_mode);
		    passert(st->st_pfs_group != &unset_group);
		    out_attr(GROUP_DESCRIPTION, st->st_pfs_group->group
			, attr_desc, attr_val_descs
			, &trans_pbs);
		}

		/* automatically generate duration
		 * and, for Phase 2 / Quick Mode, encapsulation.
		 */
		if (oakley_mode)
		{
		    out_attr(OAKLEY_LIFE_TYPE, OAKLEY_LIFE_SECONDS
			, attr_desc, attr_val_descs
			, &trans_pbs);
		    out_attr(OAKLEY_LIFE_DURATION
			, st->st_connection->sa_ike_life_seconds
			, attr_desc, attr_val_descs
			, &trans_pbs);
		}
		else
		{
		    /* RFC 2407 (IPSEC DOI) 4.5 specifies that
		     * the default is "unspecified (host-dependent)".
		     * This makes little sense, so we always specify it.
		     *
		     * Unlike other IPSEC transforms, IPCOMP defaults
		     * to Transport Mode, so we can exploit the default
		     * (draft-shacham-ippcp-rfc2393bis-05.txt 4.1).
		     */
		    if (p->protoid != PROTO_IPCOMP
		    || st->st_policy & POLICY_TUNNEL)
		    {
#ifdef NAT_TRAVERSAL
#ifndef I_KNOW_TRANSPORT_MODE_HAS_SECURITY_CONCERN_BUT_I_WANT_IT
			if ((st->nat_traversal & NAT_T_DETECTED) &&
				(!(st->st_policy & POLICY_TUNNEL))) {
				/* Inform user that we will not respect policy and only
				 * propose Tunnel Mode
				 */
				loglog(RC_LOG_SERIOUS, "NAT-Traversal: "
					"Transport Mode not allowed due to security concerns -- "
					"using Tunnel mode");
			}
#endif
#endif
			out_attr(ENCAPSULATION_MODE
#ifdef NAT_TRAVERSAL
#ifdef I_KNOW_TRANSPORT_MODE_HAS_SECURITY_CONCERN_BUT_I_WANT_IT
			    , NAT_T_ENCAPSULATION_MODE(st,st->st_policy)
#else
				/* If NAT-T is detected, use UDP_TUNNEL as long as Transport
				 * Mode has security concerns.
				 *
				 * User has been informed of that
				 */
			    , NAT_T_ENCAPSULATION_MODE(st,POLICY_TUNNEL)
#endif
#else /* ! NAT_TRAVERSAL */
			    , st->st_policy & POLICY_TUNNEL
			      ? ENCAPSULATION_MODE_TUNNEL : ENCAPSULATION_MODE_TRANSPORT
#endif
			    , attr_desc, attr_val_descs
			    , &trans_pbs);
		    }
		    out_attr(SA_LIFE_TYPE, SA_LIFE_TYPE_SECONDS
			, attr_desc, attr_val_descs
			, &trans_pbs);
		    out_attr(SA_LIFE_DURATION
			, st->st_connection->sa_ipsec_life_seconds
			, attr_desc, attr_val_descs
			, &trans_pbs);
		}

		/* spit out attributes from table */
		for (an = 0; an != t->attr_cnt; an++)
		{
		    struct db_attr *a = &t->attrs[an];

		    out_attr(a->type, a->val
			, attr_desc, attr_val_descs
			, &trans_pbs);
		}

		close_output_pbs(&trans_pbs);
	    }
	    close_output_pbs(&proposal_pbs);
	}
	/* end of a conjunction of proposals */
    }
    close_output_pbs(&sa_pbs);
    return TRUE;
}

/* Handle long form of duration attribute.
 * The code is can only handle values that can fit in unsigned long.
 * "Clamping" is probably an acceptable way to impose this limitation.
 */
static u_int32_t
decode_long_duration(pb_stream *pbs)
{
    u_int32_t val = 0;

    /* ignore leading zeros */
    while (pbs_left(pbs) != 0 && *pbs->cur == '\0')
	pbs->cur++;

    if (pbs_left(pbs) > sizeof(val))
    {
	/* "clamp" too large value to max representable value */
	val -= 1;	/* portable way to get to maximum value */
	DBG(DBG_PARSING, DBG_log("   too large duration clamped to: %lu"
	    , (unsigned long)val));
    }
    else
    {
	/* decode number */
	while (pbs_left(pbs) != 0)
	    val = (val << BITS_PER_BYTE) | *pbs->cur++;
	DBG(DBG_PARSING, DBG_log("   long duration: %lu", (unsigned long)val));
    }
    return val;
}

/* Parse the body of an ISAKMP SA Payload (i.e. Phase 1 / Main Mode).
 * Various shortcuts are taken.  In particular, the policy, such as
 * it is, is hardwired.
 *
 * If r_sa is non-NULL, the body of an SA representing the selected
 * proposal is emitted.
 *
 * If "selection" is true, the SA is supposed to represent the
 * single tranform that the peer has accepted.
 * ??? We only check that it is acceptable, not that it is one that we offered!
 *
 * It also means that we are inR1, and this as implications when we are
 * doing XAUTH, as it changes the meaning of the XAUTHInit/XAUTHResp.
 *
 * Only IPsec DOI is accepted (what is the ISAKMP DOI?).
 * Error response is rudimentary.
 *
 * This routine is used by main_inI1_outR1() and main_inR1_outI2().
 */
notification_t
parse_isakmp_sa_body(
    pb_stream *sa_pbs,	/* body of input SA Payload */
    const struct isakmp_sa *sa,	/* header of input SA Payload */
    pb_stream *r_sa_pbs,	/* if non-NULL, where to emit winning SA */
    bool selection,	/* if this SA is a selection, only one tranform
			 * can appear. */
    struct state *st)	/* current state object */
{
    u_int32_t ipsecdoisit;
    pb_stream proposal_pbs;
    struct isakmp_proposal proposal;
    unsigned no_trans_left;
    int last_transnum;
    struct connection *c = st->st_connection;
    struct spd_route *spd, *me = &c->spd;
    bool xauth_init, xauth_resp;
    const char *role;

    xauth_init = xauth_resp = FALSE;

    /* calculate the per-end policy which might apply */
    for(spd = me; spd; spd = spd->next) {
	if(selection)
	{ /* this is the initiator, we have proposed, they have answered,
	   * and we must decide if they proposed what we wanted.
	   */
	    role = "initiator";
	    xauth_init = xauth_init | spd->this.xauth_client;
	    xauth_resp = xauth_resp | spd->this.xauth_server;
	}
	else
	{ /* this is the responder, they have proposed to us, what
	   * are we willing to be?
	   */
	    role = "responder";
	    xauth_init = xauth_init | spd->this.xauth_server;
	    xauth_resp = xauth_resp | spd->this.xauth_client;
	}
    }

    /* DOI */
    if (sa->isasa_doi != ISAKMP_DOI_IPSEC)
    {
	loglog(RC_LOG_SERIOUS, "Unknown/unsupported DOI %s", enum_show(&doi_names, sa->isasa_doi));
	/* XXX Could send notification back */
	return DOI_NOT_SUPPORTED;
    }

    /* Situation */
    if (!in_struct(&ipsecdoisit, &ipsec_sit_desc, sa_pbs, NULL))
    {
	return SITUATION_NOT_SUPPORTED;
    }

    if (ipsecdoisit != SIT_IDENTITY_ONLY)
    {
	loglog(RC_LOG_SERIOUS, "unsupported IPsec DOI situation (%s)"
	    , bitnamesof(sit_bit_names, ipsecdoisit));
	/* XXX Could send notification back */
	return SITUATION_NOT_SUPPORTED;
    }

    /* The rules for ISAKMP SAs are scattered.
     * RFC 2409 "IKE" section 5 says that there
     * can only be one SA, and it can have only one proposal in it.
     * There may well be multiple transforms.
     */
    if (!in_struct(&proposal, &isakmp_proposal_desc, sa_pbs, &proposal_pbs))
	return PAYLOAD_MALFORMED;

    if (proposal.isap_np != ISAKMP_NEXT_NONE)
    {
	loglog(RC_LOG_SERIOUS, "Proposal Payload must be alone in Oakley SA; found %s following Proposal"
	    , enum_show(&payload_names, proposal.isap_np));
	return PAYLOAD_MALFORMED;
    }

    if (proposal.isap_protoid != PROTO_ISAKMP)
    {
	loglog(RC_LOG_SERIOUS, "unexpected Protocol ID (%s) found in Oakley Proposal"
	    , enum_show(&protocol_names, proposal.isap_protoid));
	return INVALID_PROTOCOL_ID;
    }

    /* Just what should we accept for the SPI field?
     * The RFC is sort of contradictory.  We will ignore the SPI
     * as long as it is of the proper size.
     *
     * From RFC2408 2.4 Identifying Security Associations:
     *   During phase 1 negotiations, the initiator and responder cookies
     *   determine the ISAKMP SA. Therefore, the SPI field in the Proposal
     *   payload is redundant and MAY be set to 0 or it MAY contain the
     *   transmitting entity's cookie.
     *
     * From RFC2408 3.5 Proposal Payload:
     *    o  SPI Size (1 octet) - Length in octets of the SPI as defined by
     *       the Protocol-Id.  In the case of ISAKMP, the Initiator and
     *       Responder cookie pair from the ISAKMP Header is the ISAKMP SPI,
     *       therefore, the SPI Size is irrelevant and MAY be from zero (0) to
     *       sixteen (16).  If the SPI Size is non-zero, the content of the
     *       SPI field MUST be ignored.  If the SPI Size is not a multiple of
     *       4 octets it will have some impact on the SPI field and the
     *       alignment of all payloads in the message.  The Domain of
     *       Interpretation (DOI) will dictate the SPI Size for other
     *       protocols.
     */
    if (proposal.isap_spisize == 0)
    {
	/* empty (0) SPI -- fine */
    }
    else if (proposal.isap_spisize <= MAX_ISAKMP_SPI_SIZE)
    {
	u_char junk_spi[MAX_ISAKMP_SPI_SIZE];

	if (!in_raw(junk_spi, proposal.isap_spisize, &proposal_pbs, "Oakley SPI"))
	    return PAYLOAD_MALFORMED;
    }
    else
    {
	loglog(RC_LOG_SERIOUS, "invalid SPI size (%u) in Oakley Proposal"
	    , (unsigned)proposal.isap_spisize);
	return INVALID_SPI;
    }

    if (selection && proposal.isap_notrans != 1)
    {
	loglog(RC_LOG_SERIOUS, "a single Transform is required in a selecting Oakley Proposal; found %u"
	    , (unsigned)proposal.isap_notrans);
	return BAD_PROPOSAL_SYNTAX;
    }

    /* for each transform payload... */

    last_transnum = -1;
    no_trans_left = proposal.isap_notrans;
    for (;;)
    {
	pb_stream trans_pbs;
	u_char *attr_start;
	size_t attr_len;
	struct isakmp_transform trans;
	lset_t seen_attrs = 0
	    , seen_durations = 0;
	u_int16_t life_type;
	struct oakley_trans_attrs ta;
	err_t ugh = NULL;	/* set to diagnostic when problem detected */
	zero(&ta);

	/* initialize only optional field in ta */
	ta.life_seconds = OAKLEY_ISAKMP_SA_LIFETIME_DEFAULT;	/* When this SA expires (seconds) */

	if (no_trans_left == 0)
	{
	    loglog(RC_LOG_SERIOUS, "number of Transform Payloads disagrees with Oakley Proposal Payload");
	    return BAD_PROPOSAL_SYNTAX;
	}

	if (!in_struct(&trans, &isakmp_isakmp_transform_desc, &proposal_pbs, &trans_pbs))
	    return BAD_PROPOSAL_SYNTAX;

	if (trans.isat_transnum <= last_transnum)
	{
	    /* picky, picky, picky */
	    loglog(RC_LOG_SERIOUS, "Transform Numbers are not monotonically increasing"
		" in Oakley Proposal");
	    return BAD_PROPOSAL_SYNTAX;
	}
	last_transnum = trans.isat_transnum;

	if (trans.isat_transid != KEY_IKE)
	{
	    loglog(RC_LOG_SERIOUS, "expected KEY_IKE but found %s in Oakley Transform"
		, enum_show(&isakmp_transformid_names, trans.isat_transid));
	    return INVALID_TRANSFORM_ID;
	}

	attr_start = trans_pbs.cur;
	attr_len = pbs_left(&trans_pbs);

	/* process all the attributes that make up the transform */

	while (pbs_left(&trans_pbs) != 0)
	{
	    struct isakmp_attribute a;
	    pb_stream attr_pbs;
	    u_int32_t val;	/* room for larger values */

	    if (!in_struct(&a, &isakmp_oakley_attribute_desc, &trans_pbs, &attr_pbs))
		return BAD_PROPOSAL_SYNTAX;

	    passert((a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK) < 32);

	    if (LHAS(seen_attrs, a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK))
	    {
		loglog(RC_LOG_SERIOUS, "repeated %s attribute in Oakley Transform %u"
		    , enum_show(&oakley_attr_names, a.isaat_af_type)
		    , trans.isat_transnum);
		return BAD_PROPOSAL_SYNTAX;
	    }

	    seen_attrs |= LELEM(a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);

	    val = a.isaat_lv;

	    DBG(DBG_PARSING,
	    {
		enum_names *vdesc = oakley_attr_val_descs
		    [a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK];

		if (vdesc != NULL)
		{
		    const char *nm = enum_name(vdesc, val);

		    if (nm != NULL)
			DBG_log("   [%u is %s]", (unsigned)val, nm);
		}
	    });

	    switch (a.isaat_af_type)
	    {
		case OAKLEY_ENCRYPTION_ALGORITHM | ISAKMP_ATTR_AF_TV:
		    switch (val)
		    {
		    case OAKLEY_3DES_CBC:
			ta.encrypt = val;
			ta.encrypter = &oakley_encrypter[val];
			break;

   		    /* we don't feel DES is safe */
		    case OAKLEY_DES_CBC:
		    default:
			ugh = builddiag("%s is not supported"
			    , enum_show(&oakley_enc_names, val));
		    }
		    break;

		case OAKLEY_HASH_ALGORITHM | ISAKMP_ATTR_AF_TV:
		    switch (val)
		    {
		    case OAKLEY_MD5:
		    case OAKLEY_SHA:
			ta.hash = val;
			ta.hasher = &oakley_hasher[val];
			break;
		    default:
			ugh = builddiag("%s is not supported"
			    , enum_show(&oakley_hash_names, val));
		    }
		    break;

		case OAKLEY_AUTHENTICATION_METHOD | ISAKMP_ATTR_AF_TV:
		    {
	            lset_t iap = st->st_policy & POLICY_ID_AUTH_MASK;

 		    /* check that authentication method is acceptable */
		    switch (val)
		    {
#ifdef XAUTH
		    case XAUTHInitPreShared:
			if(!xauth_init)
			{
			    ugh = builddiag("policy does not allow Extended Authentication (XAUTH) of initiator (we are %s)", role);
			    break;
			}
			ta.xauth = val;
			val = OAKLEY_PRESHARED_KEY;
			goto psk;

		    case XAUTHRespPreShared:
			if(!xauth_resp)
			{
			    ugh = builddiag("policy does not allow Extended Authentication (XAUTH) of responder (we are %s)", role);
			    break;
			}
			ta.xauth = val;
			val = OAKLEY_PRESHARED_KEY;
			/* No break; */
#endif


		    case OAKLEY_PRESHARED_KEY:
#ifdef XAUTH
		    psk:
			if(xauth_init && ta.xauth == 0)
			{
			    ugh = builddiag("policy mandates Extended Authentication (XAUTH) with PSK of initiator (we are %s)", role);
			    break;
			}
			if(xauth_resp && ta.xauth == 0)
			{
			    ugh = builddiag("policy mandates Extended Authentication (XAUTH) with PSK of responder (we are %s)", role);
			    break;
			}
#endif

			if ((iap & POLICY_PSK) == LEMPTY)
			{
			    ugh = "policy does not allow OAKLEY_PRESHARED_KEY authentication";
			}
			else
			{
			    /* check that we can find a preshared secret */
			    struct connection *c = st->st_connection;

			    if (get_preshared_secret(c) == NULL)
			    {
				char mid[IDTOA_BUF]
				    , hid[IDTOA_BUF];

				idtoa(&c->spd.this.id, mid, sizeof(mid));
				if (his_id_was_instantiated(c))
				    strcpy(hid, "%any");
				else
				    idtoa(&c->spd.that.id, hid, sizeof(hid));
				ugh = builddiag("Can't authenticate: no preshared key found for `%s' and `%s'"
				    , mid, hid);
			    }
			    ta.auth = val;
			}
			break;
#ifdef XAUTH
		    case XAUTHInitRSA:
			if(!xauth_init)
			{
			    ugh = builddiag("policy does not allow Extended Authentication (XAUTH) with RSA of initiator (we are %s)", role);
			    break;
			}
			ta.xauth = val;
			val = OAKLEY_RSA_SIG;
			goto rsasig;

		    case XAUTHRespRSA:
			if(!xauth_resp)
			{
			    ugh = builddiag("policy does not allow Extended Authentication (XAUTH) with RSA of responder (we are %s)", role);
			    break;
			}
			ta.xauth = val;
			val = OAKLEY_RSA_SIG;
			/* No break; */
#endif			

		    case OAKLEY_RSA_SIG:
#ifdef XAUTH
		    rsasig:
			if(xauth_init && ta.xauth == 0)
			{
			    ugh = builddiag("policy mandates Extended Authentication (XAUTH) with RSA of initiator (we are %s)", role);
			    break;
			}
			if(xauth_resp && ta.xauth == 0)
			{
			    ugh = builddiag("policy mandates Extended Authentication (XAUTH) with RSA of responder (we are %s)", role);
			    break;
			}
#endif
			/* Accept if policy specifies RSASIG or is default */
			if ((iap & POLICY_RSASIG) == LEMPTY)
			{
			    ugh = "policy does not allow OAKLEY_RSA_SIG authentication";
			}
			else
			{
			    /* We'd like to check that we can find a public
			     * key for him and a private key for us that is
			     * suitable, but we don't yet have his
			     * Id Payload, so it seems futile to try.
			     * We can assume that if he proposes it, he
			     * thinks we've got it.  If we proposed it,
			     * perhaps we know what we're doing.
			     */
			    ta.auth = val;
			}
			break;

		    default:
			ugh = builddiag("Pluto does not support %s authentication"
			    , enum_show(&oakley_auth_names, val));
			break;
		    }
		    }
		    break;

		case OAKLEY_GROUP_DESCRIPTION | ISAKMP_ATTR_AF_TV:
		    ta.group = lookup_group(val);
		    if (ta.group == NULL)
		    {
			ugh = "only OAKLEY_GROUP_MODP1024 and OAKLEY_GROUP_MODP1536 supported";
			break;
		    }
		    break;

		case OAKLEY_LIFE_TYPE | ISAKMP_ATTR_AF_TV:
		    switch (val)
		    {
		    case OAKLEY_LIFE_SECONDS:
		    case OAKLEY_LIFE_KILOBYTES:
			if (LHAS(seen_durations, val))
			{
			    loglog(RC_LOG_SERIOUS
				, "attribute OAKLEY_LIFE_TYPE value %s repeated"
				, enum_show(&oakley_lifetime_names, val));
			    return BAD_PROPOSAL_SYNTAX;
			}
			seen_durations |= LELEM(val);
			life_type = val;
			break;
		    default:
			ugh = builddiag("unknown value %s"
			    , enum_show(&oakley_lifetime_names, val));
			break;
		    }
		    break;

		case OAKLEY_LIFE_DURATION | ISAKMP_ATTR_AF_TLV:
		    val = decode_long_duration(&attr_pbs);
		    /* fall through */
		case OAKLEY_LIFE_DURATION | ISAKMP_ATTR_AF_TV:
		    if (!LHAS(seen_attrs, OAKLEY_LIFE_TYPE))
		    {
			ugh = "OAKLEY_LIFE_DURATION attribute not preceded by OAKLEY_LIFE_TYPE attribute";
			break;
		    }
		    seen_attrs &= ~(LELEM(OAKLEY_LIFE_DURATION) | LELEM(OAKLEY_LIFE_TYPE));

		    switch (life_type)
		    {
			case OAKLEY_LIFE_SECONDS:
			    if (val > OAKLEY_ISAKMP_SA_LIFETIME_MAXIMUM)
				ugh = builddiag("peer requested %lu seconds"
				    " which exceeds our limit %d seconds"
				    , (long) val
				    , OAKLEY_ISAKMP_SA_LIFETIME_MAXIMUM);
			    ta.life_seconds = val;
			    break;
			case OAKLEY_LIFE_KILOBYTES:
			    ta.life_kilobytes = val;
			    break;
			default:
			    bad_case(life_type);
		    }
		    break;

#if 0 /* not yet supported */
		case OAKLEY_GROUP_TYPE | ISAKMP_ATTR_AF_TV:
		case OAKLEY_PRF | ISAKMP_ATTR_AF_TV:
		case OAKLEY_KEY_LENGTH | ISAKMP_ATTR_AF_TV:
		case OAKLEY_FIELD_SIZE | ISAKMP_ATTR_AF_TV:

		case OAKLEY_GROUP_PRIME | ISAKMP_ATTR_AF_TV:
		case OAKLEY_GROUP_PRIME | ISAKMP_ATTR_AF_TLV:
		case OAKLEY_GROUP_GENERATOR_ONE | ISAKMP_ATTR_AF_TV:
		case OAKLEY_GROUP_GENERATOR_ONE | ISAKMP_ATTR_AF_TLV:
		case OAKLEY_GROUP_GENERATOR_TWO | ISAKMP_ATTR_AF_TV:
		case OAKLEY_GROUP_GENERATOR_TWO | ISAKMP_ATTR_AF_TLV:
		case OAKLEY_GROUP_CURVE_A | ISAKMP_ATTR_AF_TV:
		case OAKLEY_GROUP_CURVE_A | ISAKMP_ATTR_AF_TLV:
		case OAKLEY_GROUP_CURVE_B | ISAKMP_ATTR_AF_TV:
		case OAKLEY_GROUP_CURVE_B | ISAKMP_ATTR_AF_TLV:
		case OAKLEY_GROUP_ORDER | ISAKMP_ATTR_AF_TV:
		case OAKLEY_GROUP_ORDER | ISAKMP_ATTR_AF_TLV:
#endif
		default:
		    ugh = "unsupported OAKLEY attribute";
		    break;
	    }

	    if (ugh != NULL)
	    {
		loglog(RC_LOG_SERIOUS, "%s.  Attribute %s"
		    , ugh, enum_show(&oakley_attr_names, a.isaat_af_type));
		break;
	    }
	}

	if (ugh == NULL)
	{
	    /* a little more checking is in order */
	    {
		lset_t missing
		    = ~seen_attrs
		    & (LELEM(OAKLEY_ENCRYPTION_ALGORITHM)
		      | LELEM(OAKLEY_HASH_ALGORITHM)
		      | LELEM(OAKLEY_AUTHENTICATION_METHOD)
		      | LELEM(OAKLEY_GROUP_DESCRIPTION));

		if (missing)
		{
		    loglog(RC_LOG_SERIOUS, "missing mandatory attribute(s) %s in Oakley Transform %u"
			, bitnamesof(oakley_attr_bit_names, missing)
			, trans.isat_transnum);
		    return BAD_PROPOSAL_SYNTAX;
		}
	    }
	    /* We must have liked this transform.
	     * Lets finish early and leave.
	     */

	    DBG(DBG_PARSING | DBG_CRYPT
		, DBG_log("Oakley Transform %u accepted", trans.isat_transnum));

	    if (r_sa_pbs != NULL)
	    {
		struct isakmp_proposal r_proposal = proposal;
		pb_stream r_proposal_pbs;
		struct isakmp_transform r_trans = trans;
		pb_stream r_trans_pbs;

		/* Situation */
		if (!out_struct(&ipsecdoisit, &ipsec_sit_desc, r_sa_pbs, NULL))
		    impossible();

		/* Proposal */
#ifdef EMIT_ISAKMP_SPI
		r_proposal.isap_spisize = COOKIE_SIZE;
#else
		r_proposal.isap_spisize = 0;
#endif
		r_proposal.isap_notrans = 1;
		if (!out_struct(&r_proposal, &isakmp_proposal_desc, r_sa_pbs, &r_proposal_pbs))
		    impossible();

		/* SPI */
#ifdef EMIT_ISAKMP_SPI
		if (!out_raw(my_cookie, COOKIE_SIZE, &r_proposal_pbs, "SPI"))
		    impossible();
		r_proposal.isap_spisize = COOKIE_SIZE;
#else
		/* none (0) */
#endif

		/* Transform */
		r_trans.isat_np = ISAKMP_NEXT_NONE;
		if (!out_struct(&r_trans, &isakmp_isakmp_transform_desc, &r_proposal_pbs, &r_trans_pbs))
		    impossible();

		if (!out_raw(attr_start, attr_len, &r_trans_pbs, "attributes"))
		    impossible();
		close_output_pbs(&r_trans_pbs);
		close_output_pbs(&r_proposal_pbs);
		close_output_pbs(r_sa_pbs);
	    }

	    /* ??? If selection, we used to save the proposal in state.
	     * We never used it.  From proposal_pbs.start,
	     * length pbs_room(&proposal_pbs)
	     */

	    /* copy over the results */
	    st->st_oakley = ta;
	    return NOTHING_WRONG;
	}

	/* on to next transform */
	no_trans_left--;

	if (trans.isat_np == ISAKMP_NEXT_NONE)
	{
	    if (no_trans_left != 0)
	    {
		loglog(RC_LOG_SERIOUS, "number of Transform Payloads disagrees with Oakley Proposal Payload");
		return BAD_PROPOSAL_SYNTAX;
	    }
	    break;
	}
	if (trans.isat_np != ISAKMP_NEXT_T)
	{
	    loglog(RC_LOG_SERIOUS, "unexpected %s payload in Oakley Proposal"
		, enum_show(&payload_names, proposal.isap_np));
	    return BAD_PROPOSAL_SYNTAX;
	}
    }
    loglog(RC_LOG_SERIOUS, "no acceptable Oakley Transform");
    return NO_PROPOSAL_CHOSEN;
}

/* Parse the body of an IPsec SA Payload (i.e. Phase 2 / Quick Mode).
 *
 * The main routine is parse_ipsec_sa_body; other functions defined
 * between here and there are just helpers.
 *
 * Various shortcuts are taken.  In particular, the policy, such as
 * it is, is hardwired.
 *
 * If r_sa is non-NULL, the body of an SA representing the selected
 * proposal is emitted into it.
 *
 * If "selection" is true, the SA is supposed to represent the
 * single tranform that the peer has accepted.
 * ??? We only check that it is acceptable, not that it is one that we offered!
 *
 * Only IPsec DOI is accepted (what is the ISAKMP DOI?).
 * Error response is rudimentary.
 *
 * Since all ISAKMP groups in all SA Payloads must match, st->st_pfs_group
 * holds this across multiple payloads.
 * &unset_group signifies not yet "set"; NULL signifies NONE.
 *
 * This routine is used by quick_inI1_outR1() and quick_inR1_outI2().
 */

static const struct ipsec_trans_attrs null_ipsec_trans_attrs = {
    0,					/* transid (NULL, for now) */
    0,					/* spi */
    SA_LIFE_DURATION_DEFAULT,		/* life_seconds */
    SA_LIFE_DURATION_K_DEFAULT,		/* life_kilobytes */
    ENCAPSULATION_MODE_UNSPECIFIED,	/* encapsulation */
    AUTH_ALGORITHM_NONE,		/* auth */
    0,					/* key_len */
    0,					/* key_rounds */
};

static bool
parse_ipsec_transform(struct isakmp_transform *trans
, struct ipsec_trans_attrs *attrs
, pb_stream *prop_pbs
, pb_stream *trans_pbs
, struct_desc *trans_desc
, int previous_transnum	/* or -1 if none */
, bool selection
, bool is_last
, bool is_ipcomp
, struct state *st)	/* current state object */
{
    lset_t seen_attrs = 0
	, seen_durations = 0;
    u_int16_t life_type;
    const struct oakley_group_desc *pfs_group = NULL;

    if (!in_struct(trans, trans_desc, prop_pbs, trans_pbs))
	return FALSE;

    if (trans->isat_transnum <= previous_transnum)
    {
	loglog(RC_LOG_SERIOUS, "Transform Numbers in Proposal are not monotonically increasing");
	return FALSE;
    }

    switch (trans->isat_np)
    {
	case ISAKMP_NEXT_T:
	    if (is_last)
	    {
		loglog(RC_LOG_SERIOUS, "Proposal Payload has more Transforms than specified");
		return FALSE;
	    }
	    break;
	case ISAKMP_NEXT_NONE:
	    if (!is_last)
	    {
		loglog(RC_LOG_SERIOUS, "Proposal Payload has fewer Transforms than specified");
		return FALSE;
	    }
	    break;
	default:
	    loglog(RC_LOG_SERIOUS, "expecting Transform Payload, but found %s in Proposal"
		, enum_show(&payload_names, trans->isat_np));
	    return FALSE;
    }

    *attrs = null_ipsec_trans_attrs;
    attrs->transid = trans->isat_transid;

    while (pbs_left(trans_pbs) != 0)
    {
	struct isakmp_attribute a;
	pb_stream attr_pbs;
	enum_names *vdesc;
	u_int32_t val;	/* room for larger value */
	bool ipcomp_inappropriate = is_ipcomp;	/* will get reset if OK */

	if (!in_struct(&a, &isakmp_ipsec_attribute_desc, trans_pbs, &attr_pbs))
	    return FALSE;

	passert((a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK) < 32);

	if (LHAS(seen_attrs, a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK))
	{
	    loglog(RC_LOG_SERIOUS, "repeated %s attribute in IPsec Transform %u"
		, enum_show(&ipsec_attr_names, a.isaat_af_type)
		, trans->isat_transnum);
	    return FALSE;
	}

	seen_attrs |= LELEM(a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);

	val = a.isaat_lv;

	vdesc  = ipsec_attr_val_descs[a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK];
	if (vdesc != NULL)
	{
	    if (enum_name(vdesc, val) == NULL)
	    {
		loglog(RC_LOG_SERIOUS, "invalid value %u for attribute %s in IPsec Transform"
		    , (unsigned)val, enum_show(&ipsec_attr_names, a.isaat_af_type));
		return FALSE;
	    }
	    DBG(DBG_PARSING
		, if ((a.isaat_af_type & ISAKMP_ATTR_AF_MASK) == ISAKMP_ATTR_AF_TV)
		    DBG_log("   [%u is %s]"
			, (unsigned)val, enum_show(vdesc, val)));
	}

	switch (a.isaat_af_type)
	{
	    case SA_LIFE_TYPE | ISAKMP_ATTR_AF_TV:
		ipcomp_inappropriate = FALSE;
		if (LHAS(seen_durations, val))
		{
		    loglog(RC_LOG_SERIOUS, "attribute SA_LIFE_TYPE value %s repeated in message"
			, enum_show(&sa_lifetime_names, val));
		    return FALSE;
		}
		seen_durations |= LELEM(val);
		life_type = val;
		break;
	    case SA_LIFE_DURATION | ISAKMP_ATTR_AF_TLV:
		val = decode_long_duration(&attr_pbs);
		/* fall through */
	    case SA_LIFE_DURATION | ISAKMP_ATTR_AF_TV:
		ipcomp_inappropriate = FALSE;
		if (!LHAS(seen_attrs, SA_LIFE_DURATION))
		{
		    loglog(RC_LOG_SERIOUS, "SA_LIFE_DURATION IPsec attribute not preceded by SA_LIFE_TYPE attribute");
		    return FALSE;
		}
		seen_attrs &= ~(LELEM(SA_LIFE_DURATION) | LELEM(SA_LIFE_TYPE));

		switch (life_type)
		{
		    case SA_LIFE_TYPE_SECONDS:
			/* silently limit duration to our maximum */
			attrs->life_seconds = val <= SA_LIFE_DURATION_MAXIMUM
			    ? val : SA_LIFE_DURATION_MAXIMUM;
			break;
		    case SA_LIFE_TYPE_KBYTES:
			attrs->life_kilobytes = val;
			break;
		    default:
			bad_case(life_type);
		}
		break;
	    case GROUP_DESCRIPTION | ISAKMP_ATTR_AF_TV:
		if (is_ipcomp)
		{
		    /* Accept reluctantly.  Should not happen, according to
		     * draft-shacham-ippcp-rfc2393bis-05.txt 4.1.
		     */
		    ipcomp_inappropriate = FALSE;
		    loglog(RC_COMMENT
			, "IPCA (IPcomp SA) contains GROUP_DESCRIPTION."
			"  Ignoring inapproprate attribute.");
		}
		pfs_group = lookup_group(val);
		if (pfs_group == NULL)
		{
		    loglog(RC_LOG_SERIOUS, "only OAKLEY_GROUP_MODP1024 and OAKLEY_GROUP_MODP1536 supported for PFS");
		    return FALSE;
		}
		break;
	    case ENCAPSULATION_MODE | ISAKMP_ATTR_AF_TV:
		ipcomp_inappropriate = FALSE;
#ifdef NAT_TRAVERSAL
		switch (val) {
			case ENCAPSULATION_MODE_TUNNEL:
			case ENCAPSULATION_MODE_TRANSPORT:
				if (st->nat_traversal & NAT_T_DETECTED) {
					loglog(RC_LOG_SERIOUS,
						"%s must only be used if "
						"NAT-Traversal is not detected",
						enum_name(&enc_mode_names, val));
					/*
					 * Accept it anyway because SSH-Sentinel does not
					 * use UDP_TUNNEL or UDP_TRANSPORT for the diagnostic.
					 *
					 * remove when SSH-Sentinel is fixed
					 */
#ifdef I_DONT_CARE_OF_SSH_SENTINEL
					return FALSE;
#endif
				}
				attrs->encapsulation = val;
				break;
			case ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS:
#ifndef I_KNOW_TRANSPORT_MODE_HAS_SECURITY_CONCERN_BUT_I_WANT_IT
				loglog(RC_LOG_SERIOUS,
					"NAT-Traversal: Transport mode disabled due "
					"to security concerns");
				return FALSE;
				break;
#endif
			case ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS:
				if (st->nat_traversal & NAT_T_WITH_RFC_VALUES) {
					loglog(RC_LOG_SERIOUS,
						"%s must only be used with old IETF drafts",
						enum_name(&enc_mode_names, val));
					return FALSE;
				}
				else if (st->nat_traversal & NAT_T_DETECTED) {
					attrs->encapsulation = val - ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS + ENCAPSULATION_MODE_TUNNEL;
				}
				else {
					loglog(RC_LOG_SERIOUS,
						"%s must only be used if "
						"NAT-Traversal is detected",
						enum_name(&enc_mode_names, val));
					return FALSE;
				}
				break;
			case ENCAPSULATION_MODE_UDP_TRANSPORT_RFC:
#ifndef I_KNOW_TRANSPORT_MODE_HAS_SECURITY_CONCERN_BUT_I_WANT_IT
				loglog(RC_LOG_SERIOUS,
					"NAT-Traversal: Transport mode disabled due "
					"to security concerns");
				return FALSE;
				break;
#endif
			case ENCAPSULATION_MODE_UDP_TUNNEL_RFC:
				if ((st->nat_traversal & NAT_T_DETECTED) &&
					(st->nat_traversal & NAT_T_WITH_RFC_VALUES)) {
					attrs->encapsulation = val - ENCAPSULATION_MODE_UDP_TUNNEL_RFC + ENCAPSULATION_MODE_TUNNEL;
				}
				else if (st->nat_traversal & NAT_T_DETECTED) {
					loglog(RC_LOG_SERIOUS,
						"%s must only be used with NAT-T RFC",
						enum_name(&enc_mode_names, val));
					return FALSE;
				}
				else {
					loglog(RC_LOG_SERIOUS,
						"%s must only be used if "
						"NAT-Traversal is detected",
						enum_name(&enc_mode_names, val));
					return FALSE;
				}
				break;
			default:
				loglog(RC_LOG_SERIOUS,
					"unknown ENCAPSULATION_MODE %d in IPSec SA", val);
				return FALSE;
				break;
		}
#else
		attrs->encapsulation = val;
#endif
		break;
	    case AUTH_ALGORITHM | ISAKMP_ATTR_AF_TV:
		attrs->auth = val;
		break;
	    case KEY_LENGTH | ISAKMP_ATTR_AF_TV:
		attrs->key_len = val;
		break;
	    case KEY_ROUNDS | ISAKMP_ATTR_AF_TV:
		attrs->key_rounds = val;
		break;
#if 0 /* not yet implemented */
	    case COMPRESS_DICT_SIZE | ISAKMP_ATTR_AF_TV:
		break;
	    case COMPRESS_PRIVATE_ALG | ISAKMP_ATTR_AF_TV:
		break;

	    case SA_LIFE_DURATION | ISAKMP_ATTR_AF_TLV:
		break;
	    case COMPRESS_PRIVATE_ALG | ISAKMP_ATTR_AF_TLV:
		break;
#endif
	    default:
		loglog(RC_LOG_SERIOUS, "unsupported IPsec attribute %s"
		    , enum_show(&ipsec_attr_names, a.isaat_af_type));
		return FALSE;
	}
	if (ipcomp_inappropriate)
	{
	    loglog(RC_LOG_SERIOUS, "IPsec attribute %s inappropriate for IPCOMP"
		, enum_show(&ipsec_attr_names, a.isaat_af_type));
	    return FALSE;
	}
    }

    /* Although an IPCOMP SA (IPCA) ought not to have a pfs_group,
     * if it does, demand that it be consistent.
     * See draft-shacham-ippcp-rfc2393bis-05.txt 4.1.
     */
    if (!is_ipcomp || pfs_group != NULL)
    {
	if (st->st_pfs_group == &unset_group)
	    st->st_pfs_group = pfs_group;

	if (st->st_pfs_group != pfs_group)
	{
	    loglog(RC_LOG_SERIOUS, "GROUP_DESCRIPTION inconsistent with that of %s in IPsec SA"
		, selection? "the Proposal" : "a previous Transform");
	    return FALSE;
	}
    }

    if (LHAS(seen_attrs, SA_LIFE_DURATION))
    {
	loglog(RC_LOG_SERIOUS, "SA_LIFE_TYPE IPsec attribute not followed by SA_LIFE_DURATION attribute in message");
	return FALSE;
    }

    if (!LHAS(seen_attrs, ENCAPSULATION_MODE))
    {
	if (is_ipcomp)
	{
	    /* draft-shacham-ippcp-rfc2393bis-05.txt 4.1:
	     * "If the Encapsulation Mode is unspecified,
	     * the default value of Transport Mode is assumed."
	     * This contradicts/overrides the DOI (quuoted below).
	     */
	    attrs->encapsulation = ENCAPSULATION_MODE_TRANSPORT;
	}
	else
	{
	    /* ??? Technically, RFC 2407 (IPSEC DOI) 4.5 specifies that
	     * the default is "unspecified (host-dependent)".
	     * This makes little sense, so we demand that it be specified.
	     */
	    loglog(RC_LOG_SERIOUS, "IPsec Transform must specify ENCAPSULATION_MODE");
	    return FALSE;
	}
    }

    /* ??? should check for key_len and/or key_rounds if required */

    return TRUE;
}

static void
echo_proposal(
    struct isakmp_proposal r_proposal,	/* proposal to emit */
    struct isakmp_transform r_trans,	/* winning transformation within it */
    u_int8_t np,			/* Next Payload for proposal */
    pb_stream *r_sa_pbs,		/* SA PBS into which to emit */
    struct ipsec_proto_info *pi,	/* info about this protocol instance */
    struct_desc *trans_desc,		/* descriptor for this transformation */
    pb_stream *trans_pbs,		/* PBS for incoming transform */
    struct spd_route *sr,		/* host details for the association */
    bool tunnel_mode)			/* true for inner most tunnel SA */
{
    pb_stream r_proposal_pbs;
    pb_stream r_trans_pbs;

    /* Proposal */
    r_proposal.isap_np = np;
    r_proposal.isap_notrans = 1;
    if (!out_struct(&r_proposal, &isakmp_proposal_desc, r_sa_pbs, &r_proposal_pbs))
	impossible();

    /* allocate and emit our CPI/SPI */
    if (r_proposal.isap_protoid == PROTO_IPCOMP)
    {
	/* CPI is stored in network low order end of an
	 * ipsec_spi_t.  So we start a couple of bytes in.
	 * Note: we may fail to generate a satisfactory CPI,
	 * but we'll ignore that.
	 */
	pi->our_spi = get_my_cpi(sr, tunnel_mode);
	out_raw((u_char *) &pi->our_spi
	     + IPSEC_DOI_SPI_SIZE - IPCOMP_CPI_SIZE
	    , IPCOMP_CPI_SIZE
	    , &r_proposal_pbs, "CPI");
    }
    else
    {
	pi->our_spi = get_ipsec_spi(pi->attrs.spi
	    , r_proposal.isap_protoid == PROTO_IPSEC_AH ?
		IPPROTO_AH : IPPROTO_ESP
	    , sr
	    , tunnel_mode);
	/* XXX should check for errors */
	out_raw((u_char *) &pi->our_spi, IPSEC_DOI_SPI_SIZE
	    , &r_proposal_pbs, "SPI");
    }

    /* Transform */
    r_trans.isat_np = ISAKMP_NEXT_NONE;
    if (!out_struct(&r_trans, trans_desc, &r_proposal_pbs, &r_trans_pbs))
	impossible();

    /* Transform Attributes: pure echo */
    trans_pbs->cur = trans_pbs->start + sizeof(struct isakmp_transform);
    if (!out_raw(trans_pbs->cur, pbs_left(trans_pbs)
    , &r_trans_pbs, "attributes"))
	impossible();

    close_output_pbs(&r_trans_pbs);
    close_output_pbs(&r_proposal_pbs);
}

notification_t
parse_ipsec_sa_body(
    pb_stream *sa_pbs,		/* body of input SA Payload */
    const struct isakmp_sa *sa,	/* header of input SA Payload */
    pb_stream *r_sa_pbs,	/* if non-NULL, where to emit body of winning SA */
    bool selection,		/* if this SA is a selection, only one transform may appear */
    struct state *st)		/* current state object */
{
    const struct connection *c = st->st_connection;
    u_int32_t ipsecdoisit;
    pb_stream next_proposal_pbs;

    struct isakmp_proposal next_proposal;
    ipsec_spi_t next_spi;

    bool next_full = TRUE;

    /* DOI */
    if (sa->isasa_doi != ISAKMP_DOI_IPSEC)
    {
	loglog(RC_LOG_SERIOUS, "Unknown or unsupported DOI %s", enum_show(&doi_names, sa->isasa_doi));
	/* XXX Could send notification back */
	return DOI_NOT_SUPPORTED;
    }

    /* Situation */
    if (!in_struct(&ipsecdoisit, &ipsec_sit_desc, sa_pbs, NULL))
	return SITUATION_NOT_SUPPORTED;

    if (ipsecdoisit != SIT_IDENTITY_ONLY)
    {
	loglog(RC_LOG_SERIOUS, "unsupported IPsec DOI situation (%s)"
	    , bitnamesof(sit_bit_names, ipsecdoisit));
	/* XXX Could send notification back */
	return SITUATION_NOT_SUPPORTED;
    }

    /* The rules for IPsec SAs are scattered.
     * RFC 2408 "ISAKMP" section 4.2 gives some info.
     * There may be multiple proposals.  Those with identical proposal
     * numbers must be considered as conjuncts.  Those with different
     * numbers are disjuncts.
     * Each proposal may have several transforms, each considered
     * an alternative.
     * Each transform may have several attributes, all applying.
     *
     * To handle the way proposals are combined, we need to do a
     * look-ahead.
     */

    if (!in_struct(&next_proposal, &isakmp_proposal_desc, sa_pbs, &next_proposal_pbs))
	return BAD_PROPOSAL_SYNTAX;

    /* for each conjunction of proposals... */
    while (next_full)
    {
	int propno = next_proposal.isap_proposal;
	pb_stream ah_prop_pbs, esp_prop_pbs, ipcomp_prop_pbs;
	struct isakmp_proposal ah_proposal, esp_proposal, ipcomp_proposal;
	ipsec_spi_t ah_spi, esp_spi, ipcomp_cpi;
	bool ah_seen = FALSE, esp_seen = FALSE, ipcomp_seen = FALSE;
	int inner_proto = 0;
	bool tunnel_mode = FALSE;
	u_int16_t well_known_cpi = 0;

	pb_stream ah_trans_pbs, esp_trans_pbs, ipcomp_trans_pbs;
	struct isakmp_transform ah_trans, esp_trans, ipcomp_trans;
	struct ipsec_trans_attrs ah_attrs, esp_attrs, ipcomp_attrs;

	/* for each proposal in the conjunction */
	do {

	    if (next_proposal.isap_protoid == PROTO_IPCOMP)
	    {
		/* IPCOMP CPI */
		if (next_proposal.isap_spisize == IPSEC_DOI_SPI_SIZE)
		{
		    /* This code is to accommodate those peculiar
		     * implementations that send a CPI in the bottom of an
		     * SPI-sized field.
		     * See draft-shacham-ippcp-rfc2393bis-05.txt 4.1
		     */
		    u_int8_t filler[IPSEC_DOI_SPI_SIZE - IPCOMP_CPI_SIZE];

		    if (!in_raw(filler, sizeof(filler)
		     , &next_proposal_pbs, "CPI filler")
		    || !all_zero(filler, sizeof(filler)))
			return INVALID_SPI;
		}
		else if (next_proposal.isap_spisize != IPCOMP_CPI_SIZE)
		{
		    loglog(RC_LOG_SERIOUS, "IPsec Proposal with improper CPI size (%u)"
			, next_proposal.isap_spisize);
		    return INVALID_SPI;
		}

		/* We store CPI in the low order of a network order
		 * ipsec_spi_t.  So we start a couple of bytes in.
		 */
		zero(&next_spi);
		if (!in_raw((u_char *)&next_spi
		  + IPSEC_DOI_SPI_SIZE - IPCOMP_CPI_SIZE
		, IPCOMP_CPI_SIZE, &next_proposal_pbs, "CPI"))
		    return INVALID_SPI;

		/* If sanity ruled, CPIs would have to be such that
		 * the SAID (the triple (CPI, IPCOM, destination IP))
		 * would be unique, just like for SPIs.  But there is a
		 * perversion where CPIs can be well-known and consequently
		 * the triple is not unique.  We hide this fact from
		 * ourselves by fudging the top 16 bits to make
		 * the property true internally!
		 */
		switch (ntohl(next_spi))
		{
		case IPCOMP_DEFLATE:
		    well_known_cpi = ntohl(next_spi);
		    next_spi = uniquify_his_cpi(next_spi, st);
		    if (next_spi == 0)
		    {
			loglog(RC_LOG_SERIOUS
			    , "IPsec Proposal contains well-known CPI that I cannot uniquify");
			return INVALID_SPI;
		    }
		    break;
		default:
		    if (ntohl(next_spi) < IPCOMP_FIRST_NEGOTIATED
		    || ntohl(next_spi) > IPCOMP_LAST_NEGOTIATED)
		    {
			loglog(RC_LOG_SERIOUS, "IPsec Proposal contains CPI from non-negotiated range (0x%lx)"
			    , (unsigned long) ntohl(next_spi));
			return INVALID_SPI;
		    }
		    break;
		}
	    }
	    else
	    {
		/* AH or ESP SPI */
		if (next_proposal.isap_spisize != IPSEC_DOI_SPI_SIZE)
		{
		    loglog(RC_LOG_SERIOUS, "IPsec Proposal with improper SPI size (%u)"
			, next_proposal.isap_spisize);
		    return INVALID_SPI;
		}

		if (!in_raw((u_char *)&next_spi, sizeof(next_spi), &next_proposal_pbs, "SPI"))
		    return INVALID_SPI;

		/* SPI value 0 is invalid and values 1-255 are reserved to IANA.
		 * RFC 2402 (ESP) 2.4, RFC 2406 (AH) 2.1
		 * IPCOMP???
		 */
		if (ntohl(next_spi) < IPSEC_DOI_SPI_MIN)
		{
		    loglog(RC_LOG_SERIOUS, "IPsec Proposal contains invalid SPI (0x%lx)"
			, (unsigned long) ntohl(next_spi));
		    return INVALID_SPI;
		}
	    }

	    if (next_proposal.isap_notrans == 0)
	    {
		loglog(RC_LOG_SERIOUS, "IPsec Proposal contains no Transforms");
		return BAD_PROPOSAL_SYNTAX;
	    }

	    switch (next_proposal.isap_protoid)
	    {
	    case PROTO_IPSEC_AH:
		if (ah_seen)
		{
		    loglog(RC_LOG_SERIOUS, "IPsec SA contains two simultaneous AH Proposals");
		    return BAD_PROPOSAL_SYNTAX;
		}
		ah_seen = TRUE;
		ah_prop_pbs = next_proposal_pbs;
		ah_proposal = next_proposal;
		ah_spi = next_spi;
		break;

	    case PROTO_IPSEC_ESP:
		if (esp_seen)
		{
		    loglog(RC_LOG_SERIOUS, "IPsec SA contains two simultaneous ESP Proposals");
		    return BAD_PROPOSAL_SYNTAX;
		}
		esp_seen = TRUE;
		esp_prop_pbs = next_proposal_pbs;
		esp_proposal = next_proposal;
		esp_spi = next_spi;
		break;

	    case PROTO_IPCOMP:
		if (ipcomp_seen)
		{
		    loglog(RC_LOG_SERIOUS, "IPsec SA contains two simultaneous IPCOMP Proposals");
		    return BAD_PROPOSAL_SYNTAX;
		}
		ipcomp_seen = TRUE;
		ipcomp_prop_pbs = next_proposal_pbs;
		ipcomp_proposal = next_proposal;
		ipcomp_cpi = next_spi;
		break;

	    default:
		loglog(RC_LOG_SERIOUS, "unexpected Protocol ID (%s) in IPsec Proposal"
		    , enum_show(&protocol_names, next_proposal.isap_protoid));
		return INVALID_PROTOCOL_ID;
	    }

	    /* refill next_proposal */
	    if (next_proposal.isap_np == ISAKMP_NEXT_NONE)
	    {
		next_full = FALSE;
		break;
	    }
	    else if (next_proposal.isap_np != ISAKMP_NEXT_P)
	    {
		loglog(RC_LOG_SERIOUS, "unexpected in Proposal: %s"
		    , enum_show(&payload_names, next_proposal.isap_np));
		return BAD_PROPOSAL_SYNTAX;
	    }

	    if (!in_struct(&next_proposal, &isakmp_proposal_desc, sa_pbs, &next_proposal_pbs))
		return BAD_PROPOSAL_SYNTAX;
	} while (next_proposal.isap_proposal == propno);

	/* Now that we have all conjuncts, we should try
	 * the Cartesian product of eachs tranforms!
	 * At the moment, we take short-cuts on account of
	 * our rudimentary hard-wired policy.
	 * For now, we find an acceptable AH (if any)
	 * and then an acceptable ESP.  The only interaction
	 * is that the ESP acceptance can know whether there
	 * was an acceptable AH and hence not require an AUTH.
	 */

	if (ah_seen)
	{
	    int previous_transnum = -1;
	    int tn;

	    for (tn = 0; tn != ah_proposal.isap_notrans; tn++)
	    {
		int ok_transid = 0;
		bool ok_auth = FALSE;

		if (!parse_ipsec_transform(&ah_trans
		, &ah_attrs
		, &ah_prop_pbs
		, &ah_trans_pbs
		, &isakmp_ah_transform_desc
		, previous_transnum
		, selection
		, tn == ah_proposal.isap_notrans - 1
		, FALSE
		, st))
		    return BAD_PROPOSAL_SYNTAX;

		previous_transnum = ah_trans.isat_transnum;

		/* we must understand ah_attrs.transid
		 * COMBINED with ah_attrs.auth.
		 * See RFC 2407 "IPsec DOI" section 4.4.3
		 * The following combinations are legal,
		 * but we don't implement all of them:
		 * It seems as if each auth algorithm
		 * only applies to one ah transid.
		 * AH_MD5, AUTH_ALGORITHM_HMAC_MD5
		 * AH_MD5, AUTH_ALGORITHM_KPDK (unimplemented)
		 * AH_SHA, AUTH_ALGORITHM_HMAC_SHA1
		 * AH_DES, AUTH_ALGORITHM_DES_MAC (unimplemented)
		 */
		switch (ah_attrs.auth)
		{
		    case AUTH_ALGORITHM_NONE:
			loglog(RC_LOG_SERIOUS, "AUTH_ALGORITHM attribute missing in AH Transform");
			return BAD_PROPOSAL_SYNTAX;

		    case AUTH_ALGORITHM_HMAC_MD5:
			ok_auth = TRUE;
			/* fall through */
		    case AUTH_ALGORITHM_KPDK:
			ok_transid = AH_MD5;
			break;

		    case AUTH_ALGORITHM_HMAC_SHA1:
			ok_auth = TRUE;
			ok_transid = AH_SHA;
			break;

		    case AUTH_ALGORITHM_DES_MAC:
			ok_transid = AH_DES;
			break;
		}
		if (ah_attrs.transid != ok_transid)
		{
		    loglog(RC_LOG_SERIOUS, "%s attribute inappropriate in %s Transform"
			, enum_name(&auth_alg_names, ah_attrs.auth)
			, enum_show(&ah_transformid_names, ah_attrs.transid));
		    return BAD_PROPOSAL_SYNTAX;
		}
		if (!ok_auth)
		{
		    DBG(DBG_CONTROL | DBG_CRYPT
			, DBG_log("%s attribute unsupported"
			    " in %s Transform from %s"
			    , enum_name(&auth_alg_names, ah_attrs.auth)
			    , enum_show(&ah_transformid_names, ah_attrs.transid)
			    , ip_str(&c->spd.that.host_addr)));
		    continue;   /* try another */
		}
		break;	/* we seem to be happy */
	    }
	    if (tn == ah_proposal.isap_notrans)
		continue;	/* we didn't find a nice one */
	    ah_attrs.spi = ah_spi;
	    inner_proto = IPPROTO_AH;
	    if (ah_attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
		tunnel_mode = TRUE;
	}

	if (esp_seen)
	{
	    int previous_transnum = -1;
	    int tn;

	    for (tn = 0; tn != esp_proposal.isap_notrans; tn++)
	    {
		if (!parse_ipsec_transform(&esp_trans
		, &esp_attrs
		, &esp_prop_pbs
		, &esp_trans_pbs
		, &isakmp_esp_transform_desc
		, previous_transnum
		, selection
		, tn == esp_proposal.isap_notrans - 1
		, FALSE
		, st))
		    return BAD_PROPOSAL_SYNTAX;

		previous_transnum = esp_trans.isat_transnum;

		switch (esp_attrs.transid)
		{
#if 0	/* we don't feel single DES is safe */
		    case ESP_DES:
#endif
		    case ESP_3DES:
			break;

#ifdef SUPPORT_ESP_NULL	/* should be about as secure as AH-only */
		    case ESP_NULL:
			if (esp_attrs.auth == AUTH_ALGORITHM_NONE)
			{
			    loglog(RC_LOG_SERIOUS, "ESP_NULL requires auth algorithm");
			    return BAD_PROPOSAL_SYNTAX;
			}
			if (st->st_policy & POLICY_ENCRYPT)
			{
			    DBG(DBG_CONTROL | DBG_CRYPT
				    , DBG_log("ESP_NULL Transform Proposal from %s"
					" does not satisfy POLICY_ENCRYPT"
					, ip_str(&c->spd.that.host_addr)));
			    continue;   /* try another */
			}
			break;
#endif

		    default:
			DBG(DBG_CONTROL | DBG_CRYPT
			    , DBG_log("unsupported ESP Transform %s from %s"
				, enum_show(&esp_transformid_names, esp_attrs.transid)
				, ip_str(&c->spd.that.host_addr)));
			continue;   /* try another */
		}

		switch (esp_attrs.auth)
		{
		    case AUTH_ALGORITHM_NONE:
			if (!ah_seen)
			{
			    DBG(DBG_CONTROL | DBG_CRYPT
				, DBG_log("ESP from %s must either have AUTH or be combined with AH"
				    , ip_str(&c->spd.that.host_addr)));
			    continue;   /* try another */
			}
			break;
		    case AUTH_ALGORITHM_HMAC_MD5:
		    case AUTH_ALGORITHM_HMAC_SHA1:
			break;
		    default:
			DBG(DBG_CONTROL | DBG_CRYPT
			    , DBG_log("unsupported ESP auth alg %s from %s"
				, enum_show(&auth_alg_names, esp_attrs.auth)
				, ip_str(&c->spd.that.host_addr)));
			continue;   /* try another */
		}

		if (ah_seen && ah_attrs.encapsulation != esp_attrs.encapsulation)
		{
		    /* ??? This should be an error, but is it? */
		    DBG(DBG_CONTROL | DBG_CRYPT
			, DBG_log("AH and ESP transforms disagree about encapsulation; TUNNEL presumed"));
		}

		break;	/* we seem to be happy */
	    }
	    if (tn == esp_proposal.isap_notrans)
		continue;	/* we didn't find a nice one */
	    esp_attrs.spi = esp_spi;
	    inner_proto = IPPROTO_ESP;
	    if (esp_attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
		tunnel_mode = TRUE;
	}
	else if (st->st_policy & POLICY_ENCRYPT)
	{
	    DBG(DBG_CONTROL | DBG_CRYPT
		, DBG_log("policy for \"%s\" requires encryption but ESP not in Proposal from %s"
		    , c->name, ip_str(&c->spd.that.host_addr)));
	    continue;	/* we needed encryption, but didn't find ESP */
	}
	else if ((st->st_policy & POLICY_AUTHENTICATE) && !ah_seen)
	{
	    DBG(DBG_CONTROL | DBG_CRYPT
		, DBG_log("policy for \"%s\" requires authentication"
		    " but none in Proposal from %s"
		    , c->name, ip_str(&c->spd.that.host_addr)));
	    continue;	/* we need authentication, but we found neither ESP nor AH */
	}

	if (ipcomp_seen)
	{
	    int previous_transnum = -1;
	    int tn;

#ifdef NEVER	/* we think IPcomp is working now */
	    /**** FUDGE TO PREVENT UNREQUESTED IPCOMP:
	     **** NEEDED BECAUSE OUR IPCOMP IS EXPERIMENTAL (UNSTABLE).
	     ****/
	    if (!(st->st_policy & POLICY_COMPRESS))
	    {
		plog("compression proposed by %s, but policy for \"%s\" forbids it"
		    , ip_str(&c->spd.that.host_addr), c->name);
		continue;	/* unwanted compression proposal */
	    }
#endif
	    if (!can_do_IPcomp)
	    {
		plog("compression proposed by %s, but KLIPS is not configured with IPCOMP"
		    , ip_str(&c->spd.that.host_addr));
		continue;
	    }

	    if (well_known_cpi != 0 && !ah_seen && !esp_seen)
	    {
		plog("illegal proposal: bare IPCOMP used with well-known CPI");
		return BAD_PROPOSAL_SYNTAX;
	    }

	    for (tn = 0; tn != ipcomp_proposal.isap_notrans; tn++)
	    {
		if (!parse_ipsec_transform(&ipcomp_trans
		, &ipcomp_attrs
		, &ipcomp_prop_pbs
		, &ipcomp_trans_pbs
		, &isakmp_ipcomp_transform_desc
		, previous_transnum
		, selection
		, tn == ipcomp_proposal.isap_notrans - 1
		, TRUE
		, st))
		    return BAD_PROPOSAL_SYNTAX;

		previous_transnum = ipcomp_trans.isat_transnum;

		if (well_known_cpi != 0 && ipcomp_attrs.transid != well_known_cpi)
		{
		    plog("illegal proposal: IPCOMP well-known CPI disagrees with transform");
		    return BAD_PROPOSAL_SYNTAX;
		}

		switch (ipcomp_attrs.transid)
		{
		    case IPCOMP_DEFLATE:    /* all we can handle! */
			break;

		    default:
			DBG(DBG_CONTROL | DBG_CRYPT
			    , DBG_log("unsupported IPCOMP Transform %s from %s"
				, enum_show(&ipcomp_transformid_names, ipcomp_attrs.transid)
				, ip_str(&c->spd.that.host_addr)));
			continue;   /* try another */
		}

		if (ah_seen && ah_attrs.encapsulation != ipcomp_attrs.encapsulation)
		{
		    /* ??? This should be an error, but is it? */
		    DBG(DBG_CONTROL | DBG_CRYPT
			, DBG_log("AH and IPCOMP transforms disagree about encapsulation; TUNNEL presumed"));
		} else if (esp_seen && esp_attrs.encapsulation != ipcomp_attrs.encapsulation)
		{
		    /* ??? This should be an error, but is it? */
		    DBG(DBG_CONTROL | DBG_CRYPT
			, DBG_log("ESP and IPCOMP transforms disagree about encapsulation; TUNNEL presumed"));
		}

		break;	/* we seem to be happy */
	    }
	    if (tn == ipcomp_proposal.isap_notrans)
		continue;	/* we didn't find a nice one */
	    ipcomp_attrs.spi = ipcomp_cpi;
	    inner_proto = IPPROTO_COMP;
	    if (ipcomp_attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
		tunnel_mode = TRUE;
	}

	/* Eureka: we liked what we saw -- accept it. */

	if (r_sa_pbs != NULL)
	{
	    /* emit what we've accepted */

	    /* Situation */
	    if (!out_struct(&ipsecdoisit, &ipsec_sit_desc, r_sa_pbs, NULL))
		impossible();

	    /* AH proposal */
	    if (ah_seen)
		echo_proposal(ah_proposal
		    , ah_trans
		    , esp_seen || ipcomp_seen? ISAKMP_NEXT_P : ISAKMP_NEXT_NONE
		    , r_sa_pbs
		    , &st->st_ah
		    , &isakmp_ah_transform_desc
		    , &ah_trans_pbs
		    , &st->st_connection->spd
		    , tunnel_mode && inner_proto == IPPROTO_AH);

	    /* ESP proposal */
	    if (esp_seen)
		echo_proposal(esp_proposal
		    , esp_trans
		    , ipcomp_seen? ISAKMP_NEXT_P : ISAKMP_NEXT_NONE
		    , r_sa_pbs
		    , &st->st_esp
		    , &isakmp_esp_transform_desc
		    , &esp_trans_pbs
		    , &st->st_connection->spd
		    , tunnel_mode && inner_proto == IPPROTO_ESP);

	    /* IPCOMP proposal */
	    if (ipcomp_seen)
		echo_proposal(ipcomp_proposal
		    , ipcomp_trans
		    , ISAKMP_NEXT_NONE
		    , r_sa_pbs
		    , &st->st_ipcomp
		    , &isakmp_ipcomp_transform_desc
		    , &ipcomp_trans_pbs
		    , &st->st_connection->spd
		    , tunnel_mode && inner_proto == IPPROTO_COMP);

	    close_output_pbs(r_sa_pbs);
	}

	/* save decoded version of winning SA in state */

	st->st_ah.present = ah_seen;
	if (ah_seen)
	    st->st_ah.attrs = ah_attrs;

	st->st_esp.present = esp_seen;
	if (esp_seen)
	    st->st_esp.attrs = esp_attrs;

	st->st_ipcomp.present = ipcomp_seen;
	if (ipcomp_seen)
	    st->st_ipcomp.attrs = ipcomp_attrs;

	return NOTHING_WRONG;
    }

    loglog(RC_LOG_SERIOUS, "no acceptable Proposal in IPsec SA");
    return NO_PROPOSAL_CHOSEN;
}
