/* Support of X.509 certificates and CRLs
 * Copyright (C) 2000 Andreas Hess, Patric Lichtsteiner, Roger Wegmann
 * Copyright (C) 2001 Marco Bertossa, Andreas Schleiss
 * Copyright (C) 2002 Mario Strasser
 * Copyright (C) 2000-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <limits.h>
#include <sys/types.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "sysdep.h"
#include "constants.h"
#include "oswlog.h"
#include "oswalloc.h"
#include "oswlog.h"
#include "oswtime.h"
#include "mpzfuncs.h"
#include "id.h"
#include "asn1.h"
#include "oid.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "secrets.h"
#include "md2.h"
#include "md5.h"
#include "sha1.h"
#ifdef USE_SHA2
# include "sha2.h"
#endif

#ifdef HAVE_LIBNSS
# include <nss.h>
# include <pk11pub.h>
# include <keyhi.h>
# include <secerr.h>
# include "oswconf.h"
#endif



/* ASN.1 definition of a basicConstraints extension */

static const asn1Object_t basicConstraintsObjects[] = {
  { 0, "basicConstraints",		ASN1_SEQUENCE,     ASN1_NONE }, /*  0 */
  { 1,   "CA",				ASN1_BOOLEAN,      ASN1_DEF |
							   ASN1_BODY }, /*  1 */
  { 1,   "pathLenConstraint",		ASN1_INTEGER,      ASN1_OPT |
							   ASN1_BODY }, /*  2 */
  { 1,   "end opt",			ASN1_EOC,          ASN1_END  }  /*  3 */
};

#define BASIC_CONSTRAINTS_CA	1
#define BASIC_CONSTRAINTS_ROOF	4

/* ASN.1 definition of time */

static const asn1Object_t timeObjects[] = {
  { 0,   "utcTime",			ASN1_UTCTIME,         ASN1_OPT |
							      ASN1_BODY }, /*  0 */
  { 0,   "end opt",			ASN1_EOC,             ASN1_END  }, /*  1 */
  { 0,   "generalizeTime",		ASN1_GENERALIZEDTIME, ASN1_OPT |
							      ASN1_BODY }, /*  2 */
  { 0,   "end opt",			ASN1_EOC,             ASN1_END  }  /*  3 */
};

#define TIME_UTC		0
#define TIME_GENERALIZED	2
#define TIME_ROOF		4

/* ASN.1 definiton of an algorithmIdentifier */

static const asn1Object_t algorithmIdentifierObjects[] = {
  { 0, "algorithmIdentifier",		ASN1_SEQUENCE,	   ASN1_NONE }, /*  0 */
  { 1,   "algorithm",			ASN1_OID,	   ASN1_BODY }  /*  1 */
};

#define ALGORITHM_IDENTIFIER_ALG	1
#define ALGORITHM_IDENTIFIER_ROOF	2

/* ASN.1 definition of a keyIdentifier */

static const asn1Object_t keyIdentifierObjects[] = {
  { 0,   "keyIdentifier",		ASN1_OCTET_STRING, ASN1_BODY }  /*  0 */
};

/* ASN.1 definition of a authorityKeyIdentifier extension */

static const asn1Object_t authorityKeyIdentifierObjects[] = {
  { 0,   "authorityKeyIdentifier",	ASN1_SEQUENCE,     ASN1_NONE }, /*  0 */
  { 1,     "keyIdentifier",		ASN1_CONTEXT_S_0,  ASN1_OPT |
							   ASN1_OBJ  }, /*  1 */
  { 1,     "end opt",			ASN1_EOC,          ASN1_END  }, /*  2 */
  { 1,     "authorityCertIssuer",	ASN1_CONTEXT_C_1,  ASN1_OPT |
							   ASN1_OBJ  }, /*  3 */
  { 1,     "end opt",			ASN1_EOC,          ASN1_END  }, /*  4 */
  { 1,     "authorityCertSerialNumber",	ASN1_CONTEXT_S_2,  ASN1_OPT |
							   ASN1_BODY }, /*  5 */
  { 1,     "end opt",			ASN1_EOC,          ASN1_END  }  /*  6 */
};

#define AUTH_KEY_ID_KEY_ID		1
#define AUTH_KEY_ID_CERT_ISSUER		3
#define AUTH_KEY_ID_CERT_SERIAL		5
#define AUTH_KEY_ID_ROOF		7

/* ASN.1 definition of a authorityInfoAccess extension */

static const asn1Object_t authorityInfoAccessObjects[] = {
  { 0,   "authorityInfoAccess",         ASN1_SEQUENCE,     ASN1_LOOP }, /*  0 */
  { 1,     "accessDescription",         ASN1_SEQUENCE,     ASN1_NONE }, /*  1 */
  { 2,       "accessMethod",            ASN1_OID,          ASN1_BODY }, /*  2 */
  { 2,       "accessLocation",          ASN1_EOC,          ASN1_RAW  }, /*  3 */
  { 0,   "end loop",                    ASN1_EOC,          ASN1_END  }  /*  4 */
};

#define AUTH_INFO_ACCESS_METHOD		2
#define AUTH_INFO_ACCESS_LOCATION	3
#define AUTH_INFO_ACCESS_ROOF		5

/* ASN.1 definition of a extendedKeyUsage extension */

static const asn1Object_t extendedKeyUsageObjects[] = {
  { 0, "extendedKeyUsage",		ASN1_SEQUENCE,     ASN1_LOOP }, /*  0 */
  { 1,   "keyPurposeID",		ASN1_OID,     	   ASN1_BODY }, /*  1 */
  { 0, "end loop",			ASN1_EOC,	   ASN1_END  }, /*  2 */
};

#define EXT_KEY_USAGE_PURPOSE_ID	1
#define EXT_KEY_USAGE_ROOF		3

/* ASN.1 definition of generalNames */

static const asn1Object_t generalNamesObjects[] = {
  { 0, "generalNames",			ASN1_SEQUENCE,     ASN1_LOOP }, /*  0 */
  { 1,   "generalName",			ASN1_EOC,          ASN1_RAW  }, /*  1 */
  { 0, "end loop",			ASN1_EOC,          ASN1_END  }  /*  2 */
};

#define GENERAL_NAMES_GN	1
#define GENERAL_NAMES_ROOF	3

/* ASN.1 definition of generalName */

static const asn1Object_t generalNameObjects[] = {
  { 0,   "otherName",			ASN1_CONTEXT_C_0,  ASN1_OPT |
							   ASN1_BODY }, /*  0 */
  { 0,   "end choice",			ASN1_EOC,          ASN1_END  }, /*  1 */
  { 0,   "rfc822Name",			ASN1_CONTEXT_S_1,  ASN1_OPT |
							   ASN1_BODY }, /*  2 */
  { 0,   "end choice",			ASN1_EOC,          ASN1_END  }, /*  3 */
  { 0,   "dnsName",			ASN1_CONTEXT_S_2,  ASN1_OPT |
							   ASN1_BODY }, /*  4 */
  { 0,   "end choice",			ASN1_EOC,          ASN1_END  }, /*  5 */
  { 0,   "x400Address",			ASN1_CONTEXT_S_3,  ASN1_OPT |
							   ASN1_BODY }, /*  6 */
  { 0,   "end choice",			ASN1_EOC,          ASN1_END  }, /*  7 */
  { 0,   "directoryName",		ASN1_CONTEXT_C_4,  ASN1_OPT |
							   ASN1_BODY }, /*  8 */
  { 0,   "end choice",			ASN1_EOC,          ASN1_END  }, /*  9 */
  { 0,   "ediPartyName",		ASN1_CONTEXT_C_5,  ASN1_OPT |
							   ASN1_BODY }, /* 10 */
  { 0,   "end choice",			ASN1_EOC,          ASN1_END  }, /* 11 */
  { 0,   "uniformResourceIdentifier",	ASN1_CONTEXT_S_6,  ASN1_OPT |
							   ASN1_BODY }, /* 12 */
  { 0,   "end choice",			ASN1_EOC,          ASN1_END  }, /* 13 */
  { 0,   "ipAddress",			ASN1_CONTEXT_S_7,  ASN1_OPT |
							   ASN1_BODY }, /* 14 */
  { 0,   "end choice",			ASN1_EOC,          ASN1_END  }, /* 15 */
  { 0,   "registeredID",		ASN1_CONTEXT_S_8,  ASN1_OPT |
							   ASN1_BODY }, /* 16 */
  { 0,   "end choice",			ASN1_EOC,          ASN1_END  }  /* 17 */
};

#define GN_OBJ_OTHER_NAME	 0
#define GN_OBJ_RFC822_NAME	 2
#define GN_OBJ_DNS_NAME		 4
#define GN_OBJ_X400_ADDRESS	 6
#define GN_OBJ_DIRECTORY_NAME	 8
#define GN_OBJ_EDI_PARTY_NAME	10
#define GN_OBJ_URI		12
#define GN_OBJ_IP_ADDRESS	14
#define GN_OBJ_REGISTERED_ID	16
#define GN_OBJ_ROOF		18

/* ASN.1 definition of crlDistributionPoints */

static const asn1Object_t crlDistributionPointsObjects[] = {
  { 0, "crlDistributionPoints",		ASN1_SEQUENCE,     ASN1_LOOP }, /*  0 */
  { 1,   "DistributionPoint",		ASN1_SEQUENCE,     ASN1_NONE }, /*  1 */
  { 2,     "distributionPoint",		ASN1_CONTEXT_C_0,  ASN1_OPT |
							   ASN1_LOOP }, /*  2 */
  { 3,       "fullName",		ASN1_CONTEXT_C_0,  ASN1_OPT |
							   ASN1_OBJ  }, /*  3 */
  { 3,       "end choice",		ASN1_EOC,          ASN1_END  }, /*  4 */
  { 3,       "nameRelativeToCRLIssuer",	ASN1_CONTEXT_C_1,  ASN1_OPT |
							   ASN1_BODY }, /*  5 */
  { 3,       "end choice",		ASN1_EOC,          ASN1_END  }, /*  6 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /*  7 */
  { 2,     "reasons",			ASN1_CONTEXT_C_1,  ASN1_OPT |
							   ASN1_BODY }, /*  8 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /*  9 */
  { 2,     "crlIssuer",			ASN1_CONTEXT_C_2,  ASN1_OPT |
							   ASN1_BODY }, /* 10 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /* 11 */
  { 0, "end loop",			ASN1_EOC,          ASN1_END  }, /* 12 */
};

#define CRL_DIST_POINTS_FULLNAME	 3
#define CRL_DIST_POINTS_ROOF		13

/* ASN.1 definition of an X.509v3 certificate */

static const asn1Object_t certObjects[] = {
  { 0, "certificate",			ASN1_SEQUENCE,     ASN1_OBJ  }, /*  0 */
  { 1,   "tbsCertificate",		ASN1_SEQUENCE,     ASN1_OBJ  }, /*  1 */
  { 2,     "DEFAULT v1",		ASN1_CONTEXT_C_0,  ASN1_DEF  }, /*  2 */
  { 3,       "version",			ASN1_INTEGER,      ASN1_BODY }, /*  3 */
  { 2,     "serialNumber",		ASN1_INTEGER,      ASN1_BODY }, /*  4 */
  { 2,     "signature",			ASN1_EOC,          ASN1_RAW  }, /*  5 */
  { 2,     "issuer",			ASN1_SEQUENCE,     ASN1_OBJ  }, /*  6 */
  { 2,     "validity",			ASN1_SEQUENCE,     ASN1_NONE }, /*  7 */
  { 3,       "notBefore",		ASN1_EOC,          ASN1_RAW  }, /*  8 */
  { 3,       "notAfter",		ASN1_EOC,          ASN1_RAW  }, /*  9 */
  { 2,     "subject",			ASN1_SEQUENCE,     ASN1_OBJ  }, /* 10 */
  { 2,     "subjectPublicKeyInfo",	ASN1_SEQUENCE,     ASN1_NONE }, /* 11 */
  { 3,       "algorithm",		ASN1_EOC,          ASN1_RAW  }, /* 12 */
  { 3,       "subjectPublicKey",	ASN1_BIT_STRING,   ASN1_NONE }, /* 13 */
  { 4,         "RSAPublicKey",		ASN1_SEQUENCE,     ASN1_NONE }, /* 14 */
  { 5,           "modulus",		ASN1_INTEGER,      ASN1_BODY }, /* 15 */
  { 5,           "publicExponent",	ASN1_INTEGER,      ASN1_BODY }, /* 16 */
  { 2,     "issuerUniqueID",		ASN1_CONTEXT_C_1,  ASN1_OPT  }, /* 17 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /* 18 */
  { 2,     "subjectUniqueID",		ASN1_CONTEXT_C_2,  ASN1_OPT  }, /* 19 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /* 20 */
  { 2,     "optional extensions",	ASN1_CONTEXT_C_3,  ASN1_OPT  }, /* 21 */
  { 3,       "extensions",		ASN1_SEQUENCE,     ASN1_LOOP }, /* 22 */
  { 4,         "extension",		ASN1_SEQUENCE,     ASN1_NONE }, /* 23 */
  { 5,           "extnID",		ASN1_OID,          ASN1_BODY }, /* 24 */
  { 5,           "critical",		ASN1_BOOLEAN,      ASN1_DEF |
							   ASN1_BODY }, /* 25 */
  { 5,           "extnValue",		ASN1_OCTET_STRING, ASN1_BODY }, /* 26 */
  { 3,       "end loop",		ASN1_EOC,          ASN1_END  }, /* 27 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /* 28 */
  { 1,   "signatureAlgorithm",		ASN1_EOC,          ASN1_RAW  }, /* 29 */
  { 1,   "signatureValue",		ASN1_BIT_STRING,   ASN1_BODY }  /* 30 */
};

#define X509_OBJ_CERTIFICATE			 0
#define X509_OBJ_TBS_CERTIFICATE		 1
#define X509_OBJ_VERSION			 3
#define X509_OBJ_SERIAL_NUMBER			 4
#define X509_OBJ_SIG_ALG			 5
#define X509_OBJ_ISSUER 			 6
#define X509_OBJ_NOT_BEFORE			 8
#define X509_OBJ_NOT_AFTER			 9
#define X509_OBJ_SUBJECT			10
#define X509_OBJ_SUBJECT_PUBLIC_KEY_ALGORITHM	12
#define X509_OBJ_SUBJECT_PUBLIC_KEY		13
#define X509_OBJ_MODULUS			15
#define X509_OBJ_PUBLIC_EXPONENT		16
#define X509_OBJ_EXTN_ID			24
#define X509_OBJ_CRITICAL			25
#define X509_OBJ_EXTN_VALUE			26
#define X509_OBJ_ALGORITHM			29
#define X509_OBJ_SIGNATURE			30
#define X509_OBJ_ROOF				31


/* ASN.1 definition of an X.509 certificate list */

static const asn1Object_t crlObjects[] = {
  { 0, "certificateList",		ASN1_SEQUENCE,     ASN1_OBJ  }, /*  0 */
  { 1,   "tbsCertList",			ASN1_SEQUENCE,     ASN1_OBJ  }, /*  1 */
  { 2,     "version",			ASN1_INTEGER,      ASN1_OPT |
							   ASN1_BODY }, /*  2 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /*  3 */
  { 2,     "signature",			ASN1_EOC,          ASN1_RAW  }, /*  4 */
  { 2,     "issuer",			ASN1_SEQUENCE,     ASN1_OBJ  }, /*  5 */
  { 2,     "thisUpdate",		ASN1_EOC,          ASN1_RAW  }, /*  6 */
  { 2,     "nextUpdate",		ASN1_EOC,          ASN1_RAW  }, /*  7 */
  { 2,     "revokedCertificates",	ASN1_SEQUENCE,     ASN1_OPT |
							   ASN1_LOOP }, /*  8 */
  { 3,       "certList",		ASN1_SEQUENCE,     ASN1_NONE }, /*  9 */
  { 4,         "userCertificate",	ASN1_INTEGER,      ASN1_BODY }, /* 10 */
  { 4,         "revocationDate",	ASN1_EOC,          ASN1_RAW  }, /* 11 */
  { 4,         "crlEntryExtensions",	ASN1_SEQUENCE,     ASN1_OPT |
							   ASN1_LOOP }, /* 12 */
  { 5,           "extension",		ASN1_SEQUENCE,     ASN1_NONE }, /* 13 */
  { 6,             "extnID",		ASN1_OID,          ASN1_BODY }, /* 14 */
  { 6,             "critical",		ASN1_BOOLEAN,      ASN1_DEF |
							   ASN1_BODY }, /* 15 */
  { 6,             "extnValue",		ASN1_OCTET_STRING, ASN1_BODY }, /* 16 */
  { 4,         "end opt or loop",	ASN1_EOC,          ASN1_END  }, /* 17 */
  { 2,     "end opt or loop",		ASN1_EOC,          ASN1_END  }, /* 18 */
  { 2,     "optional extensions",	ASN1_CONTEXT_C_0,  ASN1_OPT  }, /* 19 */
  { 3,       "crlExtensions",		ASN1_SEQUENCE,     ASN1_LOOP }, /* 20 */
  { 4,         "extension",		ASN1_SEQUENCE,     ASN1_NONE }, /* 21 */
  { 5,           "extnID",		ASN1_OID,          ASN1_BODY }, /* 22 */
  { 5,           "critical",		ASN1_BOOLEAN,      ASN1_DEF |
							   ASN1_BODY }, /* 23 */
  { 5,           "extnValue",		ASN1_OCTET_STRING, ASN1_BODY }, /* 24 */
  { 3,       "end loop",		ASN1_EOC,          ASN1_END  }, /* 25 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /* 26 */
  { 1,   "signatureAlgorithm",		ASN1_EOC,          ASN1_RAW  }, /* 27 */
  { 1,   "signatureValue",		ASN1_BIT_STRING,   ASN1_BODY }  /* 28 */
 };

#define CRL_OBJ_CERTIFICATE_LIST		 0
#define CRL_OBJ_TBS_CERT_LIST			 1
#define CRL_OBJ_VERSION				 2
#define CRL_OBJ_SIG_ALG				 4
#define CRL_OBJ_ISSUER				 5
#define CRL_OBJ_THIS_UPDATE			 6
#define CRL_OBJ_NEXT_UPDATE			 7
#define CRL_OBJ_USER_CERTIFICATE		10
#define CRL_OBJ_REVOCATION_DATE			11
#define CRL_OBJ_CRL_ENTRY_CRITICAL		15
#define CRL_OBJ_EXTN_ID				22
#define CRL_OBJ_CRITICAL			23
#define CRL_OBJ_EXTN_VALUE			24
#define CRL_OBJ_ALGORITHM			27
#define CRL_OBJ_SIGNATURE			28
#define CRL_OBJ_ROOF				29


const x509cert_t empty_x509cert = {
      NULL        , /* *next */
    UNDEFINED_TIME, /* installed */
            0     , /* count */
     AUTH_NONE    , /* authority_flags */
    { NULL, 0 }   , /* certificate */
    { NULL, 0 }   , /*   tbsCertificate */
            1	  , /*     version */
    { NULL, 0 }   , /*     serialNumber */
    OID_UNKNOWN   , /*     sigAlg */
    { NULL, 0 }   , /*     issuer */
                    /*     validity */
            0     , /*       notBefore */
            0     , /*       notAfter */
    { NULL, 0 }   , /*     subject */
                    /*     subjectPublicKeyInfo */
    OID_UNKNOWN   , /*       subjectPublicKeyAlgorithm */
                    /*       subjectPublicKey */
    { NULL, 0 }   , /*         modulus */
    { NULL, 0 }   , /*         publicExponent */
                    /*     issuerUniqueID */
                    /*     subjectUniqueID */
                    /*     extensions */
                    /*       extension */
                    /*         extnID */
                    /*         critical */
                    /*         extnValue */
      FALSE       , /*           isCA */
      FALSE       , /*           isOcspSigner */
    { NULL, 0 }   , /*           subjectKeyID */
    { NULL, 0 }   , /*           authKeyID */
    { NULL, 0 }   , /*           authKeySerialNumber */
    { NULL, 0 }   , /*           accessLocation */
      NULL        , /*           subjectAltName */
      NULL        , /*           crlDistributionPoints */
    OID_UNKNOWN   , /*   algorithm */
    { NULL, 0 }     /*   signature */
};

const x509crl_t empty_x509crl = {
      NULL        , /* *next */
    UNDEFINED_TIME, /* installed */
      NULL        , /* distributionPoints */
    { NULL, 0 }   , /* certificateList */
    { NULL, 0 }   , /*   tbsCertList */
            1     , /*     version */
    OID_UNKNOWN   , /*     sigAlg */
    { NULL, 0 }   , /*     issuer */
    UNDEFINED_TIME, /*     thisUpdate */
    UNDEFINED_TIME, /*     nextUpdate */
      NULL        , /*     revokedCertificates */
                    /*     crlExtensions */
                    /*       extension */
                    /*         extnID */
                    /*         critical */
                    /*         extnValue */
    { NULL, 0 }   , /*           authKeyID */
    { NULL, 0 }   , /*           authKeySerialNumber */
    OID_UNKNOWN   , /*   algorithm */
    { NULL, 0 }     /*   signature */
};


/* coding of X.501 distinguished name */

typedef struct {
    const char *name;
    chunk_t oid;
    u_char type;
} x501rdn_t;


/* X.501 acronyms for well known object identifiers (OIDs) */

static u_char oid_ND[]  = {0x02, 0x82, 0x06, 0x01,
			   0x0A, 0x07, 0x14};
static u_char oid_UID[] = {0x09, 0x92, 0x26, 0x89, 0x93,
			   0xF2, 0x2C, 0x64, 0x01, 0x01};
static u_char oid_DC[]  = {0x09, 0x92, 0x26, 0x89, 0x93,
			   0xF2, 0x2C, 0x64, 0x01, 0x19};
static u_char oid_CN[]  = {0x55, 0x04, 0x03};
static u_char oid_S[]   = {0x55, 0x04, 0x04};
static u_char oid_SN[]  = {0x55, 0x04, 0x05};
static u_char oid_C[]   = {0x55, 0x04, 0x06};
static u_char oid_L[]   = {0x55, 0x04, 0x07};
static u_char oid_ST[]  = {0x55, 0x04, 0x08};
static u_char oid_O[]   = {0x55, 0x04, 0x0A};
static u_char oid_OU[]  = {0x55, 0x04, 0x0B};
static u_char oid_T[]   = {0x55, 0x04, 0x0C};
static u_char oid_D[]   = {0x55, 0x04, 0x0D};
static u_char oid_N[]   = {0x55, 0x04, 0x29};
static u_char oid_G[]   = {0x55, 0x04, 0x2A};
static u_char oid_I[]   = {0x55, 0x04, 0x2B};
static u_char oid_ID[]  = {0x55, 0x04, 0x2D};
static u_char oid_E[]   = {0x2A, 0x86, 0x48, 0x86, 0xF7,
			   0x0D, 0x01, 0x09, 0x01};
static u_char oid_UN[]  = {0x2A, 0x86, 0x48, 0x86, 0xF7,
			   0x0D, 0x01, 0x09, 0x02};
static u_char oid_TCGID[] = {0x2B, 0x06, 0x01, 0x04, 0x01, 0x89,
			     0x31, 0x01, 0x01, 0x02, 0x02, 0x4B};

static const x501rdn_t x501rdns[] = {
  {"ND"           , {oid_ND,     7}, ASN1_PRINTABLESTRING},
  {"UID"          , {oid_UID,   10}, ASN1_PRINTABLESTRING},
  {"DC"           , {oid_DC,    10}, ASN1_PRINTABLESTRING},
  {"CN"           , {oid_CN,     3}, ASN1_PRINTABLESTRING},
  {"S"            , {oid_S,      3}, ASN1_PRINTABLESTRING},
  {"SN"           , {oid_SN,     3}, ASN1_PRINTABLESTRING},
  {"serialNumber" , {oid_SN,     3}, ASN1_PRINTABLESTRING},
  {"C"            , {oid_C,      3}, ASN1_PRINTABLESTRING},
  {"L"            , {oid_L,      3}, ASN1_PRINTABLESTRING},
  {"ST"           , {oid_ST,     3}, ASN1_PRINTABLESTRING},
  {"O"            , {oid_O,      3}, ASN1_PRINTABLESTRING},
  {"OU"           , {oid_OU,     3}, ASN1_PRINTABLESTRING},
  {"T"            , {oid_T,      3}, ASN1_PRINTABLESTRING},
  {"D"            , {oid_D,      3}, ASN1_PRINTABLESTRING},
  {"N"            , {oid_N,      3}, ASN1_PRINTABLESTRING},
  {"G"            , {oid_G,      3}, ASN1_PRINTABLESTRING},
  {"I"            , {oid_I,      3}, ASN1_PRINTABLESTRING},
  {"ID"           , {oid_ID,     3}, ASN1_PRINTABLESTRING},
  {"E"            , {oid_E,      9}, ASN1_IA5STRING},
  {"Email"        , {oid_E,      9}, ASN1_IA5STRING},
  {"emailAddress" , {oid_E,      9}, ASN1_IA5STRING},
  {"UN"              , {oid_UN,     9}, ASN1_IA5STRING},
  {"unstructuredName", {oid_UN,     9}, ASN1_IA5STRING},
  {"TCGID"        , {oid_TCGID, 12}, ASN1_PRINTABLESTRING}
};

#define X501_RDN_ROOF   24

/* Maximum length of ASN.1 distinquished name */
#define ASN1_BUF_LEN	      512

static void
update_chunk(chunk_t *ch, int n)
{
    n = (n > -1 && n < (int)ch->len)? n : (int)ch->len-1;
    ch->ptr += n; ch->len -= n;
}


/*
 *  Pointer is set to the first RDN in a DN
 */
static err_t
init_rdn(chunk_t dn, chunk_t *rdn, chunk_t *attribute, bool *next)
{
    *rdn = empty_chunk;
    *attribute = empty_chunk;

    /* a DN is a SEQUENCE OF RDNs */

    if (*dn.ptr != ASN1_SEQUENCE)
    {
	return "DN is not a SEQUENCE";
    }

    rdn->len = asn1_length(&dn);

    if (rdn->len == ASN1_INVALID_LENGTH)
       return "Invalid RDN length";

    rdn->ptr = dn.ptr;

    /* are there any RDNs ? */
    *next = rdn->len > 0;

    return NULL;
}

/*
 *  Fetches the next RDN in a DN
 */
static err_t
get_next_rdn(chunk_t *rdn, chunk_t * attribute, chunk_t *oid, chunk_t *value
, asn1_t *type, bool *next)
{
    chunk_t body;

    /* initialize return values */
    *oid   = empty_chunk;
    *value = empty_chunk;

    /* if all attributes have been parsed, get next rdn */
    if (attribute->len <= 0)
    {
	/* an RDN is a SET OF attributeTypeAndValue */
	if (*rdn->ptr != ASN1_SET)
	    return "RDN is not a SET";

	attribute->len = asn1_length(rdn);

        if (attribute->len == ASN1_INVALID_LENGTH)
            return "Invalid attribute length";

	attribute->ptr = rdn->ptr;

	/* advance to start of next RDN */
	rdn->ptr += attribute->len;
	rdn->len -= attribute->len;
    }

    /* an attributeTypeAndValue is a SEQUENCE */
    if (*attribute->ptr != ASN1_SEQUENCE)
 	return "attributeTypeAndValue is not a SEQUENCE";

    /* extract the attribute body */
    body.len = asn1_length(attribute);


    if (body.len == ASN1_INVALID_LENGTH)
        return "Invalid attribute body length";


    body.ptr = attribute->ptr;

    /* advance to start of next attribute */
    attribute->ptr += body.len;
    attribute->len -= body.len;

    /* attribute type is an OID */
    if (*body.ptr != ASN1_OID)
	return "attributeType is not an OID";

    /* extract OID */
    oid->len = asn1_length(&body);

    if (oid->len == ASN1_INVALID_LENGTH)
        return "Invalid attribute OID length";


   oid->ptr = body.ptr;

    /* advance to the attribute value */
    body.ptr += oid->len;
    body.len -= oid->len;

    /* extract string type */
    *type = *body.ptr;

    /* extract string value */
    value->len = asn1_length(&body);

    if (value->len == ASN1_INVALID_LENGTH)
        return "Invalid attribute string length";

    value->ptr = body.ptr;

    /* are there any RDNs left? */
    *next = rdn->len > 0 || attribute->len > 0;

    return NULL;
}

/*
 *  Parses an ASN.1 distinguished name int its OID/value pairs
 */
static err_t
dn_parse(chunk_t dn, chunk_t *str)
{
    chunk_t rdn, oid, attribute, value;
    asn1_t type;
    int oid_code;
    bool next;
    bool first = TRUE;
    err_t ugh;

    if(dn.ptr == NULL) {
	const char *e = "(empty)";
	strncpy((char *)str->ptr, e, str->len);
	update_chunk(str, strlen(e));
	return NULL;
    }
    ugh = init_rdn(dn, &rdn, &attribute, &next);

    if (ugh != NULL) /* a parsing error has occured */
        return ugh;

    while (next)
    {
	ugh = get_next_rdn(&rdn, &attribute, &oid, &value, &type, &next);

	if (ugh != NULL) /* a parsing error has occured */
	    return ugh;

	if (first)		/* first OID/value pair */
	    first = FALSE;
	else			/* separate OID/value pair by a comma */
	    update_chunk(str, snprintf((char *)str->ptr,str->len,", "));

	/* print OID */
	oid_code = known_oid(oid);
	if (oid_code == OID_UNKNOWN)	/* OID not found in list */
	    hex_str(oid, str);
	else
	    update_chunk(str, snprintf((char *)str->ptr,str->len,"%s",
			      oid_names[oid_code].name));

	/* print value */
	update_chunk(str, snprintf((char *)str->ptr,str->len,"=%.*s",
			      (int)value.len,value.ptr));
    }
    return NULL;
}

/*
 *  Count the number of wildcard RDNs in a distinguished name
 */
int
dn_count_wildcards(chunk_t dn)
{
    chunk_t rdn, attribute, oid, value;
    asn1_t type;
    bool next;
    int wildcards = 0;

    err_t ugh = init_rdn(dn, &rdn, &attribute, &next);

    if (ugh != NULL) /* a parsing error has occured */
        return -1;

    while (next)
    {
	ugh = get_next_rdn(&rdn, &attribute, &oid, &value, &type, &next);

	if (ugh != NULL) /* a parsing error has occured */
	    return -1;
	if (value.len == 1 && *value.ptr == '*')
	    wildcards++; /* we have found a wildcard RDN */
    }
    return wildcards;
}

/*
 * Prints a binary string in hexadecimal form
 */
void
hex_str(chunk_t bin, chunk_t *str)
{
    u_int i;
    update_chunk(str, snprintf((char *)str->ptr,str->len,"0x"));
    for (i=0; i < bin.len; i++)
	update_chunk(str, snprintf((char *)str->ptr,str->len,"%02X",*bin.ptr++));
}


/*  Converts a binary DER-encoded ASN.1 distinguished name
 *  into LDAP-style human-readable ASCII format
 */
int
dntoa(char *dst, size_t dstlen, chunk_t dn)
{
    err_t ugh = NULL;
    chunk_t str;

    str.ptr = (unsigned char*)dst;
    str.len = dstlen;
    ugh = dn_parse(dn, &str);

    if (ugh != NULL) /* error, print DN as hex string */
    {
	DBG(DBG_PARSING,
	    DBG_log("error in DN parsing: %s", ugh));
	str.ptr = (unsigned char *)dst;
	str.len = dstlen;
	hex_str(dn, &str);
    }
    return (int)(dstlen - str.len);
}

/*
 * Same as dntoa but prints a special string for a null dn
 */
int
dntoa_or_null(char *dst, size_t dstlen, chunk_t dn, const char* null_dn)
{
    if (dn.ptr == NULL)
	return snprintf(dst, dstlen, "%s", null_dn);
    else
	return dntoa(dst, dstlen, dn);
}

/*  Converts an LDAP-style human-readable ASCII-encoded
 *  ASN.1 distinguished name into binary DER-encoded format
 */
err_t
atodn(char *src, chunk_t *dn)
{
  /* finite state machine for atodn */

    typedef enum {
	SEARCH_OID =	0,
	READ_OID =	1,
	SEARCH_NAME =	2,
	READ_NAME =	3,
        UNKNOWN_OID =	4
    } state_t;

    u_char oid_len_buf[3];
    u_char name_len_buf[3];
    u_char rdn_seq_len_buf[3];
    u_char rdn_set_len_buf[3];
    u_char dn_seq_len_buf[3];

    chunk_t asn1_oid_len     = { oid_len_buf,     0 };
    chunk_t asn1_name_len    = { name_len_buf,    0 };
    chunk_t asn1_rdn_seq_len = { rdn_seq_len_buf, 0 };
    chunk_t asn1_rdn_set_len = { rdn_set_len_buf, 0 };
    chunk_t asn1_dn_seq_len  = { dn_seq_len_buf,  0 };
    chunk_t oid  = empty_chunk;
    chunk_t name = empty_chunk;

    int whitespace  = 0;
    int rdn_seq_len = 0;
    int rdn_set_len = 0;
    int dn_seq_len  = 0;
    int pos         = 0;

    err_t ugh = NULL;

    u_char *dn_ptr = dn->ptr + 4;

    state_t state = SEARCH_OID;

    do
    {
        switch (state)
	{
	case SEARCH_OID:
	    if (*src != ' ' && *src != '/' && *src !=  ',')
	    {
		oid.ptr = (unsigned char *)src;
		oid.len = 1;
		state = READ_OID;
	    }
	    break;
	case READ_OID:
	    if (*src != ' ' && *src != '=')
		oid.len++;
	    else
	    {
		for (pos = 0; pos < X501_RDN_ROOF; pos++)
		{
		    if (strlen(x501rdns[pos].name) == oid.len &&
			strncasecmp(x501rdns[pos].name, (char *)oid.ptr, oid.len) == 0)
			break; /* found a valid OID */
		}
		if (pos == X501_RDN_ROOF)
		{
		    ugh = "unknown OID in ID_DER_ASN1_DN";
		    state = UNKNOWN_OID;
		    break;
		}
		code_asn1_length(x501rdns[pos].oid.len, &asn1_oid_len);

		/* reset oid and change state */
		oid = empty_chunk;
		state = SEARCH_NAME;
	    }
	    break;
	case SEARCH_NAME:
	    if (*src != ' ' && *src != '=')
	    {
		name.ptr = (unsigned char *)src;
		name.len = 1;
		whitespace = 0;
		state = READ_NAME;
	    }
	    break;
	case READ_NAME:
	    if (*src != ',' && *src != '/' && *src != '\0')
	    {
		name.len++;
		if (*src == ' ')
		    whitespace++;
		else
		    whitespace = 0;
	    }
	    else
	    {
		name.len -= whitespace;
		code_asn1_length(name.len, &asn1_name_len);

		/* compute the length of the relative distinguished name sequence */
		rdn_seq_len = 1 + asn1_oid_len.len + x501rdns[pos].oid.len +
			      1 + asn1_name_len.len + name.len;
		code_asn1_length(rdn_seq_len, &asn1_rdn_seq_len);

		/* compute the length of the relative distinguished name set */
		rdn_set_len = 1 + asn1_rdn_seq_len.len + rdn_seq_len;
		code_asn1_length(rdn_set_len, &asn1_rdn_set_len);

		/* encode the relative distinguished name */
		*dn_ptr++ = ASN1_SET;
		chunkcpy(dn_ptr, asn1_rdn_set_len);
		*dn_ptr++ = ASN1_SEQUENCE;
		chunkcpy(dn_ptr, asn1_rdn_seq_len);
		*dn_ptr++ = ASN1_OID;
		chunkcpy(dn_ptr, asn1_oid_len);
		chunkcpy(dn_ptr, x501rdns[pos].oid);
		/* encode the ASN.1 character string type of the name */
		*dn_ptr++ = (x501rdns[pos].type == ASN1_PRINTABLESTRING
		    && !is_printablestring(name))? ASN1_T61STRING : x501rdns[pos].type;
		chunkcpy(dn_ptr, asn1_name_len);
		chunkcpy(dn_ptr, name);

		/* accumulate the length of the distinguished name sequence */
		dn_seq_len += 1 + asn1_rdn_set_len.len + rdn_set_len;

		/* reset name and change state */
		name = empty_chunk;
		state = SEARCH_OID;
	    }
	    break;
	case UNKNOWN_OID:
	    break;
	}
    } while (*src++ != '\0');

    /* complete the distinguished name sequence*/
    code_asn1_length(dn_seq_len, &asn1_dn_seq_len);
    dn->ptr += 3 - asn1_dn_seq_len.len;
    dn->len =  1 + asn1_dn_seq_len.len + dn_seq_len;
    dn_ptr = dn->ptr;
    *dn_ptr++ = ASN1_SEQUENCE;
    chunkcpy(dn_ptr, asn1_dn_seq_len);
    return ugh;
}


#ifdef X509DN_MAIN

#include <stdio.h>

#if 0
#define	MAX_BUF		6
extern unsigned char *cyclic_buffers[MAX_BUF][IDTOA_BUF](void);
extern unsigned char *cyclic_canary(void);
#endif
extern bool verify_cyclic_buffer(void);
extern void reset_cyclic_buffer(void);

void regress(void);
char *progname = "x509dn_regress";
void exit_tool(int num) { exit(num);}


int
main(int argc, char *argv[])
{
	ip_said sa;
	char buf[100];
	char buf2[100];
	const char *oops;
	size_t n;

        chunk_t name;

	name.ptr = temporary_cyclic_buffer(); /* assign temporary buffer */
	name.len = IDTOA_BUF;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s {ahnnn@aaa|-r}\n", argv[0]);
		exit(2);
	}

	if (strcmp(argv[1], "-r") == 0) {
		regress();
		fprintf(stderr, "regress() returned?!?\n");
		exit(1);
	}

	oops = atodn(argv[1], &name);

	if (oops != NULL) {
		fprintf(stderr, "%s: conversion failed: %s\n", argv[0], oops);
		exit(1);
	}
	n = dntoa(buf, sizeof(buf), name);
	if (n > sizeof(buf)) {
            fprintf(stderr, "%s: reverse conv ", argv[0]);
		fprintf(stderr, " failed: need %ld bytes, have only %ld\n",
						(long)n, (long)sizeof(buf));
		exit(1);
	}
	printf("%s\n", buf);

	exit(0);
}

struct rtab {
	int format;
	char *input;
	char *output;			/* NULL means error expected */
} rtab[] = {
	{0, "esp257@1.2.3.0",		"esp.101@1.2.3.0"},
	{0, "ah0x20@1.2.3.4",		"ah.20@1.2.3.4"},
	{0, "tun20@1.2.3.4",		"tun.14@1.2.3.4"},
	{0, "comp20@1.2.3.4",		"comp.14@1.2.3.4"},
	{0, "esp257@::1",		"esp:101@::1"},
	{0, "esp257@0bc:12de::1",	"esp:101@bc:12de::1"},
	{0, "esp78@1049:1::8007:2040",	"esp:4e@1049:1::8007:2040"},
	{0, "esp0x78@1049:1::8007:2040",	"esp:78@1049:1::8007:2040"},
	{0, "ah78@1049:1::8007:2040",	"ah:4e@1049:1::8007:2040"},
	{0, "ah0x78@1049:1::8007:2040",	"ah:78@1049:1::8007:2040"},
	{0, "tun78@1049:1::8007:2040",	"tun:4e@1049:1::8007:2040"},
	{0, "tun0x78@1049:1::8007:2040",	"tun:78@1049:1::8007:2040"},
	{0, "duk99@3ffe:370:400:ff::9001:3001",	NULL},
	{0, "esp78x@1049:1::8007:2040",	NULL},
	{0, "esp0x78@1049:1:0xfff::8007:2040",	NULL},
	{0, "es78@1049:1::8007:2040",	NULL},
	{0, "",				NULL},
	{0, "_",				NULL},
	{0, "ah2.2",			NULL},
	{0, "goo2@1.2.3.4",		NULL},
	{0, "esp9@1.2.3.4",		"esp.9@1.2.3.4"},
	{0, "esp0xa9@1.2.3.4",		"esp.000000a9@1.2.3.4"},
	{0, "espp9@1.2.3.4",		NULL},
	{0, "es9@1.2.3.4",		NULL},
	{0, "ah@1.2.3.4",		NULL},
	{0, "esp7x7@1.2.3.4",		NULL},
	{0, "esp77@1.0x2.3.4",		NULL},
	{0, PASSTHROUGHNAME,		PASSTHROUGH4NAME},
	{0, PASSTHROUGH6NAME,		PASSTHROUGH6NAME},
	{0, "%pass",			"%pass"},
	{0, "int256@0.0.0.0",		"%pass"},
	{0, "%drop",			"%drop"},
	{0, "int257@0.0.0.0",		"%drop"},
	{0, "%reject",			"%reject"},
	{0, "int258@0.0.0.0",		"%reject"},
	{0, "%hold",			"%hold"},
	{0, "int259@0.0.0.0",		"%hold"},
	{0, "%trap",			"%trap"},
	{0, "int260@0.0.0.0",		"%trap"},
	{0, "%trapsubnet",		"%trapsubnet"},
	{0, "int261@0.0.0.0",		"%trapsubnet"},
	{0, "int262@0.0.0.0",		"int.106@0.0.0.0"},
	{0, "esp9@1.2.3.4",		"unk77.9@1.2.3.4"},
	{0, NULL,			NULL}
};

void
regress(void)
{
	struct rtab *r;
	int status = 0;
	ip_said sa;
	char in[100];
	char buf[100];
	const char *oops;
	size_t n;
        chunk_t name;

	for (r = rtab; r->input != NULL; r++) {
		strcpy(in, r->input);

                reset_cyclic_buffer();

                name.ptr = temporary_cyclic_buffer(); /* assign temporary buffer */
                name.len = IDTOA_BUF;

                oops = atodn(in, &name);

		if (oops != NULL && r->output == NULL)
			{}		/* okay, error expected */
		else if (oops != NULL) {
			printf("`%s' ttosa failed: %s\n", r->input, oops);
			status = 1;
		} else if (r->output == NULL) {
			printf("`%s' atodn succeeded unexpectedly\n",
                               r->input);
			status = 1;
		} else {
                    n = dntoa(buf, sizeof(buf), name);
                    if (n > sizeof(buf)) {
                        printf("`%s' dntoa failed:  need %ld\n",
                               r->input, (long)n);
                        status = 1;
                    } else if (strcmp(r->output, buf) != 0) {
                        printf("`%s' gave `%s', expected `%s'\n",
                               r->input, buf, r->output);
                        status = 1;
                    }
		}
                if(!verify_cyclic_buffer()) {
                    printf("overran buffer\n");
                    status = 1;
                }
	}
	exit(status);
}

#endif /* ATODN_MAIN */

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */

