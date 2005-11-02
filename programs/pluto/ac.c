/* Support of X.509 attribute certificates
 * Copyright (C) 2002 Ueli Gallizzi, Ariane Seiler
 * Copyright (C) 2003 Martin Berner, Lukas Suter
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
 * RCSID $Id: ac.c,v 1.3 2003/11/04 07:58:58 dhr Exp $
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <sys/types.h>

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "asn1.h"
#include "oid.h"
#include "ac.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "log.h"

/* ASN.1 definition of ietfAttrSyntax */

static const asn1Object_t ietfAttrSyntaxObjects[] =
{
  { 0, "ietfAttrSyntax",		ASN1_SEQUENCE,        ASN1_NONE }, /*  0 */
  { 1,   "policyAuthority",		ASN1_CONTEXT_C_0,     ASN1_OPT |
							      ASN1_BODY }, /*  1 */
  { 1,   "end opt",			ASN1_EOC,             ASN1_END  }, /*  2 */
  { 1,   "values",			ASN1_SEQUENCE,        ASN1_LOOP }, /*  3 */
  { 2,     "octets",			ASN1_OCTET_STRING,    ASN1_OPT |
							      ASN1_BODY }, /*  4 */
  { 2,     "end choice",		ASN1_EOC,             ASN1_END  }, /*  5 */
  { 2,     "oid",			ASN1_OID,	      ASN1_OPT |
							      ASN1_BODY }, /*  6 */
  { 2,     "end choice",		ASN1_EOC,             ASN1_END  }, /*  7 */
  { 2,     "string",			ASN1_UTF8STRING,      ASN1_OPT |
							      ASN1_BODY }, /*  8 */
  { 2,     "end choice",		ASN1_EOC,             ASN1_END  }, /*  9 */
  { 1,   "end loop",			ASN1_EOC,	      ASN1_END  }  /* 10 */
};

#define IETF_ATTR_ROOF		11

/* ASN.1 definition of roleSyntax */

static const asn1Object_t roleSyntaxObjects[] = 
{
  { 0, "roleSyntax",			ASN1_SEQUENCE,        ASN1_NONE }, /*  0 */
  { 1,   "roleAuthority",		ASN1_CONTEXT_C_0,     ASN1_OPT |
							      ASN1_OBJ  }, /*  1 */
  { 1,   "end opt",			ASN1_EOC,             ASN1_END  }, /*  2 */
  { 1,   "roleName",			ASN1_CONTEXT_C_1,     ASN1_OBJ  }  /*  3 */
};

#define ROLE_ROOF		4

/* ASN.1 definition of an X509 attribute certificate */

static const asn1Object_t acObjects[] =
{
  { 0, "AttributeCertificate",		ASN1_SEQUENCE,        ASN1_OBJ  }, /*  0 */
  { 1,   "AttributeCertificateInfo",    ASN1_SEQUENCE,        ASN1_OBJ  }, /*  1 */
  { 2,	   "version",			ASN1_INTEGER,	      ASN1_DEF |
							      ASN1_BODY }, /*  2 */
  { 2,	   "holder",                    ASN1_SEQUENCE,	      ASN1_NONE }, /*  3 */
  { 3,	     "baseCertificateID",	ASN1_CONTEXT_C_0,     ASN1_OPT  }, /*  4 */
  { 4,	       "issuer",		ASN1_SEQUENCE,	      ASN1_OBJ  }, /*  5 */
  { 4,	       "serial",		ASN1_INTEGER,	      ASN1_BODY }, /*  6 */
  { 4,         "issuerUID",		ASN1_BIT_STRING,      ASN1_OPT |
                                                              ASN1_BODY }, /*  7 */
  { 4,         "end opt",		ASN1_EOC,             ASN1_END  }, /*  8 */
  { 3,       "end opt",			ASN1_EOC,             ASN1_END  }, /*  9 */
  { 3,	     "entityName",		ASN1_CONTEXT_C_1,     ASN1_OPT |
							      ASN1_OBJ  }, /* 10 */
  { 3,       "end opt",			ASN1_EOC,             ASN1_END  }, /* 11 */
  { 3,	     "objectDigestInfo",	ASN1_CONTEXT_C_2,     ASN1_OPT  }, /* 12 */
  { 4,	       "digestedObjectType",	ASN1_ENUMERATED,      ASN1_BODY }, /* 13*/
  { 4,	       "otherObjectTypeID",	ASN1_OID,    	      ASN1_OPT |
							      ASN1_BODY }, /* 14 */
  { 4,         "end opt",		ASN1_EOC,             ASN1_END  }, /* 15*/
  { 4,         "digestAlgorithm",	ASN1_SEQUENCE,        ASN1_NONE }, /* 16 */
  { 5,           "algorithm",		ASN1_OID,             ASN1_BODY }, /* 17 */
  { 3,       "end opt",			ASN1_EOC,             ASN1_END  }, /* 18 */
  { 2,	   "v2Form",			ASN1_CONTEXT_C_0,     ASN1_NONE }, /* 19 */
  { 3,	     "issuerName",		ASN1_SEQUENCE,        ASN1_OPT |
                                                              ASN1_OBJ  }, /* 20 */
  { 3,       "end opt",			ASN1_EOC,             ASN1_END  }, /* 21 */
  { 3,	     "baseCertificateID",	ASN1_CONTEXT_C_0,     ASN1_OPT  }, /* 22 */
  { 4,	       "issuerSerial",		ASN1_SEQUENCE,        ASN1_NONE }, /* 23 */
  { 5,	         "issuer",		ASN1_SEQUENCE,	      ASN1_OBJ  }, /* 24 */
  { 5,	  	 "serial",		ASN1_INTEGER,	      ASN1_BODY }, /* 25 */
  { 5,           "issuerUID",		ASN1_BIT_STRING,      ASN1_OPT |
                                                              ASN1_BODY }, /* 26 */
  { 5,           "end opt",		ASN1_EOC,             ASN1_END  }, /* 27 */
  { 3,       "end opt",			ASN1_EOC,             ASN1_END  }, /* 28 */
  { 3,       "objectDigestInfo",	ASN1_CONTEXT_C_1,     ASN1_OPT  }, /* 29 */
  { 4,	       "digestInfo",		ASN1_SEQUENCE,        ASN1_OBJ  }, /* 30 */
  { 5,  	 "digestedObjectType",	ASN1_ENUMERATED,      ASN1_BODY }, /* 31 */
  { 5,	  	 "otherObjectTypeID",	ASN1_OID,    	      ASN1_OPT |
							      ASN1_BODY }, /* 32 */
  { 5,           "end opt",		ASN1_EOC,             ASN1_END  }, /* 33 */
  { 5,           "digestAlgorithm",	ASN1_SEQUENCE,        ASN1_NONE }, /* 34 */
  { 6,             "algorithm",		ASN1_OID,             ASN1_BODY }, /* 35 */
  { 3,       "end opt",			ASN1_EOC,             ASN1_END  }, /* 36 */
  { 2,	   "signature",                 ASN1_SEQUENCE,        ASN1_NONE }, /* 37 */
  { 3,	     "algorithm",               ASN1_OID,      	      ASN1_BODY }, /* 38 */
  { 2,	   "serialNumber",              ASN1_INTEGER,         ASN1_BODY }, /* 39 */
  { 2,	   "attrCertValidityPeriod",    ASN1_SEQUENCE,        ASN1_NONE }, /* 40 */
  { 3,	     "notBeforeTime",           ASN1_GENERALIZEDTIME, ASN1_BODY }, /* 41 */
  { 3,	     "notAfterTime",            ASN1_GENERALIZEDTIME, ASN1_BODY }, /* 42 */
  { 2,	   "attributes",                ASN1_SEQUENCE,        ASN1_LOOP }, /* 43 */
  { 3,       "attribute",		ASN1_SEQUENCE,        ASN1_NONE }, /* 44 */
  { 4,         "type",			ASN1_OID,             ASN1_BODY }, /* 45 */
  { 4,         "values",		ASN1_SET, 	      ASN1_LOOP }, /* 46 */
  { 5,           "value",		ASN1_SEQUENCE, 	      ASN1_OBJ  }, /* 47 */
  { 4, 	       "end loop",		ASN1_EOC,	      ASN1_END  }, /* 48 */
  { 2,     "end loop",			ASN1_EOC,             ASN1_END  }, /* 49 */
  { 2,     "extensions",		ASN1_SEQUENCE,        ASN1_LOOP }, /* 50 */
  { 3,       "extension",		ASN1_SEQUENCE,        ASN1_NONE }, /* 51 */
  { 4,         "extnID",		ASN1_OID,             ASN1_BODY }, /* 52 */
  { 4,         "critical",		ASN1_BOOLEAN,         ASN1_DEF |
							      ASN1_BODY }, /* 53 */
  { 4,         "extnValue",		ASN1_OCTET_STRING,    ASN1_BODY }, /* 54 */
  { 2,     "end loop",			ASN1_EOC,             ASN1_END  }, /* 55 */
  { 1,   "signatureAlgorithm",		ASN1_SEQUENCE,        ASN1_NONE }, /* 56 */
  { 2,     "algorithm",			ASN1_OID,             ASN1_BODY }, /* 57 */
  { 1,   "signature",			ASN1_BIT_STRING,      ASN1_BODY }  /* 58 */
};

#define AC_OBJ_CERTIFICATE		 0
#define AC_OBJ_CERTIFICATE_INFO		 1
#define AC_OBJ_VERSION			 2
#define AC_OBJ_HOLDER_ISSUER		 5
#define AC_OBJ_HOLDER_SERIAL		 6
#define AC_OBJ_ENTITY_NAME		10
#define AC_OBJ_ISSUER_NAME		20
#define AC_OBJ_ISSUER			24
#define AC_OBJ_SIG_ALG			38
#define AC_OBJ_SERIAL_NUMBER		39
#define AC_OBJ_NOT_BEFORE		41
#define AC_OBJ_NOT_AFTER		42
#define AC_OBJ_ATTRIBUTE_TYPE		45
#define AC_OBJ_ATTRIBUTE_VALUE		47
#define AC_OBJ_EXTN_ID			52
#define AC_OBJ_CRITICAL			53
#define AC_OBJ_EXTN_VALUE		54
#define AC_OBJ_ALGORITHM		57
#define AC_OBJ_SIGNATURE		58
#define AC_OBJ_ROOF			59

const ac_cert_t empty_ac = {
      NULL     , /* *next */
            0  , /* installed */
    { NULL, 0 }, /* certificate */
    { NULL, 0 }, /*   certificateInfo */
            1  , /*     version */
		 /*     holder */
		 /*       baseCertificateID */
    { NULL, 0 }, /*         holderIssuer */
    { NULL, 0 }, /*         holderSerial */
		 /*       entityName */
    { NULL, 0 }, /*         generalNames */
		 /*     v2Form */
    { NULL, 0 }, /*       issuerName */
                 /*     signature */
    { NULL, 0 }, /*       sigAlg */
    { NULL, 0 }, /*     serialNumber */
                 /*     attrCertValidityPeriod */
            0  , /*       notBefore */
            0  , /*       notAfter */
		 /*     attributes */
    { NULL, 0 }, /*       group */
		 /*     extensions */
    { NULL, 0 }, /*       authKeyID */
    { NULL, 0 }, /*       authKeySerialNumber */
      FALSE    , /*       noRevAvail */
		 /*   signatureAlgorithm */
    { NULL, 0 }, /*     algorithm */
    { NULL, 0 }, /*   signature */
};


/* Maximum length of ASN.1 distinquished name */

#define BUF_LEN	      512

/*
 * parses ietfAttrSyntax
 */
static void
parse_ietfAttrSyntax(chunk_t blob, int level0)
{
    asn1_ctx_t ctx;
    chunk_t object;
    int objectID = 0;

    asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

    while (objectID < IETF_ATTR_ROOF)
    {
	if (!extract_object(ietfAttrSyntaxObjects, &objectID, &object, &ctx))
	     return;

	switch (objectID) {
	default:
	    break;
	}
	objectID++;
    }
}

/*
 * parses roleSyntax
 */
static void
parse_roleSyntax(chunk_t blob, int level0)
{
    asn1_ctx_t ctx;
    chunk_t object;
    int objectID = 0;

    asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

    while (objectID < ROLE_ROOF)
    {
	if (!extract_object(roleSyntaxObjects, &objectID, &object, &ctx))
	     return;

	switch (objectID) {
	default:
	    break;
	}
	objectID++;
    }
}

/*
 *  Parses an X.509 attribute certificate
 */
static bool
parse_ac(chunk_t blob, ac_cert_t *ac)
{
    asn1_ctx_t ctx;
    bool critical;
    chunk_t extnID;
    chunk_t type;
    chunk_t object;
    int objectID = 0;

    asn1_init(&ctx, blob, 0, FALSE, DBG_RAW);

    while (objectID < AC_OBJ_ROOF) {

	if (!extract_object(acObjects, &objectID, &object, &ctx))
	     return FALSE;

	switch (objectID)
	{
	case AC_OBJ_CERTIFICATE:
	    ac->certificate = object;
	    break;
	case AC_OBJ_CERTIFICATE_INFO:
	    ac->certificateInfo = object;
	    break;
	case AC_OBJ_VERSION:
	    ac->version = (object.len) ? (1 + (u_int)*object.ptr) : 1;
	    DBG(DBG_PARSING,
		DBG_log("  v%d", ac->version);
	    )
	    if (ac->version != 2)
	    {
		plog("v%d attribute certificates are not supported"
		    , ac->version);
		return FALSE;
	    }
	    break;
	case AC_OBJ_HOLDER_ISSUER:
	    ac->holderIssuer = get_directoryName(object
		, acObjects[objectID].level, FALSE);
	    break;
	case AC_OBJ_HOLDER_SERIAL:
	    ac->holderSerial = object;
	    break;
	case AC_OBJ_ENTITY_NAME:
	    ac->entityName = get_directoryName(object
		, acObjects[objectID].level, TRUE);
	    break;
	case AC_OBJ_ISSUER_NAME:
	    ac->issuerName = get_directoryName(object
		, acObjects[objectID].level, FALSE);
	case AC_OBJ_SIG_ALG:
	    ac->sigAlg = object;
	    break;
	case AC_OBJ_SERIAL_NUMBER:
	    ac->serialNumber = object;
	    break;
	case AC_OBJ_NOT_BEFORE:
	    ac->notBefore = asn1totime(&object, ASN1_GENERALIZEDTIME);
	    break;
	case AC_OBJ_NOT_AFTER:
	    ac->notAfter = asn1totime(&object, ASN1_GENERALIZEDTIME);
	    break;
	case AC_OBJ_ATTRIBUTE_TYPE:
	    type = object;
	    break;
	case AC_OBJ_ATTRIBUTE_VALUE:
	    {
		u_int type_oid = known_oid(type);
		u_int level = acObjects[objectID].level;

		switch (type_oid) {
		case OID_AUTHENTICATION_INFO:
		    DBG(DBG_PARSING,
			DBG_log("  need to parse authenticationInfo")
		    )
		    break;
		case OID_ACCESS_IDENTITY:
		    DBG(DBG_PARSING,
			DBG_log("  need to parse accessIdentity")
		    )
		    break;
		case OID_CHARGING_IDENTITY:
		    parse_ietfAttrSyntax(object, level);
		    break;
		case OID_GROUP:
		    parse_ietfAttrSyntax(object, level);
		    break;
		case OID_ROLE:
		    parse_roleSyntax(object, level);
		    break;
		default:
		    break;
		}
	    }
	    break;
	case AC_OBJ_EXTN_ID:
	    extnID = object;
	    break;
	case AC_OBJ_CRITICAL:
	    critical = object.len && *object.ptr;
	    DBG(DBG_PARSING,
		DBG_log("  %s",(critical)?"TRUE":"FALSE");
	    )
	    break;
	case AC_OBJ_EXTN_VALUE:
	    {
		u_int extn_oid = known_oid(extnID);
		u_int level = acObjects[objectID].level + 1;

		switch (extn_oid) {
		case OID_CRL_DISTRIBUTION_POINTS:
		    DBG(DBG_PARSING,
			DBG_log("  need to parse crlDistributionPoints")
		    )
		    break;
		case OID_AUTHORITY_KEY_ID:
		    parse_authorityKeyIdentifier(object, level
			, &ac->authKeyID, &ac->authKeySerialNumber);
		    break;
		case OID_TARGET_INFORMATION:
		    DBG(DBG_PARSING,
			DBG_log("  need to parse targetInformation")
		    )
		    break;
		case OID_NO_REV_AVAIL:
		    ac->noRevAvail = TRUE;
		    break;
		default:
		    break;
		}
	    }
	    break;
	case AC_OBJ_ALGORITHM:
	    ac->algorithm = object;
	    break;
	case AC_OBJ_SIGNATURE:
	    ac->signature = object;
	    break;

	default:
	    break;
	}
	objectID++;
    }
    time(&ac->installed);
    return TRUE;
}

/*
 * Loads X.509 attribute certificates
 */
void
load_acerts(void)
{
    u_char buf[BUF_LEN];

    /* change directory to specified path */
    u_char *save_dir = getcwd(buf, BUF_LEN);

    if (!chdir(A_CERT_PATH))
    {
	struct dirent **filelist;
	int n;

	plog("Changing to directory '%s'",A_CERT_PATH);
	n = scandir(A_CERT_PATH, &filelist, file_select, alphasort);

	if (n > 0)
	{
	    while (n--)
	    {
		chunk_t blob = empty_chunk;
		bool pgp = FALSE;

		if (load_coded_file(filelist[n]->d_name, NULL, "acert", &blob, &pgp))
		{
		    char buf[BUF_LEN];
		    ac_cert_t ac = empty_ac;

		    if (parse_ac(blob, &ac))
		    {
			DBG(DBG_PARSING,
			    dntoa_or_null(buf, BUF_LEN, ac.holderIssuer, "empty");
			    DBG_log("Holder Issuer: '%s'", buf);
			    dntoa_or_null(buf, BUF_LEN, ac.entityName, "empty");
			    DBG_log("Entity Name: '%s'", buf);
			)
		    }
		    pfree(blob.ptr);
		}
		free(filelist[n]);
	    }
	    free(filelist);
	}
    }
    /* restore directory path */
    chdir(save_dir);
}
