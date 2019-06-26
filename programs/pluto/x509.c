/* Support of X.509 certificates and CRLs
 * Copyright (C) 2000 Andreas Hess, Patric Lichtsteiner, Roger Wegmann
 * Copyright (C) 2001 Marco Bertossa, Andreas Schleiss
 * Copyright (C) 2002 Mario Strasser
 * Copyright (C) 2000-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2006-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Gilles Espinasse <g.esp@free.fr>
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
 * Modifications to use OCF interface written by
 * Daniel Djamaludin <danield@cyberguard.com>
 * Copyright (C) 2004-2005 Intel Corporation.  All Rights Reserved.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <limits.h>
#include <sys/types.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "sysdep.h"
#include "oswconf.h"
#include "constants.h"
#include "oswlog.h"
#include "oswtime.h"

#include "oswalloc.h"
#include "oswlog.h"
#include "id.h"
#include "asn1.h"
#include "mpzfuncs.h"
#include "oid.h"
#include "pluto/defs.h"
#include "x509.h"
#include "pluto/ocsp.h"
#include "pluto/keys.h"
#include "plutocerts.h"
#include "x509more.h"
#include "pgp.h"
#include "certs.h"
#include "md5.h"
#include "sha1.h"
#include "whack.h"
#include "pkcs.h"
#include "log.h"

#define OCSP_BUF_LEN			512

/*
 *  list all X.509 certs in a chained list
 */
static void
list_x509cert_chain(const char *caption, x509cert_t* cert, u_char auth_flags
 , bool utc)
{
    bool first = TRUE;
    time_t tnow;

    /* determine the current time */
    time(&tnow);

    while (cert != NULL)
    {
	if (auth_flags == AUTH_NONE || (auth_flags & cert->authority_flags))
	{
	    unsigned keysize;
	    char keyid[KEYID_BUF];
	    char buf[ASN1_BUF_LEN];
	    char tbuf[TIMETOA_BUF];

	    cert_t c;

	    c.type = CERT_X509_SIGNATURE;
	    c.u.x509 = cert;

	    if (first)
	    {
		whack_log(RC_COMMENT, " ");
		whack_log(RC_COMMENT, "List of X.509 %s Certificates:", caption);
		whack_log(RC_COMMENT, " ");
		first = FALSE;
	    }

	    whack_log(RC_COMMENT, "%s, count: %d", timetoa(&cert->installed, utc, tbuf, sizeof(tbuf)),
		      cert->count);
	    dntoa(buf, ASN1_BUF_LEN, cert->subject);
	    whack_log(RC_COMMENT, "       subject: '%s'", buf);
	    dntoa(buf, ASN1_BUF_LEN, cert->issuer);
	    whack_log(RC_COMMENT, "       issuer:  '%s'", buf);
	    datatot(cert->serialNumber.ptr, cert->serialNumber.len, ':'
		, buf, ASN1_BUF_LEN);
	    whack_log(RC_COMMENT, "       serial:   %s", buf);
	    form_keyid(cert->publicExponent, cert->modulus, keyid, &keysize);
	    whack_log(RC_COMMENT, "       pubkey:   %4d RSA Key %s%s"
		, 8*keysize, keyid
		, has_private_key(c)? ", has private key" : "");
	    whack_log(RC_COMMENT, "       validity: not before %s %s",
		timetoa(&cert->notBefore, utc, tbuf, sizeof(tbuf)),
		(cert->notBefore < tnow)?"ok":"fatal (not valid yet)");
	    whack_log(RC_COMMENT, "                 not after  %s %s",
		timetoa(&cert->notAfter, utc, tbuf, sizeof(tbuf)),
		check_expiry(cert->notAfter, CA_CERT_WARNING_INTERVAL, TRUE));
	    if (cert->subjectKeyID.ptr != NULL)
	    {
		datatot(cert->subjectKeyID.ptr, cert->subjectKeyID.len, ':'
		    , buf, ASN1_BUF_LEN);
		whack_log(RC_COMMENT, "       subjkey:  %s", buf);
	    }
	    if (cert->authKeyID.ptr != NULL)
	    {
		datatot(cert->authKeyID.ptr, cert->authKeyID.len, ':'
		    , buf, ASN1_BUF_LEN);
		whack_log(RC_COMMENT, "       authkey:  %s", buf);
	    }
	    if (cert->authKeySerialNumber.ptr != NULL)
	    {
		datatot(cert->authKeySerialNumber.ptr, cert->authKeySerialNumber.len
		    , ':', buf, ASN1_BUF_LEN);
		whack_log(RC_COMMENT, "       aserial:  %s", buf);
	    }
	}
	cert = cert->next;
    }
}

/*
 *  list all X.509 end certificates in a chained list
 */
void
list_x509_end_certs(bool utc)
{
    list_x509cert_chain("End", x509certs, AUTH_NONE, utc);
}

/*
 *  list all X.509 authcerts with given auth flags in a chained list
 */
void
list_authcerts(const char *caption, u_char auth_flags, bool utc)
{
    lock_authcert_list("list_authcerts");
    list_x509cert_chain(caption, x509_get_authcerts_chain(), auth_flags, utc);
    unlock_authcert_list("list_authcerts");
}

/*
 *  list all X.509 crls in the chained list
 */
void
list_crls(bool utc, bool strict)
{
    x509crl_t *crl;

    lock_crl_list("list_crls");
    crl = x509crls;

    if (crl != NULL)
    {
	whack_log(RC_COMMENT, " ");
	whack_log(RC_COMMENT, "List of X.509 CRLs:");
	whack_log(RC_COMMENT, " ");
    }

    while (crl != NULL)
    {
	char buf[ASN1_BUF_LEN];
	u_int revoked = 0;
	revokedCert_t *revokedCert = crl->revokedCertificates;
	char tbuf[TIMETOA_BUF];

	/* count number of revoked certificates in CRL */
	while (revokedCert != NULL)
	{
	    revoked++;
	    revokedCert = revokedCert->next;
        }

	whack_log(RC_COMMENT, "%s, revoked certs: %d",
		  timetoa(&crl->installed, utc, tbuf, sizeof(tbuf)), revoked);
	dntoa(buf, ASN1_BUF_LEN, crl->issuer);
	whack_log(RC_COMMENT, "       issuer:  '%s'", buf);

#ifdef HAVE_THREADS
	/* list all distribution points */
	list_distribution_points(crl->distributionPoints);
#endif

	whack_log(RC_COMMENT, "       updates:  this %s",
		  timetoa(&crl->thisUpdate, utc, tbuf, sizeof(tbuf)));
	whack_log(RC_COMMENT, "                 next %s %s"
		  , timetoa(&crl->nextUpdate, utc, tbuf, sizeof(tbuf))
		  , check_expiry(crl->nextUpdate, CRL_WARNING_INTERVAL, strict));
	if (crl->authKeyID.ptr != NULL)
	{
	    datatot(crl->authKeyID.ptr, crl->authKeyID.len, ':'
		, buf, ASN1_BUF_LEN);
	    whack_log(RC_COMMENT, "       authkey:  %s", buf);
	}
	if (crl->authKeySerialNumber.ptr != NULL)
	{
	    datatot(crl->authKeySerialNumber.ptr, crl->authKeySerialNumber.len, ':'
		, buf, ASN1_BUF_LEN);
	    whack_log(RC_COMMENT, "       aserial:  %s", buf);
	}

	crl = crl->next;
    }
    unlock_crl_list("list_crls");
}

/*
 *  list all PGP end certificates in a chained list
 */
void
list_pgp_end_certs(bool utc)
{
   pgpcert_t *cert = pgpcerts;

    /* determine the current time */

    if (cert != NULL)
    {
	whack_log(RC_COMMENT, " ");
	whack_log(RC_COMMENT, "List of PGP End certificates:");
	whack_log(RC_COMMENT, " ");
    }

    while (cert != NULL)
    {
	unsigned keysize;
	char buf[ASN1_BUF_LEN];
	char tbuf[TIMETOA_BUF];
	cert_t c;

	c.type = CERT_PGP;
	c.u.pgp = cert;

	whack_log(RC_COMMENT, "%s, count: %d"
		  , timetoa(&cert->installed, utc, tbuf, sizeof(tbuf))
		  , cert->count);
	datatot((unsigned char *)cert->fingerprint, PGP_FINGERPRINT_SIZE, 'x', buf, ASN1_BUF_LEN);
	whack_log(RC_COMMENT, "       fingerprint:  %s", buf);
	form_keyid(cert->publicExponent, cert->modulus, buf, &keysize);
	whack_log(RC_COMMENT, "       pubkey:   %4d RSA Key %s%s", 8*keysize, buf,
		(has_private_key(c))? ", has private key" : "");
	whack_log(RC_COMMENT, "       created:  %s"
		  , timetoa(&cert->created, utc, tbuf, sizeof(tbuf)));
	whack_log(RC_COMMENT, "       until:    %s %s"
		  , timetoa(&cert->until, utc, tbuf, sizeof(tbuf)),
		check_expiry(cert->until, CA_CERT_WARNING_INTERVAL, TRUE));
	cert = cert->next;
    }
}

/*
 *  list all X.509 and OpenPGP end certificates
 */
void
list_certs(bool utc)
{
    list_x509_end_certs(utc);
    list_pgp_end_certs(utc);
}

/*
 * list a chained list of ocsp_locations
 */
void
list_ocsp_locations(ocsp_location_t *location, bool requests, bool utc
, bool strict)
{
    bool first = TRUE;

    while (location != NULL)
    {
	ocsp_certinfo_t *certinfo = location->certinfo;

	if (certinfo != NULL)
	{
	    char buf[OCSP_BUF_LEN];

	    if (first)
	    {
		whack_log(RC_COMMENT, " ");
		whack_log(RC_COMMENT, "List of OCSP %s:", requests?
		    "fetch requests":"responses");
		first = FALSE;
            }
	    whack_log(RC_COMMENT, " ");
	    if (location->issuer.ptr != NULL)
	    {
		dntoa(buf, OCSP_BUF_LEN, location->issuer);
		whack_log(RC_COMMENT, "       issuer:  '%s'", buf);
	    }
	    whack_log(RC_COMMENT, "       uri:     '%.*s", (int)location->uri.len
		, location->uri.ptr);
	    if (location->authNameID.ptr != NULL)
	    {
		datatot(location->authNameID.ptr, location->authNameID.len, ':'
		    , buf, OCSP_BUF_LEN);
		whack_log(RC_COMMENT, "       authname: %s", buf);
	    }
	    if (location->authKeyID.ptr != NULL)
	    {
		datatot(location->authKeyID.ptr, location->authKeyID.len, ':'
		    , buf, OCSP_BUF_LEN);
		whack_log(RC_COMMENT, "       authkey:  %s", buf);
	    }
	    if (location->authKeySerialNumber.ptr != NULL)
	    {
		datatot(location->authKeySerialNumber.ptr
		    , location->authKeySerialNumber.len, ':', buf, OCSP_BUF_LEN);
		whack_log(RC_COMMENT, "       aserial:  %s", buf);
	    }
	    while (certinfo != NULL)
	    {
		char thisUpdate[TIMETOA_BUF];

		timetoa(&certinfo->thisUpdate, utc, thisUpdate, sizeof(thisUpdate));

		if (requests)
		{
		    whack_log(RC_COMMENT, "%s, trials: %d", thisUpdate
			, certinfo->trials);
		}
		else if (certinfo->once)
		{
		    whack_log(RC_COMMENT, "%s, onetime use%s", thisUpdate
			, (certinfo->nextUpdate < time(NULL))? " (expired)": "");
		}
		else
		{
		    char tbuf2[TIMETOA_BUF];

		    whack_log(RC_COMMENT, "%s, until %s %s", thisUpdate
			      , timetoa(&certinfo->nextUpdate, utc, tbuf2, sizeof(tbuf2))
			      , check_expiry(certinfo->nextUpdate, OCSP_WARNING_INTERVAL, strict));
		}
		datatot(certinfo->serialNumber.ptr, certinfo->serialNumber.len, ':'
		    , buf, OCSP_BUF_LEN);
		whack_log(RC_COMMENT, "       serial:   %s, %s", buf
		    , cert_status_names[certinfo->status]);
		certinfo = certinfo->next;
	    }
	}
	location = location->next;
    }
}

/*
 * list the ocsp cache
 */
void
list_ocsp_cache(bool utc, bool strict)
{
    lock_ocsp_cache("list_ocsp_cache");
    list_ocsp_locations(ocsp_cache, FALSE, utc, strict);
    unlock_ocsp_cache("list_ocsp_cache");
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
