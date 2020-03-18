#ifndef __seam_x509_list_c__
#define __seam_x509_list_c__
#include "pluto/x509lists.h"

/** by default pluto does not check crls dynamically */
long crl_check_interval = 0;

/* fetch.c SEAM */
void list_crl_fetch_requests(bool utc) {}

/* ac.c SEAM */
void decode_groups(char *groups, ietfAttrList_t **listp) {}
void load_acerts(void) {}
void list_acerts(bool utc) {}
void list_groups(bool utc) {}
void free_ietfAttrList(ietfAttrList_t* list) {}

/* x509.c SEAM */
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

#if 0
	    cert_t c;

	    c.type = CERT_X509_SIGNATURE;
	    c.u.x509 = cert;
#endif

	    if (first)
	    {
		DBG_log( " ");
		DBG_log( "List of X.509 %s Certificates:", caption);
		DBG_log( " ");
		first = FALSE;
	    }

	    DBG_log( "NOW, count: %d", cert->count);
	    dntoa(buf, ASN1_BUF_LEN, cert->subject);
	    DBG_log( "       subject: '%s'", buf);
	    dntoa(buf, ASN1_BUF_LEN, cert->issuer);
	    DBG_log( "       issuer:  '%s'", buf);
	    datatot(cert->serialNumber.ptr, cert->serialNumber.len, ':'
		, buf, ASN1_BUF_LEN);
	    DBG_log( "       serial:   %s", buf);
	    form_keyid(cert->publicExponent, cert->modulus, keyid, &keysize);
	    DBG_log( "       pubkey:   %4d RSA Key %s"
                    , 8*keysize, keyid);
	    DBG_log( "       validity: not before %s %s",
		timetoa(&cert->notBefore, utc, tbuf, sizeof(tbuf)),
		(cert->notBefore < tnow)?"ok":"fatal (not valid yet)");
	    DBG_log( "                 not after  %s %s",
		timetoa(&cert->notAfter, utc, tbuf, sizeof(tbuf)),
		check_expiry(cert->notAfter, CA_CERT_WARNING_INTERVAL, TRUE));
	    if (cert->subjectKeyID.ptr != NULL)
	    {
		datatot(cert->subjectKeyID.ptr, cert->subjectKeyID.len, ':'
		    , buf, ASN1_BUF_LEN);
		DBG_log( "       subjkey:  %s", buf);
	    }
	    if (cert->authKeyID.ptr != NULL)
	    {
		datatot(cert->authKeyID.ptr, cert->authKeyID.len, ':'
		    , buf, ASN1_BUF_LEN);
		DBG_log( "       authkey:  %s", buf);
	    }
	    if (cert->authKeySerialNumber.ptr != NULL)
	    {
		datatot(cert->authKeySerialNumber.ptr, cert->authKeySerialNumber.len
		    , ':', buf, ASN1_BUF_LEN);
		DBG_log( "       aserial:  %s", buf);
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
void list_certs(bool utc) {
  list_x509_end_certs(utc);
}

void list_authcerts(const char *caption, u_char auth_flags, bool utc) {}
void list_crls(bool utc, bool strict) {}

#endif
