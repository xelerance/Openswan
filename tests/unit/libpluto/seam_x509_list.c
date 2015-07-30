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

	    cert_t c;

	    c.type = CERT_X509_SIGNATURE;
	    c.u.x509 = cert;

	    if (first)
	    {
		printf( " \n");
		printf( "List of X.509 %s Certificates:\n", caption);
		printf( " \n");
		first = FALSE;
	    }

	    printf( "%s, count: %d\n", timetoa(&cert->installed, utc, tbuf, sizeof(tbuf)),
		      cert->count);
	    dntoa(buf, ASN1_BUF_LEN, cert->subject);
	    printf( "       subject: '%s'\n", buf);
	    dntoa(buf, ASN1_BUF_LEN, cert->issuer);
	    printf( "       issuer:  '%s'\n", buf);
	    datatot(cert->serialNumber.ptr, cert->serialNumber.len, ':'
		, buf, ASN1_BUF_LEN);
	    printf( "       serial:   %s\n", buf);
	    form_keyid(cert->publicExponent, cert->modulus, keyid, &keysize);
	    printf( "       pubkey:   %4d RSA Key %s\n"
                    , 8*keysize, keyid);
	    printf( "       validity: not before %s %s\n",
		timetoa(&cert->notBefore, utc, tbuf, sizeof(tbuf)),
		(cert->notBefore < tnow)?"ok":"fatal (not valid yet)");
	    printf( "                 not after  %s %s\n",
		timetoa(&cert->notAfter, utc, tbuf, sizeof(tbuf)),
		check_expiry(cert->notAfter, CA_CERT_WARNING_INTERVAL, TRUE));
	    if (cert->subjectKeyID.ptr != NULL)
	    {
		datatot(cert->subjectKeyID.ptr, cert->subjectKeyID.len, ':'
		    , buf, ASN1_BUF_LEN);
		printf( "       subjkey:  %s\n", buf);
	    }
	    if (cert->authKeyID.ptr != NULL)
	    {
		datatot(cert->authKeyID.ptr, cert->authKeyID.len, ':'
		    , buf, ASN1_BUF_LEN);
		printf( "       authkey:  %s\n", buf);
	    }
	    if (cert->authKeySerialNumber.ptr != NULL)
	    {
		datatot(cert->authKeySerialNumber.ptr, cert->authKeySerialNumber.len
		    , ':', buf, ASN1_BUF_LEN);
		printf( "       aserial:  %s\n", buf);
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

