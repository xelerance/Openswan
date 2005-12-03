/* Certificate support for IKE authentication
 * Copyright (C) 2002-2004 Andreas Steffen, Zuercher Hochschule Winterthur
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
 * RCSID $Id: certs.h,v 1.6 2004/06/27 20:43:41 mcr Exp $
 */

#ifndef _CERTS_H
#define _CERTS_H

#include "openswan/ipsec_policy.h"

#include "x509.h"
#include "pgp.h"

/* path definitions for private keys, end certs,
 * cacerts, attribute certs and crls
 */
#define A_CERT_PATH	  plutopaths.acerts.path
#define CA_CERT_PATH	  plutopaths.cacerts.path
#define CRL_PATH	  plutopaths.crls.path
#define PRIVATE_KEY_PATH  plutopaths.private.path
#define HOST_CERT_PATH    plutopaths.certs.path
#define AA_CERT_PATH      plutopaths.aacerts.path
#define OCSP_CERT_PATH    plutopaths.ocspcerts.path


/* advance warning of imminent expiry of
 * cacerts, public keys, and crls
 */
#define CA_CERT_WARNING_INTERVAL	30 /* days */
#define OCSP_CERT_WARNING_INTERVAL      30 /* days */
#define PUBKEY_WARNING_INTERVAL		 7 /* days */
#define CRL_WARNING_INTERVAL		 7 /* days */
#define ACERT_WARNING_INTERVAL           1 /* day */


/* access structure for RSA private keys */

typedef struct rsa_privkey rsa_privkey_t;

struct rsa_privkey {
    chunk_t keyobject;
    chunk_t field[8];
};

/* used for initialization */
extern const rsa_privkey_t empty_rsa_privkey;

/* certificate access structure
 * currently X.509 and OpenPGP certificates are supported
 */
typedef struct {
    bool                 forced;
    enum ipsec_cert_type type;       
    union {
      x509cert_t *x509;
      pgpcert_t  *pgp;
      chunk_t    blob;
    } u;
} cert_t;

/* used for initialization */
extern const cert_t empty_cert;

/*  do not send certificate requests
 *  flag set in plutomain.c and used in ipsec_doi.c
 */
extern bool no_cr_send;

extern chunk_t get_mycert(cert_t cert);
extern bool load_cert(bool forcedtype
		      , const char *filename
		      , const char *label, cert_t *cert);
extern bool load_host_cert(enum ipsec_cert_type certtype, const char *filename, cert_t *cert);
extern bool same_cert(const cert_t *a, const cert_t *b);
extern void share_cert(cert_t cert);
extern void release_cert(cert_t cert);
extern void list_certs(bool utc);



#define MAX_PROMPT_PASS_TRIALS	5
#define PROMPT_PASS_LEN		64

/* struct used to prompt for a secret passphrase
 * from a console with file descriptor fd
 */
typedef struct {
    char secret[PROMPT_PASS_LEN];
    bool prompt;
    int fd;
} prompt_pass_t;


extern rsa_privkey_t* load_rsa_private_key(const char* filename
					   , prompt_pass_t *pass);
extern bool load_coded_file(const char *filename, prompt_pass_t *pass
			    , const char *type, chunk_t *blob, bool *pgp);

#endif /* _CERTS_H */

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
