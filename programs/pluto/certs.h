/* Certificate support for IKE authentication
 * Copyright (C) 2002-2003 Andreas Steffen, Zuercher Hochschule Winterthur
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
 * RCSID $Id: certs.h,v 1.3 2003/12/24 19:51:20 mcr Exp $
 */

#ifndef _CERTS_H
#define _CERTS_H

/* path definitions for private keys, end certs,
 * cacerts, attribute certs and crls
 */
#define A_CERT_PATH	  plutopaths.acerts.path
#define CA_CERT_PATH	  plutopaths.cacerts.path
#define CRL_PATH	  plutopaths.crls.path
#define PRIVATE_KEY_PATH  plutopaths.private.path
#define HOST_CERT_PATH    plutopaths.certs.path

/* advance warning of imminent expiry of
 * cacerts, public keys, and crls
 */
#define CA_CERT_WARNING_INTERVAL	30 /* days */
#define PUBKEY_WARNING_INTERVAL		 7 /* days */
#define CRL_WARNING_INTERVAL		 7 /* days */

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
    u_char type;
    union {
	x509cert_t *x509;
	pgpcert_t  *pgp;
    } u;
} cert_t;

/*  do not send certificate requests
 *  flag set in plutomain.c and used in ipsec_doi.c
 */
extern bool no_cr_send;

extern rsa_privkey_t* load_rsa_private_key(const char* filename
    , prompt_pass_t *pass);
extern chunk_t get_mycert(cert_t cert);
extern bool load_coded_file(const char *filename, prompt_pass_t *pass
    , const char *type, chunk_t *blob, bool *pgp);
extern bool load_cert(const char *filename, const char *label
    , cert_t *cert);
extern bool load_host_cert(const char *filename, cert_t *cert);
extern void share_cert(cert_t cert);
extern void release_cert(cert_t cert);
extern void list_certs(bool utc);




#endif /* _CERTS_H */
