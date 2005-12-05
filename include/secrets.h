/* mechanisms for preshared keys (public, private, and preshared secrets)
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
 * RCSID $Id: keys.h,v 1.35 2005/02/15 01:52:30 mcr Exp $
 */
#ifndef _SECRETS_H
#define _SECRETS_H

#include <gmp.h>    /* GNU MP library */
#include "id.h"

#ifndef SHARED_SECRETS_FILE
# define SHARED_SECRETS_FILE  "/etc/ipsec.secrets"
#endif

struct state;	 /* forward declaration */
struct secret;  /* opaque definition, private to secrets.c */

const char *shared_secrets_file;

struct RSA_public_key
{
    char keyid[KEYID_BUF];	/* see ipsec_keyblobtoid(3) */

    /* length of modulus n in octets: [RSA_MIN_OCTETS, RSA_MAX_OCTETS] */
    unsigned k;

    /* public: */
    MP_INT
	n,	/* modulus: p * q */
	e;	/* exponent: relatively prime to (p-1) * (q-1) [probably small] */
};

struct RSA_private_key {
    struct RSA_public_key pub;	/* must be at start for RSA_show_public_key */

    MP_INT
	d,	/* private exponent: (e^-1) mod ((p-1) * (q-1)) */
	/* help for Chinese Remainder Theorem speedup: */
	p,	/* first secret prime */
	q,	/* second secret prime */
	dP,	/* first factor's exponent: (e^-1) mod (p-1) == d mod (p-1) */
	dQ,	/* second factor's exponent: (e^-1) mod (q-1) == d mod (q-1) */
	qInv;	/* (q^-1) mod p */
};

extern void free_RSA_public_content(struct RSA_public_key *rsa);

extern err_t unpack_RSA_public_key(struct RSA_public_key *rsa, const chunk_t *pubkey);

struct smartcard;
struct private_key_stuff {
    enum PrivateKeyKind kind;
    union {
	chunk_t preshared_secret;
	struct RSA_private_key RSA_private_key;
	struct smartcard *smartcard;
    } u;
};

extern const struct private_key_stuff *osw_get_pks(const struct secret *s);


/* public key machinery  */
struct pubkey {
    struct id id;
    unsigned refcnt;	/* reference counted! */
    enum dns_auth_level dns_auth_level;
    char *dns_sig;
    time_t installed_time
	, last_tried_time
	, last_worked_time
	, until_time;
    chunk_t issuer;
    enum pubkey_alg alg;
    union {
	struct RSA_public_key rsa;
    } u;
};

struct pubkey_list {
    struct pubkey *key;
    struct pubkey_list *next;
};


extern struct pubkey_list *pubkeys;	/* keys from ipsec.conf */

extern struct pubkey *public_key_from_rsa(const struct RSA_public_key *k);
extern struct pubkey_list *free_public_keyentry(struct pubkey_list *p);
extern void free_public_keys(struct pubkey_list **keys);
extern void free_remembered_public_keys(void);
extern void delete_public_keys(struct pubkey_list **head
			       , const struct id *id
			       , enum pubkey_alg alg);
extern void form_keyid(chunk_t e, chunk_t n, char* keyid, unsigned *keysize);

extern struct pubkey *reference_key(struct pubkey *pk);
extern void unreference_key(struct pubkey **pkp);


extern err_t add_public_key(const struct id *id
    , enum dns_auth_level dns_auth_level
    , enum pubkey_alg alg
    , const chunk_t *key
    , struct pubkey_list **head);

extern bool same_RSA_public_key(const struct RSA_public_key *a
    , const struct RSA_public_key *b);

extern void install_public_key(struct pubkey *pk, struct pubkey_list **head);
extern void free_public_key(struct pubkey *pk);

extern void osw_load_preshared_secrets(struct secret **psecrets
				       , const char *secrets_file
				       , int whackfd);
extern void osw_free_preshared_secrets(struct secret **psecrets);

extern bool osw_has_private_rawkey(struct secret *secrets, struct pubkey *pk);

extern struct secret *osw_find_secret_by_id(struct secret *secrets
					    , enum PrivateKeyKind kind
					    , const struct id *my_id
					    , const struct id *his_id
					    , bool asym);

#ifdef HAVE_THREADS
extern void lock_certs_and_keys(const char *who);
extern void unlock_certs_and_keys(const char *who);
#else
#define lock_certs_and_keys(who)  /* nothing */
#define unlock_certs_and_keys(who) /* nothing */
#endif

#include "x509.h"
extern const struct RSA_private_key*
osw_get_x509_private_key(struct secret *secrets, x509cert_t *cert);



#endif /* _SECRETS_H */
