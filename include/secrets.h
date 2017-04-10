/* mechanisms for preshared keys (public, private, and preshared secrets)
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
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
 */
#ifndef _SECRETS_H
#define _SECRETS_H

#include <gmp.h>    /* GNU MP library */
#include "id.h"

#ifdef HAVE_LIBNSS
# include <nss.h>
# include <pk11pub.h>
#endif

#ifndef SHARED_SECRETS_FILE
# define SHARED_SECRETS_FILE  "/etc/ipsec.secrets"
#endif

struct state;	 /* forward declaration */
struct secret;  /* opaque definition, private to secrets.c */

/* do mass rename later on */
typedef struct pubkey osw_public_key;


struct RSA_public_key
{
    char keyid[KEYID_BUF];	    /* see ipsec_keyblobtoid(3) */
    /* length of modulus n in octets: [RSA_MIN_OCTETS, RSA_MAX_OCTETS] */
    unsigned k;

    chunk_t        key_rfc3110;     /* Raw Public key format */

    /* public: */
    MP_INT
	n,	/* modulus: p * q */
	e;	/* exponent: relatively prime to (p-1) * (q-1) [probably small] */
};

struct RSA_private_key {
    MP_INT
	d,	/* private exponent: (e^-1) mod ((p-1) * (q-1)) */
	/* help for Chinese Remainder Theorem speedup: */
	p,	/* first secret prime */
	q,	/* second secret prime */
	dP,	/* first factor's exponent: (e^-1) mod (p-1) == d mod (p-1) */
	dQ,	/* second factor's exponent: (e^-1) mod (q-1) == d mod (q-1) */
	qInv;	/* (q^-1) mod p */
#ifdef HAVE_LIBNSS
    unsigned char ckaid[HMAC_BUFSIZE];  /*ckaid for use in NSS*/
    unsigned int  ckaid_len;
#endif
};

extern void free_RSA_public_content(struct RSA_public_key *rsa);

extern err_t unpack_RSA_public_key(struct RSA_public_key *rsa, const chunk_t *pubkey);

struct private_key_stuff {
    enum PrivateKeyKind kind;
    osw_public_key *pub;

    union {
	chunk_t preshared_secret;
	struct RSA_private_key RSA_private_key;
        /* struct ECDSA_private_key ECDSA_private_key; */
	/* struct smartcard *smartcard; */
    } u;
};

extern struct private_key_stuff *osw_get_pks(struct secret *s);
extern int osw_get_secretlineno(const struct secret *s);
extern struct id_list *osw_get_idlist(const struct secret *s);

/*
 * return 1 to continue to next,
 * return 0 to return current secret
 * return -1 to return NULL
 */
typedef int (*secret_eval)(struct secret *secret,
			   struct private_key_stuff *pks,
			   void *uservoid);

extern struct secret *osw_foreach_secret(struct secret *secrets,
					 secret_eval func, void *uservoid);
extern struct secret *osw_get_defaultsecret(struct secret *secrets);


/* public key machinery  */
struct pubkey {
    struct id id;
    unsigned refcnt;	/* reference counted! */
    bool trusted_key;   /* if this key has been loaded from disk, or validated */
    enum dns_auth_level dns_auth_level;
    char *dns_sig;
    time_t installed_time
	, last_tried_time
	, last_worked_time
	, until_time;
    chunk_t issuer;

    unsigned char key_ckaid[CKAID_BUFSIZE];  /* typically, 20 bytes, presented in hex */
    char key_ckaid_print_buf[CKAID_BUFSIZE*2 + (CKAID_BUFSIZE/2)+2];  /* a buffer for above, produced by datatot */

    enum pubkey_alg alg;

#ifdef HAVE_LIBNSS
    CERTCertificate *nssCert;
#endif
    union {
	struct RSA_public_key rsa;
    } u;
};

struct pubkey_list {
    struct pubkey *key;
    struct pubkey_list *next;
};


/* struct used to prompt for a secret passphrase
 * from a console with file descriptor fd
 */
#define MAX_PROMPT_PASS_TRIALS	5
#define PROMPT_PASS_LEN		64

typedef void (*pass_prompt_func)(int mess_no, const char *message, ...) PRINTF_LIKE(2);

typedef struct {
    char secret[PROMPT_PASS_LEN];
    pass_prompt_func prompt;
    int fd;
} prompt_pass_t;


extern struct pubkey_list *pubkeys;	/* keys from ipsec.conf */

extern struct pubkey *public_key_from_rsa(const struct RSA_public_key *k);
extern struct pubkey_list *free_public_keyentry(struct pubkey_list *p);
extern void free_public_keys(struct pubkey_list **keys);
extern void free_remembered_public_keys(void);
extern void delete_public_keys(struct pubkey_list **head
			       , const struct id *id
			       , enum pubkey_alg alg);
extern void form_keyid(chunk_t e, chunk_t n, char* keyid, unsigned *keysize);

#ifdef HAVE_LIBNSS
extern void form_keyid_from_nss(SECItem e, SECItem n, char* keyid, unsigned *keysize);
extern err_t extract_and_add_secret_from_nss_cert_file(struct private_key_stuff *pks, char *nssHostCertNickName);
#endif

extern struct pubkey *reference_key(struct pubkey *pk);
extern void unreference_key(struct pubkey **pkp);

extern err_t add_public_key(const struct id *id
                            , enum dns_auth_level dns_auth_level
                            , enum pubkey_alg alg
                            , const chunk_t *key
                            , struct pubkey_list **head);

extern bool same_RSA_public_key(const struct RSA_public_key *a
    , const struct RSA_public_key *b);

extern void install_public_key(osw_public_key *pk, struct pubkey_list **head);

extern void free_public_key(struct pubkey *pk);

extern void osw_load_preshared_secrets(struct secret **psecrets
				       , int verbose
				       , const char *secrets_file
				       , prompt_pass_t *pass, const char *root_dir);
extern void osw_free_preshared_secrets(struct secret **psecrets);

extern bool osw_has_private_rawkey(struct secret *secrets, struct pubkey *pk);

extern void RSA_show_key_fields(struct private_key_stuff *pks);

extern struct secret *osw_find_secret_by_id(struct secret *secrets
					    , enum PrivateKeyKind kind
					    , const struct id *my_id
                                            , osw_public_key *key1
                                            , osw_public_key *key2
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

extern const struct private_key_stuff *
osw_get_x509_private_stuff(struct secret *secrets, x509cert_t *cert);


#endif /* _SECRETS_H */
/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
