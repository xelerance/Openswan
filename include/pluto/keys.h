/*
 * mechanisms for managing keys (public, private, and preshared secrets)
 * inside of pluto. Common code is in ../../include/secrets.h and libopenswan.
 *
 * Copyright (C) 1998-2005  D. Hugh Redelmeier.
 * Copyright (C) 2003-2007  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
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
#ifndef _KEYS_H
#define _KEYS_H

#include "secrets.h"
#include "x509.h"
#include "certs.h"

struct connection;

extern time_t get_time_maybe_fake(time_t *when);
extern void set_fake_x509_time(time_t now);

extern const u_char der_digestinfo[];
extern const int der_digestinfo_len;

/* encrypt(sign) a hash using a private key */
extern void sign_hash(const struct private_key_stuff *pks
                      , const u_char *hash_val
		      , size_t hash_len, u_char *sig_val, size_t sig_len);

/* decrypt(verify) a signature to recover the contained hash */
extern err_t verify_signed_hash(const struct RSA_public_key *k
                                , u_char *s, unsigned int s_max_octets /* working space: RSA_MAX_OCTETS */
                                , u_char **psig                     /* result parameter; points to hash */
                                , size_t hash_len
                                , const u_char *sig_val, size_t sig_len);

#ifdef HAVE_LIBNSS
extern int sign_hash_nss(const struct private_key_stuff *pks
                         , const u_char *hash_val
                         , size_t hash_len
                         , u_char *sig_val, size_t sig_len);

extern err_t RSA_signature_verify_nss(const struct RSA_public_key *k
					, const u_char *hash_val, size_t hash_len
					,const u_char *sig_val, size_t sig_len);
#endif

extern const struct private_key_stuff *get_RSA_private_key(const struct connection *c);

extern const struct RSA_private_key *get_x509_private_key(/*const*/ x509cert_t *cert);

extern bool has_private_key(cert_t cert);
extern bool has_private_rawkey(struct pubkey *pk);
extern void add_pgp_public_key(pgpcert_t *cert, time_t until
    , enum dns_auth_level dns_auth_level);
extern void remove_x509_public_key(/*const*/ x509cert_t *cert);
extern void list_public_keys(bool utc, bool check_pub_keys);
extern void list_psks(void);

/* look up public keys */
extern struct pubkey *find_public_keys(unsigned char ckaid[CKAID_BUFSIZE]);
extern struct pubkey *find_key_by_string(const char *key_hex);



struct gw_info;	/* forward declaration of tag (defined in dnskey.h) */
extern void transfer_to_public_keys(struct gw_info *gateways_from_dns
#ifdef USE_KEYRR
    , struct pubkey_list **keys
#endif /* USE_KEYRR */
    );

extern const chunk_t *get_preshared_secret(const struct connection *c);

extern const char *pluto_shared_secrets_file;
extern void load_preshared_secrets(int whackfd);
extern void free_preshared_secrets(void);

extern struct secret *osw_find_secret_by_public_key(struct secret *secrets
						    , struct pubkey *my_public_key
						    , int kind);

extern struct secret *osw_get_xauthsecret(const struct connection *c UNUSED
					  , char *xauthname);

#define osw_asymmetric_key(cert) (cert.type == CERT_PKCS7_WRAPPED_X509 || \
                                  cert.type == CERT_PGP ||              \
                                  cert.type == CERT_DNS_SIGNED_KEY ||  \
                                  cert.type == CERT_X509_SIGNATURE ||   \
                                  cert.type == CERT_RAW_RSA)

/* check if a private key exists, by certificate-like blob */
extern bool osw_has_private_key(struct secret *list_of_secrets, cert_t cert);

extern struct pubkey *osw_get_public_key_by_end(struct end *him);


/* keys from ipsec.conf */
extern struct pubkey_list *pluto_pubkeys;

struct packet_byte_stream;
extern stf_status
check_signature_gen(struct connection *c, struct state *st
			, const u_char hash_val[MAX_DIGEST_LEN]
			, size_t hash_len
			, const struct packet_byte_stream *sig_pbs
#ifdef USE_KEYRR
			, const struct pubkey_list *keys_from_dns
#endif /* USE_KEYRR */
			, const struct gw_info *gateways_from_dns
			, err_t (*try_RSA_signature)(const u_char hash_val[MAX_DIGEST_LEN]
						     , size_t hash_len
						     , const struct packet_byte_stream *sig_pbs
						     , struct pubkey *kr
						     , struct state *st));

#endif /* _KEYS_H */
