/*
 * interfaces to the secrets.c library functions in libopenswan.
 * for now, just stupid wrappers!
 *
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2003-2008  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
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
 * Copyright (C) 2004-2005 Intel Corporation.
 *
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>

#include <glob.h>
#ifndef GLOB_ABORTED
# define GLOB_ABORTED    GLOB_ABEND	/* fix for old versions */
#endif

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "pluto/connections.h"	/* needs id.h */
#include "pluto/state.h"
#include "lex.h"
#include "keys.h"
#include "secrets.h"
#include "adns.h"	/* needs <resolv.h> */
#include "dnskey.h"	/* needs keys.h and adns.h */
#include "log.h"
#include "whack.h"	/* for RC_LOG_SERIOUS */
#include "timer.h"
#include "mpzfuncs.h"

#include "fetch.h"
#include "x509more.h"

#include "oswcrypto.h"

/* Maximum length of filename and passphrase buffer */
#define BUF_LEN		256

#ifdef NAT_TRAVERSAL
#define PB_STREAM_UNDEFINED
#include "nat_traversal.h"
#endif

#ifdef HAVE_LIBNSS
 /* nspr */
# include <prerror.h>
# include <prinit.h>
# include <prmem.h>
 /* nss */
# include <key.h>
# include <keyt.h>
# include <nss.h>
# include <pk11pub.h>
# include <seccomon.h>
# include <secerr.h>
# include <secport.h>
# include <time.h>
# include "oswconf.h"
#endif

const char *pluto_shared_secrets_file = SHARED_SECRETS_FILE;
struct secret *pluto_secrets = NULL;

void load_preshared_secrets(int whackfd)
{
    prompt_pass_t pass;

    pass.prompt = whack_log;
    pass.fd = whackfd;
    osw_load_preshared_secrets(&pluto_secrets
#ifdef SINGLE_CONF_DIR
			       , FALSE /* to much log noise in a shared directory mode */
#else
			       , TRUE
#endif
			       , pluto_shared_secrets_file
			       , &pass, NULL);
}

void free_preshared_secrets(void)
{
    osw_free_preshared_secrets(&pluto_secrets);
}

void show_secrets_status(void)
{
    whack_log(RC_COMMENT, "using secrets file: %s", pluto_shared_secrets_file);
}

static int print_secrets(struct secret *secret
			 , struct private_key_stuff *pks UNUSED
			 , void *uservoid UNUSED)
{
    char idb1[IDTOA_BUF];
    char idb2[IDTOA_BUF];
    const char *kind = "?";
    const char *more = "";
    struct id_list *ids;

    switch(pks->kind) {
    case PPK_PSK: kind="PSK"; break;
    case PPK_RSA: kind="RSA"; break;
    case PPK_PIN: kind="PIN"; break;
    case PPK_XAUTH: kind="XAUTH"; break;
    default:
	return 1;
    }

    ids = osw_get_idlist(secret);
    strcpy(idb1,"%any");
    strcpy(idb2,"");

    if(ids!=NULL) idtoa(&ids->id, idb1, sizeof(idb1));
    if(ids->next!=NULL) {
	idtoa(&ids->next->id, idb2, sizeof(idb2));
	if(ids->next->next) more="more";
    }

    whack_log(RC_COMMENT, "    %d: %s %s %s%s", osw_get_secretlineno(secret),
	      kind,
	      idb1, idb2, more);

    /* continue loop until end */
    return 1;
}


void list_psks(void)
{
    whack_log(RC_COMMENT, "List of Pre-shared secrets (from %s)", pluto_shared_secrets_file);
    osw_foreach_secret(pluto_secrets, print_secrets, NULL);
}

/* Check signature against all RSA public keys we can find.
 * If we need keys from DNS KEY records, and they haven't been fetched,
 * return STF_SUSPEND to ask for asynch DNS lookup.
 *
 * Note: parameter keys_from_dns contains results of DNS lookup for key
 * or is NULL indicating lookup not yet tried.
 *
 * take_a_crack is a helper function.  Mostly forensic.
 * If only we had coroutines.
 */
struct tac_state {
    /* RSA_check_signature's args that take_a_crack needs */
    struct state *st;
    const u_char *hash_val;
    size_t hash_len;
    const pb_stream *sig_pbs;

    err_t (*try_RSA_signature)(const u_char hash_val[MAX_DIGEST_LEN]
			       , size_t hash_len
			       , const pb_stream *sig_pbs
			       , struct pubkey *kr
			       , struct state *st);

    /* state carried between calls */
    err_t best_ugh;	/* most successful failure */
    int tried_cnt;	/* number of keys tried */
    char tried[50];	/* keyids of tried public keys */
    char *tn;	/* roof of tried[] */
};

static bool
take_a_crack(struct tac_state *s
		, struct pubkey *kr
		, const char *story USED_BY_DEBUG)
{
    err_t ugh = (s->try_RSA_signature)(s->hash_val, s->hash_len, s->sig_pbs
				       , kr, s->st);
    const struct RSA_public_key *k = &kr->u.rsa;

    s->tried_cnt++;
    if (ugh == NULL)
    {
        /* record which key was successful! */
        memcpy(s->st->st_their_keyid, kr->u.rsa.keyid, KEYID_BUF);
	DBG(DBG_CRYPT | DBG_CONTROL
	    , DBG_log("an RSA Sig check passed with *%s [%s]"
		, k->keyid, story));
	return TRUE;
    }
    else
    {
	DBG(DBG_CRYPT
	    , DBG_log("an RSA Sig check failure %s with *%s [%s]"
		, ugh + 1, k->keyid, story));
	if (s->best_ugh == NULL || s->best_ugh[0] < ugh[0])
	    s->best_ugh = ugh;
	if (ugh[0] > '0'
	&& s->tn - s->tried + KEYID_BUF + 2 < (ptrdiff_t)sizeof(s->tried))
	{
	    strcpy(s->tn, " *");
	    strcpy(s->tn + 2, k->keyid);
	    s->tn += strlen(s->tn);
	}
	return FALSE;
    }
}

stf_status
RSA_check_signature_gen(struct state *st
			, const u_char hash_val[MAX_DIGEST_LEN]
			, size_t hash_len
			, const pb_stream *sig_pbs
#ifdef USE_KEYRR
			, const struct pubkey_list *keys_from_dns
#endif /* USE_KEYRR */
			, const struct gw_info *gateways_from_dns
			, err_t (*try_RSA_signature)(const u_char hash_val[MAX_DIGEST_LEN]
						     , size_t hash_len
						     , const pb_stream *sig_pbs
						     , struct pubkey *kr
						     , struct state *st))
{
    const struct connection *c = st->st_connection;
    struct tac_state s;
    err_t dns_ugh = NULL;

    s.st = st;
    s.hash_val = hash_val;
    s.hash_len = hash_len;
    s.sig_pbs = sig_pbs;
    s.try_RSA_signature = try_RSA_signature;

    s.best_ugh = NULL;
    s.tried_cnt = 0;
    s.tn = s.tried;

    /* try all gateway records hung off c */
    if ((c->policy & POLICY_OPPO))
    {
	struct gw_info *gw;

	for (gw = c->gw_info; gw != NULL; gw = gw->next)
	{
	    /* only consider entries that have a key and are for our peer */
	    if (gw->gw_key_present
	    && same_id(&gw->gw_id, &c->spd.that.id)
	    && take_a_crack(&s, gw->key, "key saved from DNS TXT"))
		return STF_OK;
	}
    }

    /* try all appropriate Public keys */
    {
	struct pubkey_list *p, **pp;
	int pathlen;

	pp = &pluto_pubkeys;

	{

	  DBG(DBG_CONTROL,
	      char buf[IDTOA_BUF];
	      dntoa_or_null(buf, IDTOA_BUF, c->spd.that.ca, "%any");
	      DBG_log("required CA is '%s'", buf));
	}

	for (p = pluto_pubkeys; p != NULL; p = *pp)
	{
	    struct pubkey *key = p->key;

            if (key->alg == PUBKEY_ALG_RSA
                && same_id(&st->ikev2.st_peer_id, &key->id)
                && (key->dns_auth_level > DAL_UNSIGNED || trusted_ca_by_name(key->issuer, c->spd.that.ca, &pathlen)))
	    {
		time_t tnow;

		DBG(DBG_CONTROL,
		    char buf[IDTOA_BUF];
		    dntoa_or_null(buf, IDTOA_BUF, key->issuer, "%any");
		    DBG_log("key issuer CA is '%s'", buf));

		/* check if found public key has expired */
		time(&tnow);
		if (key->until_time != UNDEFINED_TIME && key->until_time < tnow)
		{
		    loglog(RC_LOG_SERIOUS,
			"cached RSA public key has expired and has been deleted");
		    *pp = free_public_keyentry(p);
		    continue; /* continue with next public key */
		}

		if (take_a_crack(&s, key, "preloaded key"))
		return STF_OK;
	    }
	    pp = &p->next;
	}
   }

    /* if no key was found (evidenced by best_ugh == NULL)
     * and that side of connection is key_from_DNS_on_demand
     * then go search DNS for keys for peer.
     */
    if (s.best_ugh == NULL && c->spd.that.key_from_DNS_on_demand)
    {
	if (gateways_from_dns != NULL)
	{
	    /* TXT keys */
	    const struct gw_info *gwp;

	    for (gwp = gateways_from_dns; gwp != NULL; gwp = gwp->next)
		if (gwp->gw_key_present
		&& take_a_crack(&s, gwp->key, "key from DNS TXT"))
		    return STF_OK;
	}
#ifdef USE_KEYRR
	else if (keys_from_dns != NULL)
	{
	    /* KEY keys */
	    const struct pubkey_list *kr;

	    for (kr = keys_from_dns; kr != NULL; kr = kr->next)
		if (kr->key->alg == PUBKEY_ALG_RSA
		&& take_a_crack(&s, kr->key, "key from DNS KEY"))
		    return STF_OK;
	}
#endif /* USE_KEYRR */
	else
	{
	    /* nothing yet: ask for asynch DNS lookup */
	    return STF_SUSPEND;
	}
    }

    /* no acceptable key was found: diagnose */
    {
	char id_buf[IDTOA_BUF];	/* arbitrary limit on length of ID reported */

	(void) idtoa(&st->st_connection->spd.that.id, id_buf, sizeof(id_buf));

	if (s.best_ugh == NULL)
	{
	    if (dns_ugh == NULL)
		loglog(RC_LOG_SERIOUS, "no RSA public key known for '%s'"
		    , id_buf);
	    else
		loglog(RC_LOG_SERIOUS, "no RSA public key known for '%s'"
		    "; DNS search for KEY failed (%s)"
		    , id_buf, dns_ugh);

	    /* ??? is this the best code there is? */
	    return STF_FAIL + INVALID_KEY_INFORMATION;
	}

	if (s.best_ugh[0] == '9')
	{
	    loglog(RC_LOG_SERIOUS, "%s", s.best_ugh + 1);
	    /* XXX Could send notification back */
	    return STF_FAIL + INVALID_HASH_INFORMATION;
	}
	else
	{
	    if (s.tried_cnt == 1)
	    {
		loglog(RC_LOG_SERIOUS
		    , "Signature check (on %s) failed (wrong key?); tried%s"
		    , id_buf, s.tried);
		DBG(DBG_CONTROL,
		    DBG_log("public key for %s failed:"
			" decrypted SIG payload into a malformed ECB (%s)"
			, id_buf, s.best_ugh + 1));
	    }
	    else
	    {
		loglog(RC_LOG_SERIOUS
		    , "Signature check (on %s) failed:"
		      " tried%s keys but none worked."
		    , id_buf, s.tried);
		DBG(DBG_CONTROL,
		    DBG_log("all %d public keys for %s failed:"
			" best decrypted SIG payload into a malformed ECB (%s)"
			, s.tried_cnt, id_buf, s.best_ugh + 1));
	    }
	    return STF_FAIL + INVALID_KEY_INFORMATION;
	}
    }
}

/* find the struct secret associated with the combination of
 * me and the peer.  We match the Id (if none, the IP address).
 * Failure is indicated by a NULL.
 *
 * my_id = &c->spd.this.id
 * his_id = &c->spd.that.id
 */
static struct secret *
osw_get_secret(const struct connection *c
	       , const struct id *my_id
	       , const struct id *his_id
	       , enum PrivateKeyKind kind, bool asym)
{
    char idme[IDTOA_BUF]
	, idhim[IDTOA_BUF], idhim2[IDTOA_BUF];
    struct secret *best = NULL;
    struct id rw_id;

    idtoa(my_id,  idme,  IDTOA_BUF);
    idtoa(his_id, idhim, IDTOA_BUF);
    strcpy(idhim2, idhim);

    DBG(DBG_CONTROL,
	DBG_log("started looking for secret for %s->%s of kind %s"
		, idme, idhim
		, enum_name(&ppk_names, kind)));

    /* is there a certificate assigned to this connection? */
    if (kind == PPK_RSA
	&& c->spd.this.sendcert != cert_forcedtype
	&& (c->spd.this.cert.type == CERT_X509_SIGNATURE ||
	    c->spd.this.cert.type == CERT_PKCS7_WRAPPED_X509 ||
	    c->spd.this.cert.type == CERT_PGP))
    {
	osw_public_key *my_public_key = allocate_RSA_public_key(c->spd.this.cert);
	passert(my_public_key != NULL);

	best = osw_find_secret_by_public_key(pluto_secrets
					     , my_public_key, kind);

	free_public_key(my_public_key);
	return best;
    }

#if defined(AGGRESSIVE)
    if (his_id_was_instantiated(c)
        && (!(c->policy & POLICY_AGGRESSIVE))
        && isanyaddr(&c->spd.that.host_addr)) {
	DBG(DBG_CONTROL,
	    DBG_log("instantiating him to 0.0.0.0"));

	/* roadwarrior: replace him with 0.0.0.0 */
	rw_id.kind = addrtypeof(&c->spd.that.host_addr) == AF_INET ?
	    ID_IPV4_ADDR : ID_IPV6_ADDR;
	happy(anyaddr(addrtypeof(&c->spd.that.host_addr), &rw_id.ip_addr));
	his_id = &rw_id;
	idtoa(his_id, idhim2, IDTOA_BUF);
    }
#endif
#ifdef NAT_TRAVERSAL
    else if ( (c->policy & POLICY_PSK)
	      && (kind == PPK_PSK)
	      && (((c->kind == CK_TEMPLATE)
		   && (c->spd.that.id.kind == ID_NONE))
                  || ((c->kind == CK_INSTANCE)
                      && (id_is_ipaddr(&c->spd.that.id))
                      /* Check if we are a road warrior instantiation, not a vnet: instantiation */
                      && (isanyaddr(&c->spd.that.host_addr)))
                  )
              ) {
        DBG(DBG_CONTROL,
            DBG_log("replace him to 0.0.0.0"));

        /* roadwarrior: replace him with 0.0.0.0 */
        rw_id.kind = ID_IPV4_ADDR;
        happy(anyaddr(addrtypeof(&c->spd.that.host_addr), &rw_id.ip_addr));
        his_id = &rw_id;
        idtoa(his_id, idhim2, IDTOA_BUF);
    }
#endif

    DBG(DBG_CONTROL,
	DBG_log("actually looking for secret for %s->%s of kind %s"
		, idme, idhim2
		, enum_name(&ppk_names, kind)));

    best = osw_find_secret_by_id(pluto_secrets
				 , kind
				 , my_id
                                 , c->spd.this.key1
                                 , c->spd.this.key2
                                 , his_id, asym);

    return best;
}

/*
 * find the struct secret associated with an XAUTH username.
 */
struct secret *
osw_get_xauthsecret(const struct connection *c UNUSED
		    , char *xauthname)
{
    struct secret *best = NULL;
    struct id xa_id;

    DBG(DBG_CONTROL,
	DBG_log("started looking for xauth secret for %s"
		, xauthname));

    memset(&xa_id, 0, sizeof(xa_id));
    xa_id.kind = ID_FQDN;
    xa_id.name.ptr = (unsigned char *)xauthname;
    xa_id.name.len = strlen(xauthname);

    best = osw_find_secret_by_id(pluto_secrets
				 , PPK_XAUTH
				 , &xa_id, NULL, NULL, NULL, TRUE);

    return best;
}

/* check the existence of an RSA private key matching an RSA public
 */
bool
has_private_rawkey(struct pubkey *pk)
{
    return osw_has_private_rawkey(pluto_secrets, pk);
}

/* find the appropriate preshared key (see get_secret).
 * Failure is indicated by a NULL pointer.
 * Note: the result is not to be freed by the caller.
 */
const chunk_t *
get_preshared_secret(const struct connection *c)
{
    struct secret *s = osw_get_secret(c
					    , &c->spd.this.id
					    , &c->spd.that.id
					    , PPK_PSK, FALSE);
    const struct private_key_stuff *pks = NULL;

    if(s != NULL) pks = osw_get_pks(s);

#ifdef DEBUG
    DBG(DBG_PRIVATE,
	if (s == NULL)
	    DBG_log("no Preshared Key Found");
	else
	    DBG_dump_chunk("Preshared Key", pks->u.preshared_secret);
	);
#endif
    return s == NULL? NULL : &pks->u.preshared_secret;
}


/* check the existence of an RSA private key matching an RSA public
 * key contained in an X.509 or OpenPGP certificate
 */
bool
has_private_key(cert_t cert)
{
    bool has_key = FALSE;
    struct pubkey *pubkey;

    pubkey = allocate_RSA_public_key(cert);
    if(pubkey == NULL) return FALSE;

    has_key = osw_has_private_rawkey(pluto_secrets, pubkey);

    free_public_key(pubkey);
    return has_key;
}

/* find the appropriate RSA private key (see get_secret).
 * Failure is indicated by a NULL pointer.
 */
const struct private_key_stuff *
get_RSA_private_key(const struct connection *c)
{
    struct secret *s = osw_get_secret(c
                                      , &c->spd.this.id, &c->spd.that.id
                                      , PPK_RSA, TRUE);
    const struct private_key_stuff *pks = NULL;

    if(s != NULL) pks = osw_get_pks(s);

#ifdef DEBUG
    DBG(DBG_PRIVATE,
	if (s == NULL)
	    DBG_log("no RSA key Found");
	else
	    DBG_log("rsa key %s found", pks->pub->u.rsa.keyid);
	);
#endif
    return s == NULL? NULL : pks;
}

/*
 * get the matching RSA private key belonging to a given X.509 certificate
 */
const struct RSA_private_key*
get_x509_private_key(x509cert_t *cert)
{
    return osw_get_x509_private_key(pluto_secrets, cert);
}

/* public key machinery
 * Note: caller must set dns_auth_level.
 */

struct pubkey *
public_key_from_rsa(const struct RSA_public_key *k)
{
    struct pubkey *p = alloc_thing(struct pubkey, "pubkey");

    p->id = empty_id;	/* don't know, doesn't matter */
    p->issuer = empty_chunk;
    p->alg = PUBKEY_ALG_RSA;

    memcpy(p->u.rsa.keyid, k->keyid, sizeof(p->u.rsa.keyid));
    p->u.rsa.k = k->k;
    mpz_init_set(&p->u.rsa.e, &k->e);
    mpz_init_set(&p->u.rsa.n, &k->n);

    /* note that we return a 1 reference count upon creation:
     * invariant: recount > 0.
     */
    p->refcnt = 1;
    p->installed_time = now();
    return p;
}

/* root of chained public key list */

struct pubkey_list *pluto_pubkeys = NULL;	/* keys from ipsec.conf */

void
free_remembered_public_keys(void)
{
    free_public_keys(&pluto_pubkeys);
}

/* find a public key */
struct pubkey *osw_get_public_key_by_end(struct end *him)
{
    struct pubkey_list *p, **pp;
    int pathlen;

    pp = &pluto_pubkeys;

    for (p = pluto_pubkeys; p != NULL; p = *pp)
	{
	    struct pubkey *key = p->key;

	    if (key->alg == PUBKEY_ALG_RSA
		&& same_id(&him->id, &key->id)
                && trusted_ca_by_name(key->issuer, him->ca, &pathlen)) {
                return key;
            }
	    pp = &p->next;
        }
    return NULL;
}

/* transfer public keys from *keys list to front of pubkeys list */
void
transfer_to_public_keys(struct gw_info *gateways_from_dns
#ifdef USE_KEYRR
, struct pubkey_list **keys
#endif /* USE_KEYRR */
)
{
    {
	struct gw_info *gwp;

	for (gwp = gateways_from_dns; gwp != NULL; gwp = gwp->next)
	{
	    struct pubkey_list *pl = alloc_thing(struct pubkey_list, "from TXT");

	    pl->key = gwp->key;	/* note: this is a transfer */
	    gwp->key = NULL;	/* really, it is! */
	    pl->next = pluto_pubkeys;
	    pluto_pubkeys = pl;
	}
    }

#ifdef USE_KEYRR
    {
	struct pubkey_list **pp = keys;

	while (*pp != NULL)
	    pp = &(*pp)->next;
	*pp = pluto_pubkeys;
	pluto_pubkeys = *keys;
	*keys = NULL;
    }
#endif /* USE_KEYRR */
}

err_t
add_public_key(const struct id *id
	       , enum dns_auth_level dns_auth_level
	       , enum pubkey_alg alg
	       , const chunk_t *key
	       , struct pubkey_list **head)
{
    struct pubkey *pk = alloc_thing(struct pubkey, "pubkey");

    /* first: algorithm-specific decoding of key chunk */
    switch (alg)
    {
    case PUBKEY_ALG_RSA:
	{
	    err_t ugh = unpack_RSA_public_key(&pk->u.rsa, key);

	    if (ugh != NULL)
	    {
		pfree(pk);
		return ugh;
	    }
	}
	break;
    default:
	bad_case(alg);
    }

    pk->id = *id;
    pk->dns_auth_level = dns_auth_level;
    pk->alg = alg;
    pk->until_time = UNDEFINED_TIME;
    pk->issuer = empty_chunk;

    install_public_key(pk, head);
    return NULL;
}

/*
 *  find a public key by ckaid
 */
struct pubkey *find_public_keys(unsigned char ckaid[CKAID_BUFSIZE])
{
    struct pubkey_list *p = pluto_pubkeys;

    for(; p != NULL; p = p->next)
    {
	struct pubkey *key = p->key;

        if(memcmp(ckaid, key->key_ckaid, CKAID_BUFSIZE) == 0) {
            return key;
        }
    }
    return NULL;
}

struct pubkey *find_key_by_string(const char *key_hex)
{
    struct pubkey *key1 = NULL;
    unsigned char ckaid[CKAID_BUFSIZE];
    err_t e = ckaidhex2ckaid(key_hex, ckaid);

    if(e) {
        openswan_log("failed to parse ckaid: %s", e);
    } else if((key1 = find_public_keys(ckaid)) == NULL) {
        openswan_log("can not find public key: %s", key_hex);
    } else {
        reference_key(key1);
    }
    return key1;
}


/*
 *  list all public keys in the chained list
 */
void list_public_keys(bool utc, bool check_pub_keys)
{
    struct pubkey_list *p = pluto_pubkeys;

    if(!check_pub_keys)
    {
	whack_log(RC_COMMENT, " ");
	whack_log(RC_COMMENT, "List of Public Keys:");
	whack_log(RC_COMMENT, " ");
    }

    while (p != NULL)
    {
	struct pubkey *key = p->key;

	if (key->alg == PUBKEY_ALG_RSA)
	{
	    char id_buf[IDTOA_BUF];
	    char expires_buf[TIMETOA_BUF];
	    char installed_buf[TIMETOA_BUF];
	    const char *check_expiry_msg = NULL;

	    check_expiry_msg = check_expiry(key->until_time
					    , PUBKEY_WARNING_INTERVAL
					    , TRUE);

	    if(!check_pub_keys || (check_pub_keys && strncmp(check_expiry_msg, "ok", 2)))
	    {
                char ckaid_print_buf[CKAID_BUFSIZE*2 + (CKAID_BUFSIZE/2)+2];
		idtoa(&key->id, id_buf, IDTOA_BUF);
                datatot(key->key_ckaid, sizeof(key->key_ckaid), 'G',
                        ckaid_print_buf, sizeof(ckaid_print_buf));

		whack_log(RC_COMMENT, "%s, %4d RSA %s key %s/%s (%s private key), until %s %s"
			  , timetoa(&key->installed_time, utc,
				    installed_buf, sizeof(installed_buf))
			  , 8*key->u.rsa.k
                          , enum_name(&dns_auth_level_names, key->dns_auth_level)
			  , key->u.rsa.keyid
                          , ckaid_print_buf
			  , (has_private_rawkey(key) ? "has" : "no")
			  , timetoa(&key->until_time, utc,
				    expires_buf, sizeof(expires_buf))
			  , check_expiry(key->until_time
					 , PUBKEY_WARNING_INTERVAL
					 , TRUE));

		whack_log(RC_COMMENT,"       %s '%s'",
			  enum_show(&ident_names, key->id.kind), id_buf);

		if (key->issuer.len > 0)
		{
		    dntoa(id_buf, IDTOA_BUF, key->issuer);
		    whack_log(RC_COMMENT,"       Issuer '%s'", id_buf);
		}
	    }
	}
	p = p->next;
    }
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
