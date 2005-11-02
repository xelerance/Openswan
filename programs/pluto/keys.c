/* mechanisms for preshared keys (public, private, and preshared secrets)
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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
 * RCSID $Id: keys.c,v 1.87 2003/12/06 16:34:32 mcr Exp $
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <arpa/nameser.h>	/* missing from <resolv.h> on old systems */
#include <sys/queue.h>

#include <glob.h>
#ifndef GLOB_ABORTED
# define GLOB_ABORTED    GLOB_ABEND	/* fix for old versions */
#endif

#include <freeswan.h>
#include <freeswan/ipsec_policy.h>

#include "constants.h"
#include "defs.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "smartcard.h"
#include "connections.h"	/* needs id.h */
#include "state.h"
#include "lex.h"
#include "keys.h"
#include "adns.h"	/* needs <resolv.h> */
#include "dnskey.h"	/* needs keys.h and adns.h */
#include "log.h"
#include "whack.h"	/* for RC_LOG_SERIOUS */
#include "timer.h"

#include "pkcs.h"
#include "x509more.h"

/* Maximum length of filename and passphrase buffer */
#define BUF_LEN		256

struct fld {
    const char *name;
    size_t offset;
};

static const struct fld RSA_private_field[] =
{
    { "Modulus", offsetof(struct RSA_private_key, pub.n) },
    { "PublicExponent", offsetof(struct RSA_private_key, pub.e) },

    { "PrivateExponent", offsetof(struct RSA_private_key, d) },
    { "Prime1", offsetof(struct RSA_private_key, p) },
    { "Prime2", offsetof(struct RSA_private_key, q) },
    { "Exponent1", offsetof(struct RSA_private_key, dP) },
    { "Exponent2", offsetof(struct RSA_private_key, dQ) },
    { "Coefficient", offsetof(struct RSA_private_key, qInv) },
};

#ifdef DEBUG
static void
RSA_show_key_fields(struct RSA_private_key *k, int fieldcnt)
{
    const struct fld *p;

    DBG_log(" keyid: *%s", k->pub.keyid);

    for (p = RSA_private_field; p < &RSA_private_field[fieldcnt]; p++)
    {
	MP_INT *n = (MP_INT *) ((char *)k + p->offset);
	size_t sz = mpz_sizeinbase(n, 16);
	char buf[RSA_MAX_OCTETS * 2 + 2];	/* ought to be big enough */

	passert(sz <= sizeof(buf));
	mpz_get_str(buf, 16, n);

	DBG_log(" %s: %s", p->name, buf);
    }
}

/* debugging info that compromises security! */
static void
RSA_show_private_key(struct RSA_private_key *k)
{
    RSA_show_key_fields(k, elemsof(RSA_private_field));
}

static void
RSA_show_public_key(struct RSA_public_key *k)
{
    /* Kludge: pretend that it is a private key, but only display the
     * first two fields (which are the public key).
     */
    passert(offsetof(struct RSA_private_key, pub) == 0);
    RSA_show_key_fields((struct RSA_private_key *)k, 2);
}
#endif

static const char *
RSA_private_key_sanity(struct RSA_private_key *k)
{
    /* note that the *last* error found is reported */
    err_t ugh = NULL;
    mpz_t t, u, q1;

#ifdef DEBUG	/* debugging info that compromises security */
    DBG(DBG_PRIVATE, RSA_show_private_key(k));
#endif

    /* PKCS#1 1.5 section 6 requires modulus to have at least 12 octets.
     * We actually require more (for security).
     */
    if (k->pub.k < RSA_MIN_OCTETS)
	return RSA_MIN_OCTETS_UGH;

    /* we picked a max modulus size to simplify buffer allocation */
    if (k->pub.k > RSA_MAX_OCTETS)
	return RSA_MAX_OCTETS_UGH;

    mpz_init(t);
    mpz_init(u);
    mpz_init(q1);

    /* check that n == p * q */
    mpz_mul(u, &k->p, &k->q);
    if (mpz_cmp(u, &k->pub.n) != 0)
	ugh = "n != p * q";

    /* check that e divides neither p-1 nor q-1 */
    mpz_sub_ui(t, &k->p, 1);
    mpz_mod(t, t, &k->pub.e);
    if (mpz_cmp_ui(t, 0) == 0)
	ugh = "e divides p-1";

    mpz_sub_ui(t, &k->q, 1);
    mpz_mod(t, t, &k->pub.e);
    if (mpz_cmp_ui(t, 0) == 0)
	ugh = "e divides q-1";

    /* check that d is e^-1 (mod lcm(p-1, q-1)) */
    /* see PKCS#1v2, aka RFC 2437, for the "lcm" */
    mpz_sub_ui(q1, &k->q, 1);
    mpz_sub_ui(u, &k->p, 1);
    mpz_gcd(t, u, q1);		/* t := gcd(p-1, q-1) */
    mpz_mul(u, u, q1);		/* u := (p-1) * (q-1) */
    mpz_divexact(u, u, t);	/* u := lcm(p-1, q-1) */

    mpz_mul(t, &k->d, &k->pub.e);
    mpz_mod(t, t, u);
    if (mpz_cmp_ui(t, 1) != 0)
	ugh = "(d * e) mod (lcm(p-1, q-1)) != 1";

    /* check that dP is d mod (p-1) */
    mpz_sub_ui(u, &k->p, 1);
    mpz_mod(t, &k->d, u);
    if (mpz_cmp(t, &k->dP) != 0)
	ugh = "dP is not congruent to d mod (p-1)";

    /* check that dQ is d mod (q-1) */
    mpz_sub_ui(u, &k->q, 1);
    mpz_mod(t, &k->d, u);
    if (mpz_cmp(t, &k->dQ) != 0)
	ugh = "dQ is not congruent to d mod (q-1)";

    /* check that qInv is (q^-1) mod p */
    mpz_mul(t, &k->qInv, &k->q);
    mpz_mod(t, t, &k->p);
    if (mpz_cmp_ui(t, 1) != 0)
	ugh = "qInv is not conguent ot (q^-1) mod p";

    mpz_clear(t);
    mpz_clear(u);
    mpz_clear(q1);
    return ugh;
}

const char *shared_secrets_file = SHARED_SECRETS_FILE;

struct id_list {
    struct id id;
    struct id_list *next;
};

struct secret {
    struct id_list *ids;
    enum PrivateKeyKind kind;
    union {
	chunk_t preshared_secret;
	struct RSA_private_key RSA_private_key;
	smartcard_t *smartcard;
    } u;
    struct secret *next;
};

/*
 * forms the keyid from the public exponent e and modulus n
 */
void
form_keyid(chunk_t e, chunk_t n, char* keyid, unsigned *keysize)
{
    /* eliminate leading zero byte in modulus from ASN.1 coding */
    if (*n.ptr == 0x00)
    {
	n.ptr++;  n.len--;
    }

    /* form the FreeS/WAN keyid */
    keyid[0] = '\0';	/* in case of splitkeytoid failure */
    splitkeytoid(e.ptr, e.len, n.ptr, n.len, keyid, KEYID_BUF);

    /* return the RSA modulus size in octets */
    *keysize = n.len;
}


struct pubkey*
allocate_RSA_public_key(const cert_t cert)
{
    struct pubkey *pk = alloc_thing(struct pubkey, "pubkey");
    chunk_t e, n;

    switch (cert.type)
    {
    case CERT_PGP:
	e = cert.u.pgp->publicExponent;
	n = cert.u.pgp->modulus;
	break;
    case CERT_X509_SIGNATURE:
	e = cert.u.x509->publicExponent;
	n = cert.u.x509->modulus;
	break;
    default:
	plog("RSA public key allocation error");
    }

    n_to_mpz(&pk->u.rsa.e, e.ptr, e.len);
    n_to_mpz(&pk->u.rsa.n, n.ptr, n.len);

    form_keyid(e, n, pk->u.rsa.keyid, &pk->u.rsa.k);

#ifdef DEBUG
    DBG(DBG_PRIVATE, RSA_show_public_key(&pk->u.rsa));
#endif

    pk->alg = PUBKEY_ALG_RSA;
    pk->id  = empty_id;
    pk->issuer = empty_chunk;

    return pk;
}

/*
 * free a public key struct
 */
void
free_public_key(struct pubkey *pk)
{
    free_id_content(&pk->id);
    freeanychunk(pk->issuer);

    /* algorithm-specific freeing */
    switch (pk->alg)
    {
    case PUBKEY_ALG_RSA:
	free_RSA_public_content(&pk->u.rsa);
	break;
    default:
	bad_case(pk->alg);
    }
    pfree(pk);
}

struct secret *secrets = NULL;

/* find the struct secret associated with the combination of
 * me and the peer.  We match the Id (if none, the IP address).
 * Failure is indicated by a NULL.
 */
static const struct secret *
get_secret(const struct connection *c, enum PrivateKeyKind kind, bool asym)
{
    enum {	/* bits */
	match_default = 01,
	match_him = 02,
	match_me = 04
    };
    unsigned char idstr1[IDTOA_BUF], idme[IDTOA_BUF], idhim[IDTOA_BUF];
    unsigned int best_match = 0;
    struct secret *best = NULL;
    struct secret *s;
    const struct id *my_id = &c->spd.this.id
	, *his_id = &c->spd.that.id;
    struct id rw_id;

    idtoa(my_id,  idme,  IDTOA_BUF);
    idtoa(his_id, idhim, IDTOA_BUF);

    DBG(DBG_CONTROL,
	DBG_log("looking for secret for %s->%s of kind %s",
		idme, idhim, enum_name(&ppk_names, kind)));

    /* is there a certificate assigned to this connection? */
    if (kind == PPK_RSA && c->spd.this.cert.type != CERT_NONE)
    {
	struct pubkey *my_public_key = allocate_RSA_public_key(c->spd.this.cert);

	for (s = secrets; s != NULL; s = s->next)
	{
	  DBG(DBG_CONTROL,
	      DBG_log("searching for certificate %s:%s vs %s:%s",
		      enum_name(&ppk_names, s->kind),
		      s->u.RSA_private_key.pub.keyid,
		      enum_name(&ppk_names, kind),
		      my_public_key->u.rsa.keyid)
	      );
	    if (s->kind == kind &&
		same_RSA_public_key(&s->u.RSA_private_key.pub, &my_public_key->u.rsa))
	    {
		best = s;
		break; /* we have found the private key - no sense in searching further */
	    }
	}
	free_public_key(my_public_key);
	return best;
    }

    if (his_id_was_instantiated(c))
    {
	/* roadwarrior: replace him with 0.0.0.0 */
	rw_id.kind = addrtypeof(&c->spd.that.host_addr) == AF_INET ?
	    ID_IPV4_ADDR : ID_IPV6_ADDR;
	happy(anyaddr(addrtypeof(&c->spd.that.host_addr), &rw_id.ip_addr));
	his_id = &rw_id;
    }

    for (s = secrets; s != NULL; s = s->next)
    {

	if (s->kind == kind)
	{
	    unsigned int match = 0;

	    if (s->ids == NULL)
	    {
		/* a default (signified by lack of ids):
		 * accept if no more specific match found
		 */
		match = match_default;
	    }
	    else
	    {
		/* check if both ends match ids */
		struct id_list *i;

		for (i = s->ids; i != NULL; i = i->next)
		{
		    idtoa(&i->id, idstr1, IDTOA_BUF);

		    DBG(DBG_PRIVATE,
			DBG_log("comparing PSK %s to %s / %s",
				idstr1, idme, idhim));

		    if (same_id(my_id, &i->id))
			match |= match_me;

		    if (same_id(his_id, &i->id))
			match |= match_him;
		}

		/* If our end matched the only id in the list,
		 * default to matching any peer.
		 * A more specific match will trump this.
		 */
		if (match == match_me
		&& s->ids->next == NULL)
		    match |= match_default;
	    }

	    switch (match)
	    {
	    case match_me:
		/* if this is an asymmetric (eg. public key) system,
		 * allow this-side-only match to count, even if
		 * there are other ids in the list.
		 */
		if (!asym)
		    break;
		/* FALLTHROUGH */
	    case match_default:	/* default all */
	    case match_me | match_default:	/* default peer */
	    case match_me | match_him:	/* explicit */
		if (match == best_match)
		{
		    /* two good matches are equally good:
		     * do they agree?
		     */
		    bool same;

		    switch (kind)
		    {
		    case PPK_PSK:
			same = s->u.preshared_secret.len == best->u.preshared_secret.len
			    && memcmp(s->u.preshared_secret.ptr, best->u.preshared_secret.ptr, s->u.preshared_secret.len) == 0;
			break;
		    case PPK_RSA:
			/* Dirty trick: since we have code to compare
			 * RSA public keys, but not private keys, we
			 * make the assumption that equal public keys
			 * mean equal private keys.  This ought to work.
			 */
			same = same_RSA_public_key(&s->u.RSA_private_key.pub
			    , &best->u.RSA_private_key.pub);
			break;
		    default:
			bad_case(kind);
		    }
		    if (!same)
		    {
			loglog(RC_LOG_SERIOUS, "multiple ipsec.secrets entries with distinct secrets match endpoints:"
			    " first secret used");
			best = s;	/* list is backwards: take latest in list */
		    }
		}
		else if (match > best_match)
		{
		    /* this is the best match so far */
		    best_match = match;
		    best = s;
		}
	    }
	}
    }
    return best;
}

/* find the appropriate preshared key (see get_secret).
 * Failure is indicated by a NULL pointer.
 * Note: the result is not to be freed by the caller.
 */
const chunk_t *
get_preshared_secret(const struct connection *c)
{
    const struct secret *s = get_secret(c, PPK_PSK, FALSE);

#ifdef DEBUG
    DBG(DBG_PRIVATE,
	if (s == NULL)
	    DBG_log("no Preshared Key Found");
	else
	    DBG_dump_chunk("Preshared Key", s->u.preshared_secret);
	);
#endif
    return s == NULL? NULL : &s->u.preshared_secret;
}

/* check the existence of an RSA private key matching an RSA public
 * key contained in an X.509 or OpenPGP certificate
 */
bool
has_private_key(cert_t cert)
{
    struct secret *s;
    bool has_key = FALSE;
    struct pubkey *pubkey = allocate_RSA_public_key(cert);

    for (s = secrets; s != NULL; s = s->next)
    {
	if (s->kind == PPK_RSA &&
	    same_RSA_public_key(&s->u.RSA_private_key.pub, &pubkey->u.rsa))
	{
	    has_key = TRUE;
	    break;
	}
    }
    free_public_key(pubkey);
    return has_key;
}

/* find the appropriate RSA private key (see get_secret).
 * Failure is indicated by a NULL pointer.
 */
const struct RSA_private_key *
get_RSA_private_key(const struct connection *c)
{
    const struct secret *s = get_secret(c, PPK_RSA, TRUE);

    return s == NULL? NULL : &s->u.RSA_private_key;
}

/* digest a secrets file
 *
 * The file is a sequence of records.  A record is a maximal sequence of
 * tokens such that the first, and only the first, is in the first column
 * of a line.
 *
 * Tokens are generally separated by whitespace and are key words, ids,
 * strings, or data suitable for ttodata(3).  As a nod to convention,
 * a trailing ":" on what would otherwise be a token is taken as a
 * separate token.  If preceded by whitespace, a "#" is taken as starting
 * a comment: it and the rest of the line are ignored.
 *
 * One kind of record is an include directive.  It starts with "include".
 * The filename is the only other token in the record.
 * If the filename does not start with /, it is taken to
 * be relative to the directory containing the current file.
 *
 * The other kind of record describes a key.  It starts with a
 * sequence of ids and ends with key information.  Each id
 * is an IP address, a Fully Qualified Domain Name (which will immediately
 * be resolved), or @FQDN which will be left as a name.
 *
 * The key part can be in several forms.
 *
 * The old form of the key is still supported: a simple
 * quoted strings (with no escapes) is taken as a preshred key.
 *
 * The new form starts the key part with a ":".
 *
 * For Preshared Key, use the "PSK" keyword, and follow it by a string
 * or a data token suitable for ttodata(3).
 *
 * For RSA Private Key, use the "RSA" keyword, followed by a
 * brace-enclosed list of key field keywords and data values.
 * The data values are large integers to be decoded by ttodata(3).
 * The fields are a subset of those used by BIND 8.2 and have the
 * same names.
 */

#ifdef X509
/* process rsa key file protected with optional passphrase which can either be
 * read from ipsec.secrets or prompted for by using whack
 */
err_t
process_rsa_keyfile(struct RSA_private_key *rsak, int whackfd)
{
    char filename[BUF_LEN];
    err_t ugh = NULL;
    rsa_privkey_t *key = NULL;
    prompt_pass_t pass;

    memset(filename,'\0', BUF_LEN);
    memset(pass.secret,'\0', sizeof(pass.secret));
    pass.prompt = FALSE;
    pass.fd = whackfd;

    /* we expect the filename of a PKCS#1 private key file */

    if (*tok == '"' || *tok == '\'')  /* quoted filename */
	memcpy(filename, tok+1, flp->cur - tok - 2);
    else
    	memcpy(filename, tok, flp->cur - tok);

    if (shift())
    {
	/* we expect an appended passphrase or passphrase prompt*/
	if (tokeqword("%prompt"))
	{
	    if (pass.fd == NULL_FD)
		return "enter a passphrase using ipsec auto --rereadsecrets";
	    pass.prompt = TRUE;
	}
	else if (*tok == '"' || *tok == '\'') /* quoted passphrase */
	    memcpy(pass.secret, tok+1, flp->cur - tok - 2);
	else
	    memcpy(pass.secret, tok, flp->cur - tok);

	if (shift())
	    ugh = "RSA private key file -- unexpected token after passphrase";
    }

    key = load_rsa_private_key(filename, &pass);

    if (key == NULL)
	ugh = "error loading RSA private key file";
    else
    {
	mpz_t u;
	u_int i;

	for (i = 0; ugh == NULL && i < elemsof(RSA_private_field); i++)
	{
	    MP_INT *n = (MP_INT *) ((char *)rsak + RSA_private_field[i].offset);

	    if (key->field[i].len > 0)
	    {
		/* PKCS#1 RSA private key format - complete */
		n_to_mpz(n, key->field[i].ptr, key->field[i].len);
	    }
	    else
	    {
		/* PGP RSA private key format - missing fields */
		switch (i)
		{
		case 5:		/* dP = d mod (p-1) */
		    mpz_init(u);
		    mpz_sub_ui(u, &rsak->p, 1);
		    mpz_mod(n, &rsak->d, u);
		    mpz_clear(u);
		    break;
		case 6:		/* dQ = d mod (q-1) */
		    mpz_init(u);
		    mpz_sub_ui(u, &rsak->q, 1);
		    mpz_mod(n, &rsak->d, u);
		    mpz_clear(u);
		    break;
		case 7:		/* qInv = (q^-1) mod p */
		    mpz_invert(n, &rsak->q, &rsak->p);
		    if (mpz_cmp_ui(n, 0) < 0)
			mpz_add(n, n, &rsak->p);
		    passert(mpz_cmp(n, &rsak->p) < 0);
		    break;
		default:
		    break;
		}
	    }
	}
	form_keyid(key->field[1], key->field[0], rsak->pub.keyid,
		   &rsak->pub.k);
	ugh = RSA_private_key_sanity(rsak);
	pfree(key->keyobject.ptr);
	pfree(key);
    }
    return ugh;
}
#endif

/* parse PSK from file */
static err_t
process_psk_secret(chunk_t *psk)
{
    err_t ugh = NULL;

    if (*tok == '"' || *tok == '\'')
    {
	clonetochunk(*psk, tok+1, flp->cur - tok  - 2, "PSK");
	(void) shift();
    }
    else
    {
	char buf[RSA_MAX_ENCODING_BYTES];	/* limit on size of binary representation of key */
	size_t sz;

	ugh = ttodatav(tok, flp->cur - tok, 0, buf, sizeof(buf), &sz
	    , diag_space, sizeof(diag_space), TTODATAV_SPACECOUNTS);
	if (ugh != NULL)
	{
	    /* ttodata didn't like PSK data */
	    ugh = builddiag("PSK data malformed (%s): %s", ugh, tok);
	}
	else
	{
	    clonetochunk(*psk, buf, sz, "PSK");
	    (void) shift();
	}
    }
    return ugh;
}

/* Parse fields of RSA private key.
 * A braced list of keyword and value pairs.
 * At the moment, each field is required, in order.
 * The fields come from BIND 8.2's representation
 */
static err_t
process_rsa_secret(struct RSA_private_key *rsak)
{
    char buf[RSA_MAX_ENCODING_BYTES];	/* limit on size of binary representation of key */
    const struct fld *p;

    /* save bytes of Modulus and PublicExponent for keyid calculation */
    unsigned char ebytes[sizeof(buf)];
    unsigned char *eb_next = ebytes;
    chunk_t pub_bytes[2];
    chunk_t *pb_next = &pub_bytes[0];

    for (p = RSA_private_field; p < &RSA_private_field[elemsof(RSA_private_field)]; p++)
    {
	size_t sz;
	err_t ugh;

	if (!shift())
	{
	    return "premature end of RSA key";
	}
	else if (!tokeqword(p->name))
	{
	    return builddiag("%s keyword not found where expected in RSA key"
		, p->name);
	}
	else if (!(shift()
	&& (!tokeq(":") || shift())))	/* ignore optional ":" */
	{
	    return "premature end of RSA key";
	}
	else if (NULL != (ugh = ttodatav(tok, flp->cur - tok
	, 0, buf, sizeof(buf), &sz, diag_space, sizeof(diag_space)
	, TTODATAV_SPACECOUNTS)))
	{
	    /* in RSA key, ttodata didn't like */
	    return builddiag("RSA data malformed (%s): %s", ugh, tok);
	}
	else
	{
	    MP_INT *n = (MP_INT *) ((char *)rsak + p->offset);

	    n_to_mpz(n, buf, sz);
	    if (pb_next < &pub_bytes[elemsof(pub_bytes)])
	    {
		if (eb_next - ebytes + sz > sizeof(ebytes))
		    return "public key takes too many bytes";

		setchunk(*pb_next, eb_next, sz);
		memcpy(eb_next, buf, sz);
		eb_next += sz;
		pb_next++;
	    }
#if 0	/* debugging info that compromises security */
	    {
		size_t sz = mpz_sizeinbase(n, 16);
		char buf[RSA_MAX_OCTETS * 2 + 2];	/* ought to be big enough */

		passert(sz <= sizeof(buf));
		mpz_get_str(buf, 16, n);

		loglog(RC_LOG_SERIOUS, "%s: %s", p->name, buf);
	    }
#endif
	}
    }

    /* We require an (indented) '}' and the end of the record.
     * We break down the test so that the diagnostic will be
     * more helpful.  Some people don't seem to wish to indent
     * the brace!
     */
    if (!shift() || !tokeq("}"))
    {
	return "malformed end of RSA private key -- indented '}' required";
    }
    else if (shift())
    {
	return "malformed end of RSA private key -- unexpected token after '}'";
    }
    else
    {
	unsigned bits = mpz_sizeinbase(&rsak->pub.n, 2);

	rsak->pub.k = (bits + BITS_PER_BYTE - 1) / BITS_PER_BYTE;
	rsak->pub.keyid[0] = '\0';	/* in case of splitkeytoid failure */
	splitkeytoid(pub_bytes[1].ptr, pub_bytes[1].len
	    , pub_bytes[0].ptr, pub_bytes[0].len
	    , rsak->pub.keyid, sizeof(rsak->pub.keyid));
	return RSA_private_key_sanity(rsak);
    }
}

#ifdef SMARTCARD
/*
 * process pin read from ipsec.secrets or prompted for it using whack
 */
static err_t
process_pin(struct secret *s, int whackfd)
{
    smartcard_t *sc;
    const char *pin_status = "no";

    s->kind = PPK_PIN;

    /* looking for the smartcard keyword */
    if (!shift() || strncmp(tok, SCX_TOKEN, strlen(SCX_TOKEN)) != 0)
	 return "PIN keyword must be followed by %smartcard<reader>:<id>";

    sc = scx_add(scx_parse_reader_id(tok + strlen(SCX_TOKEN)));
    s->u.smartcard = sc;
    scx_share(sc);
    scx_free_pin(&sc->pin);
    sc->valid = FALSE;

    if (!shift())
	return "PIN statement must be terminated either by <pin code> or %prompt";

    if (tokeqword("%prompt"))
    {
	shift();

	/* if whackfd exists, whack will be used to prompt for a pin */
	if (whackfd != NULL_FD)
	    pin_status = scx_get_pin(sc, whackfd) ? "valid" : "invalid";
    }
    else
    {
	/* we read the pin directly from ipsec.secrets */
	err_t ugh = process_psk_secret(&sc->pin);
	if (ugh != NULL)
	    return ugh;

	/* verify the pin */
	pin_status = scx_verify_pin(sc) ? "valid" : "invalid";
    }
#ifdef SMARTCARD
    plog("  %s PIN for reader: %d, id: %s", pin_status, sc->reader, sc->id);
#else
    plog("  warning: SMARTCARD support is deactivated in pluto/Makefile!");
#endif
    return NULL;
}
#endif

static void
process_secret(struct secret *s, int whackfd)
{
    err_t ugh = NULL;

    whackfd = whackfd;  /* shut up compiler */

    s->kind = PPK_PSK;	/* default */
    if (*tok == '"' || *tok == '\'')
    {
	/* old PSK format: just a string */
	ugh = process_psk_secret(&s->u.preshared_secret);
    }
    else if (tokeqword("psk"))
    {
	/* preshared key: quoted string or ttodata format */
	ugh = !shift()? "unexpected end of record in PSK"
	    : process_psk_secret(&s->u.preshared_secret);
    }
    else if (tokeqword("rsa"))
    {
	/* RSA key: the fun begins.
	 * A braced list of keyword and value pairs.
	 */
	s->kind = PPK_RSA;
	if (!shift())
	{
	    ugh = "bad RSA key syntax";
	}
	else if (tokeq("{"))
	{
	    ugh = process_rsa_secret(&s->u.RSA_private_key);
	}
	else
	{
#ifdef X509
	   ugh = process_rsa_keyfile(&s->u.RSA_private_key, whackfd);
#else
	   ugh = "X509 support not supported";
#endif
	}
	DBG(DBG_CONTROL,
	    DBG_log("loaded private key for keyid: %s:%s",
		    enum_name(&ppk_names, s->kind),
		    s->u.RSA_private_key.pub.keyid));
    }
    else if (tokeqword("pin"))
    {
#ifdef SMARTCARD
	ugh = process_pin(s, whackfd);
#else
	ugh = "Smartcard not supported";
#endif
    }
    else
    {
	ugh = builddiag("unrecognized key format: %s", tok);
    }

    if (ugh != NULL)
    {
	loglog(RC_LOG_SERIOUS, "\"%s\" line %d: %s"
	    , flp->filename, flp->lino, ugh);
	pfree(s);
    }
    else if (flushline("expected record boundary in key"))
    {
	/* gauntlet has been run: install new secret */
	s->next = secrets;
	secrets = s;
    }
}

static void process_secrets_file(const char *file_pat, int whackfd);	/* forward declaration */

static void
process_secret_records(int whackfd)
{
    /* read records from ipsec.secrets and load them into our table */
    for (;;)
    {
	(void)flushline(NULL);	/* silently ditch leftovers, if any */
	if (flp->bdry == B_file)
	    break;

	flp->bdry = B_none;	/* eat the Record Boundary */
	(void)shift();	/* get real first token */

	if (tokeqword("include"))
	{
	    /* an include directive */
	    char fn[MAX_TOK_LEN];	/* space for filename (I hope) */
	    char *p = fn;
	    char *end_prefix = strrchr(flp->filename, '/');

	    if (!shift())
	    {
		loglog(RC_LOG_SERIOUS, "\"%s\" line %d: unexpected end of include directive"
		    , flp->filename, flp->lino);
		continue;   /* abandon this record */
	    }

	    /* if path is relative and including file's pathname has
	     * a non-empty dirname, prefix this path with that dirname.
	     */
	    if (tok[0] != '/' && end_prefix != NULL)
	    {
		size_t pl = end_prefix - flp->filename + 1;

		/* "clamp" length to prevent problems now;
		 * will be rediscovered and reported later.
		 */
		if (pl > sizeof(fn))
		    pl = sizeof(fn);
		memcpy(fn, flp->filename, pl);
		p += pl;
	    }
	    if (flp->cur - tok >= &fn[sizeof(fn)] - p)
	    {
		loglog(RC_LOG_SERIOUS, "\"%s\" line %d: include pathname too long"
		    , flp->filename, flp->lino);
		continue;   /* abandon this record */
	    }
	    strcpy(p, tok);
	    (void) shift();	/* move to Record Boundary, we hope */
	    if (flushline("ignoring malformed INCLUDE -- expected Record Boundary after filename"))
	    {
		process_secrets_file(fn, whackfd);
		tok = NULL;	/* correct, but probably redundant */
	    }
	}
	else
	{
	    /* expecting a list of indices and then the key info */
	    struct secret *s = alloc_thing(struct secret, "secret");

	    s->ids = NULL;
	    s->kind = PPK_PSK;	/* default */
	    setchunk(s->u.preshared_secret, NULL, 0);
	    s->next = NULL;

	    for (;;)
	    {
		if (tok[0] == '"' || tok[0] == '\'')
		{
		    /* found key part */
		    process_secret(s, whackfd);
		    break;
		}
		else if (tokeq(":"))
		{
		    /* found key part */
		    shift();	/* discard explicit separator */
		    process_secret(s, whackfd);
		    break;
		}
		else
		{
		    /* an id
		     * See RFC2407 IPsec Domain of Interpretation 4.6.2
		     */
		    struct id id;
		    err_t ugh;

		    if (tokeq("%any"))
		    {
			id = empty_id;
			id.kind = ID_IPV4_ADDR;
			ugh = anyaddr(AF_INET, &id.ip_addr);
		    }
		    else if (tokeq("%any6"))
		    {
			id = empty_id;
			id.kind = ID_IPV6_ADDR;
			ugh = anyaddr(AF_INET6, &id.ip_addr);
		    }
		    else
		    {
			ugh = atoid(tok, &id, FALSE);
		    }

		    if (ugh != NULL)
		    {
			loglog(RC_LOG_SERIOUS
			    , "ERROR \"%s\" line %d: index \"%s\" %s"
			    , flp->filename, flp->lino, tok, ugh);
		    }
		    else
		    {
			struct id_list *i = alloc_thing(struct id_list
			    , "id_list");

			i->id = id;
			unshare_id_content(&i->id);
			i->next = s->ids;
			s->ids = i;
			/* DBG_log("id type %d: %s %.*s", i->kind, ip_str(&i->ip_addr), (int)i->name.len, i->name.ptr); */
		    }
		    if (!shift())
		    {
			/* unexpected Record Boundary or EOF */
			loglog(RC_LOG_SERIOUS, "\"%s\" line %d: unexpected end of id list"
			    , flp->filename, flp->lino);
			break;
		    }
		}
	    }
	}
    }
}

static int
globugh(const char *epath, int eerrno)
{
    log_errno_routine(eerrno, "problem with secrets file \"%s\"", epath);
    return 1;	/* stop glob */
}

static void
process_secrets_file(const char *file_pat, int whackfd)
{
    struct file_lex_position pos;
    char **fnp;
    glob_t globbuf;

    pos.depth = flp == NULL? 0 : flp->depth + 1;

    if (pos.depth > 10)
    {
	loglog(RC_LOG_SERIOUS, "preshared secrets file \"%s\" nested too deeply", file_pat);
	return;
    }

    /* do globbing */
    {
	int r = glob(file_pat, GLOB_ERR, globugh, &globbuf);

	if (r != 0)
	{
	    switch (r)
	    {
	    case GLOB_NOSPACE:
		loglog(RC_LOG_SERIOUS, "out of space processing secrets filename \"%s\"", file_pat);
		break;
	    case GLOB_ABORTED:
		break;	/* already logged */
	    case GLOB_NOMATCH:
		loglog(RC_LOG_SERIOUS, "no secrets filename matched \"%s\"", file_pat);
		break;
	    default:
		loglog(RC_LOG_SERIOUS, "unknown glob error %d", r);
		break;
	    }
	    globfree(&globbuf);
	    return;
	}
    }

    /* for each file... */
    for (fnp = globbuf.gl_pathv; *fnp != NULL; fnp++)
    {
	if (lexopen(&pos, *fnp, FALSE))
	{
	    plog("loading secrets from \"%s\"", *fnp);
	    (void) flushline("file starts with indentation (continuation notation)");
	    process_secret_records(whackfd);
	    lexclose();
	}
    }

    globfree(&globbuf);
}

void
free_preshared_secrets(void)
{
    if (secrets != NULL)
    {
	struct secret *s, *ns;

	plog("forgetting secrets");

	for (s = secrets; s != NULL; s = ns)
	{
	    struct id_list *i, *ni;

	    ns = s->next;	/* grab before freeing s */
	    for (i = s->ids; i != NULL; i = ni)
	    {
		ni = i->next;	/* grab before freeing i */
		free_id_content(&i->id);
		pfree(i);
	    }
	    switch (s->kind)
	    {
	    case PPK_PSK:
		pfree(s->u.preshared_secret.ptr);
		break;
	    case PPK_RSA:
		free_RSA_public_content(&s->u.RSA_private_key.pub);
		mpz_clear(&s->u.RSA_private_key.d);
		mpz_clear(&s->u.RSA_private_key.p);
		mpz_clear(&s->u.RSA_private_key.q);
		mpz_clear(&s->u.RSA_private_key.dP);
		mpz_clear(&s->u.RSA_private_key.dQ);
		mpz_clear(&s->u.RSA_private_key.qInv);
		break;
#ifdef SMARTCARD
	    case PPK_PIN:
		scx_release(s->u.smartcard);
		break;
#endif
	    default:
		bad_case(s->kind);
	    }
	    pfree(s);
	}
	secrets = NULL;
    }
}

void
load_preshared_secrets(int whackfd)
{
    free_preshared_secrets();
    (void) process_secrets_file(shared_secrets_file, whackfd);
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

void free_RSA_public_content(struct RSA_public_key *rsa)
{
    mpz_clear(&rsa->n);
    mpz_clear(&rsa->e);
}

/* Free a public key record.
 * As a convenience, this returns a pointer to next.
 */
struct pubkey_list *
free_public_keyentry(struct pubkey_list *p)
{
    struct pubkey_list *nxt = p->next;

    if (p->key != NULL)
	unreference_key(&p->key);
    pfree(p);
    return nxt;
}

void
free_public_keys(struct pubkey_list **keys)
{
    while (*keys != NULL)
	*keys = free_public_keyentry(*keys);
}

/* root of chained public key list */

struct pubkey_list *pubkeys = NULL;	/* keys from ipsec.conf */

void
free_remembered_public_keys(void)
{
    free_public_keys(&pubkeys);
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
	    pl->next = pubkeys;
	    pubkeys = pl;
	}
    }

#ifdef USE_KEYRR
    {
	struct pubkey_list **pp = keys;

	while (*pp != NULL)
	    pp = &(*pp)->next;
	*pp = pubkeys;
	pubkeys = *keys;
	*keys = NULL;
    }
#endif /* USE_KEYRR */
}

/* decode of RSA pubkey chunk
 * - format specified in RFC 2537 RSA/MD5 Keys and SIGs in the DNS
 * - exponent length in bytes (1 or 3 octets)
 *   + 1 byte if in [1, 255]
 *   + otherwise 0x00 followed by 2 bytes of length
 * - exponent
 * - modulus
 */
err_t
unpack_RSA_public_key(struct RSA_public_key *rsa, const chunk_t *pubkey)
{
    chunk_t exp;
    chunk_t mod;

    rsa->keyid[0] = '\0';	/* in case of keybolbtoid failure */

    if (pubkey->len < 3)
	return "RSA public key blob way to short";	/* not even room for length! */

    if (pubkey->ptr[0] != 0x00)
    {
	setchunk(exp, pubkey->ptr + 1, pubkey->ptr[0]);
    }
    else
    {
	setchunk(exp, pubkey->ptr + 3
	    , (pubkey->ptr[1] << BITS_PER_BYTE) + pubkey->ptr[2]);
    }

    if (pubkey->len - (exp.ptr - pubkey->ptr) < exp.len + RSA_MIN_OCTETS_RFC)
	return "RSA public key blob too short";

    mod.ptr = exp.ptr + exp.len;
    mod.len = &pubkey->ptr[pubkey->len] - mod.ptr;

    if (mod.len < RSA_MIN_OCTETS)
	return RSA_MIN_OCTETS_UGH;

    if (mod.len > RSA_MAX_OCTETS)
	return RSA_MAX_OCTETS_UGH;

    n_to_mpz(&rsa->e, exp.ptr, exp.len);
    n_to_mpz(&rsa->n, mod.ptr, mod.len);

    keyblobtoid(pubkey->ptr, pubkey->len, rsa->keyid, sizeof(rsa->keyid));

#ifdef DEBUG
    DBG(DBG_PRIVATE, RSA_show_public_key(rsa));
#endif


    rsa->k = mpz_sizeinbase(&rsa->n, 2);	/* size in bits, for a start */
    rsa->k = (rsa->k + BITS_PER_BYTE - 1) / BITS_PER_BYTE;	/* now octets */

    if (rsa->k != mod.len)
    {
	mpz_clear(&rsa->e);
	mpz_clear(&rsa->n);
	return "RSA modulus shorter than specified";
    }

    return NULL;
}

bool
same_RSA_public_key(const struct RSA_public_key *a
    , const struct RSA_public_key *b)
{
    return a == b
    || (a->k == b->k && mpz_cmp(&a->n, &b->n) == 0 && mpz_cmp(&a->e, &b->e) == 0);
}


void
install_public_key(struct pubkey *pk, struct pubkey_list **head)
{
    struct pubkey_list *p = alloc_thing(struct pubkey_list, "pubkey entry");
    
    unshare_id_content(&pk->id);

    /* copy issuer dn */
    if (pk->issuer.ptr != NULL)
	pk->issuer.ptr = clone_bytes(pk->issuer.ptr, pk->issuer.len, "issuer dn");

    /* store the time the public key was installed */
    time(&pk->installed_time);

    /* install new key at front */
    p->key = reference_key(pk);
    p->next = *head;
    *head = p;
}


void
delete_public_keys(const struct id *id, enum pubkey_alg alg)
{
    struct pubkey_list **pp, *p;
    struct pubkey *pk;

    for (pp = &pubkeys; (p = *pp) != NULL; )
    {
	pk = p->key;
	if (same_id(id, &pk->id) && pk->alg == alg)
	    *pp = free_public_keyentry(p);
	else
	    pp = &p->next;
    }
}

struct pubkey *
reference_key(struct pubkey *pk)
{
    pk->refcnt++;
    return pk;
}

void
unreference_key(struct pubkey **pkp)
{
    struct pubkey *pk = *pkp;
    char b[IDTOA_BUF];

    if (pk == NULL)
	return;

    /* print stuff */
    DBG(DBG_CONTROLMORE,
 	idtoa(&pk->id, b, sizeof(b));
 	DBG_log("unreference key: %p %s cnt %d--", pk, b, pk->refcnt)
	);

    /* cancel out the pointer */
    *pkp = NULL;

    passert(pk->refcnt != 0);
    pk->refcnt--;

    /* we are going to free the key as the refcount will hit zero */
    if (pk->refcnt == 0)
      free_public_key(pk);
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
 *  list all public keys in the chained list
 */
void list_public_keys(bool utc)
{
    struct pubkey_list *p = pubkeys;

    whack_log(RC_COMMENT, " ");
    whack_log(RC_COMMENT, "List of Public Keys:");
    whack_log(RC_COMMENT, " ");

    while (p != NULL)
    {
	struct pubkey *key = p->key;

	if (key->alg == PUBKEY_ALG_RSA)
	{
	    char id_buf[IDTOA_BUF];
	    char expires_buf[TIMETOA_BUF];

	    idtoa(&key->id, id_buf, IDTOA_BUF);
	    strcpy(expires_buf, timetoa(&key->until_time, utc));
	    whack_log(RC_COMMENT, "%s, %4d RSA Key %s, until %s %s",
		timetoa(&key->installed_time, utc), 8*key->u.rsa.k
		      , key->u.rsa.keyid
		      , expires_buf
		      , check_expiry(key->until_time
				     , PUBKEY_WARNING_INTERVAL
				     , TRUE));
	    whack_log(RC_COMMENT,"       %s '%s'",
		enum_show(&ident_names, key->id.kind), id_buf);

#ifdef X509
	    if (key->issuer.len > 0)
	    {
		dntoa(id_buf, IDTOA_BUF, key->issuer);
		whack_log(RC_COMMENT,"       Issuer '%s'", id_buf);
	    }
#endif
	}
	p = p->next;
    }
}
