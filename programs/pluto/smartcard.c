/* Support of smartcards and cryptotokens
 * Copyright (C) 2003 Christoph Gysin, Simon Zwahlen
 * Zuercher Hochschule Winterthur
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
 * RCSID $Id: smartcard.c,v 1.6 2004/09/22 15:47:07 paul Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#ifdef SMARTCARD
#include <opensc/opensc.h>
#include <opensc/pkcs15.h>
#endif

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "constants.h"
#include "defs.h"
#include "id.h"
#include "log.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "smartcard.h"
#include "whack.h"
#include "fetch.h"

#define BUF_LEN	      512	/* buffer size */

/* chained list of smartcard records */
static smartcard_t *smartcards   = NULL;

#ifdef SMARTCARD	/* compile with smartcard support */

static struct sc_context *ctx = NULL;
static struct sc_card *card = NULL;
static struct sc_pkcs15_card *p15card = NULL;

#endif

/*
 * Connect to the card in card reader card_reader, lock and bind it
 *
 * Status information and context is saved in the
 * global variables ctx, card and p15card
 */
bool
scx_establish_context(u_int card_reader USED_BY_SMARTCARD)
{
#ifdef SMARTCARD
    int r;

    /* establish a context */
    r = sc_establish_context(&ctx, "pluto");
    if (r)
    {
	plog("failed to establish context: %s", sc_strerror(r));
	return FALSE;
    }

    /* test if reader card_reader is available */
    if (card_reader >= (unsigned int) ctx->reader_count)
    {
	plog("illegal reader number - only %d reader(s) configured."
	    , ctx->reader_count);
	return FALSE;
    }

    /* test if card is inserted */
     r = sc_detect_card_presence(ctx->reader[card_reader], 0);
    if (!(r & SC_SLOT_CARD_PRESENT))
    {
	plog("card not present: %s", sc_strerror(r));
	return FALSE;
    }
    DBG(DBG_CONTROL | DBG_CRYPT,
	DBG_log("connecting to card in reader %s..."
	    , ctx->reader[card_reader]->name)
    )

    /* connect to the card */
    r = sc_connect_card(ctx->reader[card_reader], 0, &card);
    if (r)
    {
	plog("failed to connect to card: %s", sc_strerror(r));
	return FALSE;
    }

    /* lock card, so it can't be used by another application */
    r = sc_lock(card);
    if (r)
    {
	plog("unable to lock card: %s", sc_strerror(r));
	return FALSE;
    }

    /* establish context for pkcs15-functions */
    r = sc_pkcs15_bind(card, &p15card);
    if (r)
    {
	plog("PKCS #15 initialization failed: %s", sc_strerror(r));
	return FALSE;
    }
    DBG(DBG_CONTROL | DBG_CRYPT,
	DBG_log("found %s!", p15card->label)
    )
    return TRUE;
#else
    plog("warning: SMARTCARD support is deactivated in pluto/Makefile!");
    return FALSE;
#endif
}

/*
 * Release context and disconnect from card
 */
void
scx_release_context(void)
{
#ifdef SMARTCARD
    if (p15card != NULL)
    {
	/* release pkcs15-context */
	sc_pkcs15_unbind(p15card);
	p15card = NULL;
    }
    if (card != NULL)
    {
	/* unlock und disconnect from card */
	sc_unlock(card);
	sc_disconnect_card(card, 0);
	card = NULL;
    }
    if (ctx != NULL)
    {
	/* release context */
	sc_release_context(ctx);
	ctx = NULL;
    }
#endif
}

/*
 * Load host certificate from smartcard
 */
bool
scx_load_cert(smartcard_t *sc UNUSED, cert_t * cert UNUSED)
{
#ifdef SMARTCARD	/* compile with smartcard support */
    struct sc_pkcs15_id id;
    struct sc_pkcs15_cert *card_cert = NULL;
    struct sc_pkcs15_object *cert_obj;
    struct sc_pkcs15_cert_info *cinfo;

    x509cert_t *x509cert;
    chunk_t blob;
    int r;

    /* establish context */
    if (!scx_establish_context(sc->reader))
    {
	scx_release_context();
	return FALSE;
    }

    /* convert id-string to pkcs15-id */
    id.len = SC_PKCS15_MAX_ID_SIZE;
    sc_pkcs15_hex_string_to_id(sc->id, &id);

    /* get info for certificate with id */
    r = sc_pkcs15_find_cert_by_id(p15card, &id, &cert_obj);
    if (r < 0)
    {
	plog("unable to find cert with id %s: %s", sc->id, sc_strerror(r));
	scx_release_context();
	return FALSE;
    }
    cinfo = (struct sc_pkcs15_cert_info *) cert_obj->data;

    /* read certificate */
    r = sc_pkcs15_read_certificate(p15card, cinfo, &card_cert);
    if (r)
    {
	plog("certificate read failed: %s", sc_strerror(r));
	scx_release_context();
	return FALSE;
    }

    scx_release_context();

    if (card_cert == NULL)
    {
	plog( "cert with id %s not found.", sc->id);
	return FALSE;
    }

    /* found and read certificate - now parse it */
    x509cert = alloc_thing(x509cert_t, "x509cert");
    *x509cert = empty_x509cert;
    x509cert->smartcard = TRUE;

    /* copy and release certificate */
    clonetochunk(blob, card_cert->data, card_cert->data_len, "x509cert blob");
    sc_pkcs15_free_certificate(card_cert);
    
    if (!parse_x509cert(blob, 0, x509cert))
    {
	plog("error in X.509 certificate");
	free_x509cert(x509cert);
	return FALSE;
    }

    cert->type = CERT_X509_SIGNATURE;
    cert->u.x509 = x509cert;

    plog("  loaded cert from smartcard (reader: %d, id: %s)", sc->reader, sc->id);
    return TRUE;
#else
    plog("  warning: SMARTCARD support is deactivated in pluto/Makefile!");
    return FALSE;
#endif
}

/*
 * parse reader number and key id
 */
smartcard_t*
scx_parse_reader_id(const char *reader_id)
{
    smartcard_t *sc = alloc_thing(smartcard_t, "smartcard");
    char default_id[] = SCX_DEFAULT_ID;
    int len = strlen(reader_id);

    /*default values */
    sc->reader    = SCX_DEFAULT_READER;
    sc->id        = default_id;
    sc->pin       = empty_chunk;
    sc->valid     = FALSE;
    sc->last_cert = empty_cert;
    sc->last_load = 0;
    sc->count     = 0;
    sc->next      = NULL;

    if (len > 0)
    {
	int reader_len = len;
	err_t ugh = NULL;
	unsigned long ul;
	char *p;

	/* look for colon separator*/
	p = strchr(reader_id, ':');
	if (p != NULL)
	{
	    int id_len = len - (p + 1 - reader_id);
	    reader_len -= (1 + id_len);

	    if (id_len > 0)	/* we have an ID */
		sc->id = p + 1;
	}
	if (reader_len > 0)
	{
	    /* we have an id */
	    ugh = atoul(reader_id, reader_len, 10, &ul);
	    if (ugh == NULL)
		sc->reader = ul;
	    else
		plog("error in smartcard reader number: %s", ugh);
	}
    }
    /* unshare the id string */
    sc->id = clone_str(sc->id, "key id");
    return sc;
}

/*
 * Verify pin on card
 */
bool
scx_verify_pin(smartcard_t *sc UNUSED)
{
#ifdef SMARTCARD
    int r;
    struct sc_pkcs15_object *key, *pin;
    struct sc_pkcs15_id id;

    sc->valid = FALSE;
    if (sc->pin.ptr == NULL)
    {
	plog("unable to verify without PIN");
	return FALSE;
    }

    /* establish context */
    if (!scx_establish_context(sc->reader))
    {
	plog("unable to establish context with reader: %s"
	    , sc_strerror(r));
	return FALSE;
    }

    /* convert id-string to pkcs15-id */
    sc_pkcs15_hex_string_to_id(sc->id, &id);

    /* get private key by id */
    r = sc_pkcs15_find_prkey_by_id(p15card, &id, &key);
    if (r < 0)
    {
	plog("unable to find private key with id %s: %s"
	    , sc->id, sc_strerror(r));
	scx_release_context();
	return FALSE;
    }

    /* get pin information by id */
    r = sc_pkcs15_find_pin_by_auth_id(p15card, &key->auth_id, &pin);
    if (r)
    {
	plog("unable to find PIN code for private key: %s"
	    , sc_strerror(r));
	scx_release_context();
	return FALSE;
    }
    /* verify pin */
    sc->valid = sc_pkcs15_verify_pin(p15card
	    , (struct sc_pkcs15_pin_info *) pin->data
	    , sc->pin.ptr, sc->pin.len) == 0;
    scx_release_context();

    DBG(DBG_CONTROL | DBG_CRYPT,
	DBG_log("PIN code %s", sc->valid ? "correct":"incorrect")
    );
#else
    sc->valid = FALSE;
#endif
    return sc->valid;
}

/*
 * Sign hash on smartcard
 */
bool
scx_sign_hash(smartcard_t *sc UNUSED
	      , const u_char *in UNUSED
	      , size_t inlen UNUSED
	      , u_char *out UNUSED
	      , size_t outlen UNUSED)
{
#ifdef SMARTCARD
    int r;
    struct sc_pkcs15_object *key, *pin;
    struct sc_pkcs15_id id;

    if ((p15card == NULL) || (card == NULL))
    {
	plog("not connected to card!");
	return FALSE;
    }
    if (sc->pin.ptr == NULL)
    {
	plog("unable to sign without PIN!");
	return FALSE;
    }

    /* convert id-string to pkcs15-id */
    sc_pkcs15_hex_string_to_id(sc->id, &id);

    /* get private key by id */
    r = sc_pkcs15_find_prkey_by_id(p15card, &id, &key);

    if (r < 0)
    {
	plog("unable to find private key '%s': %s", sc->id, sc_strerror(r));
	return FALSE;
    }

    /* get pin information by id */
    r = sc_pkcs15_find_pin_by_auth_id(p15card, &key->auth_id, &pin);

    if (r)
    {
	plog("unable to find PIN code for private key: %s", sc_strerror(r));
	return FALSE;
    }

    /* verify pin with pin information */
    r= sc_pkcs15_verify_pin(p15card, (struct sc_pkcs15_pin_info *) pin->data
	, sc->pin.ptr, sc->pin.len);

    if (r)
    {
	plog("PIN code verification failed: %s", sc_strerror(r));
	return FALSE;
    }
    DBG(DBG_CONTROL | DBG_CRYPT,
	DBG_log("PIN code correct")
    )

    /* sign on card */
    r = sc_pkcs15_compute_signature(p15card, key, SC_ALGORITHM_RSA_PAD_PKCS1
	, in, inlen, out, outlen);
    if (r < 0)
    {
	plog("compute signature failed: %s", sc_strerror(r));
	return FALSE;
    }
    return TRUE;
#else
    return FALSE;
#endif
}

/*
 * get length of RSA key in bits
 */
size_t
scx_get_keylength(smartcard_t *sc UNUSED)
{
#ifdef SMARTCARD
    int r;
    struct sc_pkcs15_id id;
    struct sc_pkcs15_object *key;

    if ((p15card == NULL) || (card == NULL))
    {
	plog("not connected to card!");
	return 0;
    }

    /* convert id-string to pkcs15-id */
    sc_pkcs15_hex_string_to_id(sc->id, &id);

    /* get private key by id */
    r = sc_pkcs15_find_prkey_by_id(p15card, &id, &key);
    if (r < 0)
    {
	plog("unable to find private key '%s': %s", sc->id, sc_strerror(r));
	return 0;
    }

    return ((struct sc_pkcs15_prkey_info *) key->data)->modulus_length;
#else
    return 0;
#endif
}

/*
 * prompt for pin and verify it
 */
bool
scx_get_pin(smartcard_t *sc, int whackfd)
{
#ifdef SMARTCARD
    char pin[BUF_LEN];
    int i, n;

    whack_log(RC_ENTERSECRET, "need PIN for reader: %d, id: %s"
	, sc->reader, sc->id);

    for (i = 0; i < SCX_MAX_PIN_TRIALS; i++)
    {
	if (i > 0)
	    whack_log(RC_ENTERSECRET, "invalid PIN, please try again");

	n = read(whackfd, pin, BUF_LEN);

	if (n == -1)
	{
	    whack_log(RC_LOG_SERIOUS, "read(whackfd) failed");
	    return FALSE;
	}

	if (strlen(pin) == 0)
	{
	    whack_log(RC_LOG_SERIOUS, "no PIN entered, aborted");
	    return FALSE;
	}

	sc->pin.ptr = pin;
	sc->pin.len = strlen(pin);

	/* verify the pin */
	if (scx_verify_pin(sc))
	{
	    clonetochunk(sc->pin, pin, strlen(pin), "pin");
	    break;
	}

	/* wrong pin - we try another round */
	sc->pin = empty_chunk;
    }

    if (sc->valid)
	whack_log(RC_SUCCESS, "valid PIN");
    else
	whack_log(RC_LOG_SERIOUS, "invalid PIN, too many trials");
#else
    sc->valid = FALSE;
    whack_log(RC_LOG_SERIOUS, "SMARTCARD support is deactivated in pluto/Makefile!");
#endif
    return sc->valid;
}


/*
 * free the pin code
 */
void
scx_free_pin(chunk_t *pin)
{
    if (pin->ptr != NULL)
    {
	pfree(pin->ptr);
	*pin = empty_chunk;
    }
}

/*
 * frees a smartcard record
 */
void
scx_free(smartcard_t *sc)
{
    if (sc != NULL)
    {
	pfreeany(sc->id);
	scx_free_pin(&sc->pin);
	pfree(sc);
    }
}

/*  release of a smartcard record decreases the count by one
 "  the record is freed when the counter reaches zero
 */
void
scx_release(smartcard_t *sc, bool pthlock)
{
    if (sc != NULL && --sc->count == 0)
    {
	smartcard_t **pp = &smartcards;
	while (*pp != sc)
	    pp = &(*pp)->next;
	if(pthlock)
	{
	    lock_certs_and_keys("scx_release");
	    *pp = sc->next;
	    unlock_certs_and_keys("scx_release");
	}
	else
	{
	    *pp = sc->next;
	}
	release_cert(sc->last_cert);
	scx_free(sc);
    }
}

/*
 *  compare two smartcard records by comparing their readers and ids
 */
static bool
scx_same(smartcard_t *a, smartcard_t *b)
{
    return a->reader == b->reader && streq(a->id, b->id);
}

/*  for each link pointing to the smartcard record
 "  increase the count by one
 */
void
scx_share(smartcard_t *sc)
{
    if (sc != NULL)
 	sc->count++;
}

/*
 *  adds a smartcard record to the chained list
 */
smartcard_t*
scx_add(smartcard_t *smartcard)
{
    smartcard_t *sc = smartcards;

    while (sc != NULL)
    {
	if (scx_same(sc, smartcard)) /* already in chain, free smartcard record */
	{
	    scx_free(smartcard);
	    return sc;
	}
	sc = sc->next;
    }

    /* insert new smartcard record at the root of the chain */
    lock_certs_and_keys("scx_add");
    smartcard->next = smartcards;
    smartcards = smartcard;
    unlock_certs_and_keys("scx_add");
    return smartcard;
}

/*
 * get the smartcard that belongs to an X.509 certificate
 */
smartcard_t*
scx_get(x509cert_t *cert)
{
    smartcard_t *sc = smartcards;

    while (sc != NULL)
    {
	if (sc->last_cert.u.x509 == cert)
	    return sc;
	sc = sc->next;
    }
    return NULL;
}

/*
 *  list all smartcard info records in a chained list
 */
void
scx_list(bool utc)
{
    smartcard_t *sc = smartcards;
    char tbuf[TIMETOA_BUF];

    if (sc != NULL)
    {
	whack_log(RC_COMMENT, " ");
	whack_log(RC_COMMENT, "List of Smartcard Records:");
	whack_log(RC_COMMENT, " ");
    }

    while (sc != NULL)
    {
	whack_log(RC_COMMENT, "%s, count: %d", timetoa(&sc->last_load, utc, tbuf, sizeof(tbuf))
	    , sc->count);
	whack_log(RC_COMMENT, "       reader: %d, id: %s, has %s pin", sc->reader, sc->id
	    , (sc->pin.ptr == NULL)? "no" : ((sc->valid)? "valid" : "invalid"));
	sc = sc->next;
    }
}
