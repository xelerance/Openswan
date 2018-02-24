/*
 * make and verify key signatures in generic fashion
 *
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2003-2018  Michael Richardson <mcr@xelerance.com>
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

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
