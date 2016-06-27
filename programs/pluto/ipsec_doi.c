/* IPsec DOI and Oakley resolution routines
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003-2006  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010-2011 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <pwouters@redhat.com>
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

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>		/* for gettimeofday */
#include <gmp.h>
#include <resolv.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>
#include "openswan/pfkeyv2.h"

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "id.h"
#include "state.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "pluto/connections.h"	/* needs id.h */
#include "packet.h"
#include "keys.h"
#include "demux.h"	/* needs packet.h */
#include "adns.h"	/* needs <resolv.h> */
#include "dnskey.h"	/* needs keys.h and adns.h */
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "cookie.h"
#include "pluto/server.h"
#include "spdb.h"
#include "timer.h"
#include "rnd.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "whack.h"
#include "fetch.h"
#include "pkcs.h"
#include "asn1.h"

#include "sha1.h"
#include "md5.h"
#include "crypto.h" /* requires sha1.h and md5.h */

#include "ike_alg.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "pluto_crypt.h"
#include "ikev1.h"
#include "ikev1_continuations.h"
#include "ikev2.h"

#ifdef XAUTH
#include "xauth.h"
#endif
#include "vendor.h"
#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif
#include "pluto/virtual.h"
#include "dpd.h"
#include "x509more.h"

#include "tpm/tpm.h"

/* Pluto's Vendor ID
 *
 * Note: it is a NUL-terminated ASCII string, but NUL won't go on the wire.
 */
#define PLUTO_VENDORID_SIZE 12
static bool pluto_vendorid_built = FALSE;
char pluto_vendorid[PLUTO_VENDORID_SIZE + 1];

const char *
init_pluto_vendorid(void)
{
    MD5_CTX hc;
    unsigned char hash[MD5_DIGEST_SIZE];
    const char *v = ipsec_version_string();
    int i;

    if(pluto_vendorid_built) {
	return pluto_vendorid;
    }

    osMD5Init(&hc);
    osMD5Update(&hc, (const unsigned char *)v, strlen(v));
    osMD5Update(&hc, (const unsigned char *)compile_time_interop_options
	, strlen(compile_time_interop_options));
    osMD5Final(hash, &hc);

    pluto_vendorid[0] = 'O';
    pluto_vendorid[1] = 'S';
    pluto_vendorid[2] = 'W';

#if PLUTO_VENDORID_SIZE - 3 <= MD5_DIGEST_SIZE
    /* truncate hash to fit our vendor ID */
    memcpy(pluto_vendorid + 3, hash, PLUTO_VENDORID_SIZE - 3);
#else
    /* pad to fill our vendor ID */
    memcpy(pluto_vendorid + 3, hash, MD5_DIGEST_SIZE);
    memset(pluto_vendorid + 3 + MD5_DIGEST_SIZE, '\0'
	, PLUTO_VENDORID_SIZE - 3 - MD5_DIGEST_SIZE);
#endif

    /* Make it printable!  Hahaha - MCR */
    for (i = 0; i < PLUTO_VENDORID_SIZE; i++)
    {
	/* Reset bit 7, force bit 6.  Puts it into 64-127 range */
	pluto_vendorid[i] &= 0x7f;
	pluto_vendorid[i] |= 0x40;
        if(pluto_vendorid[i]==127) pluto_vendorid[i]='_';  /* omit RUBOUT */
    }
    pluto_vendorid[PLUTO_VENDORID_SIZE] = '\0';
    pluto_vendorid_built = TRUE;

    return pluto_vendorid;
}


/* MAGIC: perform f, a function that returns notification_t
 * and return from the ENCLOSING stf_status returning function if it fails.
 */
#define RETURN_STF_FAILURE2(f, xf)					\
    { int r = (f); if (r != NOTHING_WRONG) { \
	  if((xf)!=NULL) pfree(xf);	     \
	  return STF_FAIL + r; }}

#define RETURN_STF_FAILURE(f) RETURN_STF_FAILURE2(f, NULL)

/* create output HDR as replica of input HDR */
void
echo_hdr(struct msg_digest *md, bool enc, u_int8_t np)
{
    struct isakmp_hdr r_hdr = md->hdr;	/* mostly same as incoming header */

    /* make sure we start with a clean buffer */
    zero(reply_buffer);
    init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer), "reply packet");

    r_hdr.isa_flags &= ~ISAKMP_FLAG_COMMIT;	/* we won't ever turn on this bit */
    if (enc)
	r_hdr.isa_flags |= ISAKMP_FLAG_ENCRYPTION;
    /* some day, we may have to set r_hdr.isa_version */
    r_hdr.isa_np = np;
    if (!out_struct(&r_hdr, &isakmp_hdr_desc, &reply_stream, &md->rbody)) {
	impossible();	/* surely must have room and be well-formed */
    }
}


/*
 * Processing FOR KE values.
 */
void
unpack_KE(struct state *st
	  , struct pluto_crypto_req *r
	  , chunk_t *g)
{
    struct pcr_kenonce *kn = &r->pcr_d.kn;

    if (!st->st_sec_in_use)
    {
	st->st_sec_in_use = TRUE;
	freeanychunk(*g);	/* happens in odd error cases */

	clonetochunk(*g, wire_chunk_ptr(kn, &(kn->gi))
		     , kn->gi.len, "saved gi value");
#ifdef HAVE_LIBNSS
	DBG(DBG_CRYPT, DBG_log("saving DH priv (local secret) and pub key into state struc"));
	clonetochunk(st->st_sec_chunk
		     , wire_chunk_ptr(kn, &(kn->secret))
		     , kn->secret.len, "pointer to DH private key (secret)");

	clonetochunk(st->pubk
		     , wire_chunk_ptr(kn, &(kn->pubk))
		     , kn->pubk.len, "pointer to DH public key");
#else
	n_to_mpz(&st->st_sec
		 , wire_chunk_ptr(kn, &(kn->secret))
		 , kn->secret.len);
	clonetochunk(st->st_sec_chunk
		     , wire_chunk_ptr(kn, &(kn->secret))
		     , kn->secret.len, "long term secret");
#endif
    }
}

/* accept_ke
 *
 * Check and accept DH public value (Gi or Gr) from peer's message.
 * According to RFC2409 "The Internet key exchange (IKE)" 5:
 *  The Diffie-Hellman public value passed in a KE payload, in either
 *  a phase 1 or phase 2 exchange, MUST be the length of the negotiated
 *  Diffie-Hellman group enforced, if necessary, by pre-pending the
 *  value with zeros.
 */
notification_t
accept_KE(chunk_t *dest, const char *val_name
	  , const struct oakley_group_desc *gr
	  , pb_stream *pbs)
{
    /* To figure out which function calls us without a pbs */
    passert(pbs != NULL);

    if (pbs_left(pbs) != gr->bytes)
    {
	loglog(RC_LOG_SERIOUS, "KE has %u byte DH public value; %u required"
	    , (unsigned) pbs_left(pbs), (unsigned) gr->bytes);
	/* XXX Could send notification back */
	return INVALID_KEY_INFORMATION;
    }
    clonereplacechunk(*dest, pbs->cur, pbs_left(pbs), val_name);
    DBG_cond_dump_chunk(DBG_CRYPT, "DH public value received:\n", *dest);
    return NOTHING_WRONG;
}

void
unpack_nonce(chunk_t *n, struct pluto_crypto_req *r)
{
    struct pcr_kenonce *kn = &r->pcr_d.kn;

    freeanychunk(*n);
    clonetochunk(*n, wire_chunk_ptr(kn, &(kn->n))
		 , DEFAULT_NONCE_SIZE, "initiator nonce");
}

bool
justship_nonce(chunk_t *n, pb_stream *outs, u_int8_t np
	       , const char *name)
{
    return out_generic_chunk(np, &isakmp_nonce_desc, outs, *n, name);
}

bool
ship_nonce(chunk_t *n, struct pluto_crypto_req *r
	   , pb_stream *outs, u_int8_t np
	   , const char *name)
{
    unpack_nonce(n, r);
    return justship_nonce(n, outs, np, name);
}

notification_t
accept_nonce(struct msg_digest *md, chunk_t *dest
	     , const char *name, enum next_payload_types paynum)
{
    pb_stream *nonce_pbs = &md->chain[paynum]->pbs;
    size_t len = pbs_left(nonce_pbs);

    if (len < MINIMUM_NONCE_SIZE || MAXIMUM_NONCE_SIZE < len)
    {
	loglog(RC_LOG_SERIOUS, "%s length not between %d and %d"
	    , name , MINIMUM_NONCE_SIZE, MAXIMUM_NONCE_SIZE);
	return PAYLOAD_MALFORMED;	/* ??? */
    }
    clonereplacechunk(*dest, nonce_pbs->cur, len, "nonce");
    return NOTHING_WRONG;
}


/** The whole message must be a multiple of 4 octets.
 * I'm not sure where this is spelled out, but look at
 * rfc2408 3.6 Transform Payload.
 * Note: it talks about 4 BYTE boundaries!
 *
 * @param pbs PB Stream
 */
void
close_message(pb_stream *pbs)
{
    size_t padding =  pad_up(pbs_offset(pbs), 4);

    if (padding != 0)
	(void) out_zero(padding, pbs, "message padding");
    close_output_pbs(pbs);
}

static initiator_function *pick_initiator(struct connection *c UNUSED, lset_t policy)
{
    if((policy & POLICY_IKEV1_DISABLE) == 0 &&
       (c->failed_ikev2 || (policy & POLICY_IKEV2_PROPOSE)==0))  {
	if(policy & POLICY_AGGRESSIVE) {
#if defined(AGGRESSIVE)
	    return aggr_outI1;
#else
	    return aggr_not_present;
#endif
	} else {
	    return main_outI1;
	}

    } else if(policy & POLICY_IKEV2_PROPOSE) {
	return ikev2parent_outI1;

    } else {
	openswan_log("Neither IKEv1 nor IKEv2 allowed");
	/*
	 * tried IKEv2, if allowed, and failed,
	 * and tried IKEv1, if allowed, and got nowhere.
	 */
	return NULL;
    }
}

so_serial_t
ipsecdoi_initiate(int whack_sock
                  , struct state *old_child_state
		  , struct connection *c
		  , lset_t policy
		  , unsigned long try
		  , so_serial_t replacing
		  , enum crypto_importance importance
		  , struct xfrm_user_sec_ctx_ike * uctx
		  )
{
    /* If there's already an ISAKMP SA established, use that and
     * go directly to Quick Mode.  We are even willing to use one
     * that is still being negotiated, but only if we are the Initiator
     * (thus we can be sure that the IDs are not going to change;
     * other issues around intent might matter).
     * Note: there is no way to initiate with a Road Warrior.
     */
    so_serial_t created;

    struct state *st = NULL;

    if(old_child_state) {
        st = state_with_serialno(old_child_state->st_clonedfrom);
    }

    if(st == NULL) {
        st = find_phase1_state(c
                               , ISAKMP_SA_ESTABLISHED_STATES | PHASE1_INITIATOR_STATES);
    }

    if (st == NULL)
    {
        if(!c->spd.that.host_address_list.addresses_available
           && isanyaddr(&c->spd.that.host_addr)) {
            loglog(RC_LOG_SERIOUS, "Can not initiate: no remote address available (yet)");
            return SOS_NOBODY;
        }

	initiator_function *initiator = pick_initiator(c, policy);

	if(initiator) {
	    (void) initiator(whack_sock, c, NULL, &created, policy, try, importance
                             , uctx
                             );
            c->prospective_parent_sa = created;
	    return created;
	}
    }
    else if (HAS_IPSEC_POLICY(policy)) {

      /* boost priority if necessary */
      if(st->st_import < importance) st->st_import = importance;

      if (!IS_ISAKMP_SA_ESTABLISHED(st->st_state)) {
	/* leave our Phase 2 negotiation pending */
	add_pending(whack_sock, st, c, policy, try
		    , replacing
		    , uctx
		   );
	return st->st_serialno;
      }
      else {

	/* ??? we assume that peer_nexthop_sin isn't important:
	 * we already have it from when we negotiated the ISAKMP SA!
	 * It isn't clear what to do with the error return.
	 */
	(void) ipsec_outI1(whack_sock, st, c, policy, try
			   , replacing
			   , uctx
			  );
	return st->st_serialno;
      }
    }

    /* fall through in the case of error */
    close_any(whack_sock);

    return SOS_NOBODY;
}

/* Replace SA with a fresh one that is similar
 *
 * Shares some logic with ipsecdoi_initiate, but not the same!
 * - we must not reuse the ISAKMP SA if we are trying to replace it!
 * - if trying to replace IPSEC SA, use ipsecdoi_initiate to build
 *   ISAKMP SA if needed.
 * - duplicate whack fd, if live.
 * Does not delete the old state -- someone else will do that.
 */
void
ipsecdoi_replace(struct state *st
		 , lset_t policy_add, lset_t policy_del
		 , unsigned long try)
{
	initiator_function *initiator;
    int whack_sock = dup_any(st->st_whack_sock);
    lset_t policy = st->st_policy;
    so_serial_t  newstateno;

    if (IS_PHASE1(st->st_state) || IS_PARENT_SA(st) || IS_PHASE15(st->st_state))
    {
	struct connection *c = st->st_connection;
	policy = c->policy & ~POLICY_IPSEC_MASK;
	policy = policy & ~policy_del;
	policy = policy | policy_add;

	initiator = pick_initiator(c, policy);
	passert(!HAS_IPSEC_POLICY(policy));
	if(initiator) {
	    (void) initiator(whack_sock, st->st_connection, st, &newstateno, policy
			     , try, st->st_import
			     , st->sec_ctx);
	}
    }
    else
    {
	/* Add features of actual old state to policy.  This ensures
	 * that rekeying doesn't downgrade security.  I admit that
	 * this doesn't capture everything.
	 */
	if (st->st_pfs_group != NULL)
	    policy |= POLICY_PFS;
	if (st->st_ah.present)
	{
	    policy |= POLICY_AUTHENTICATE;
	    if (st->st_ah.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
		policy |= POLICY_TUNNEL;
	}
	if (st->st_esp.present && st->st_esp.attrs.transattrs.encrypt != ESP_NULL)
	{
	    policy |= POLICY_ENCRYPT;
	    if (st->st_esp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
		policy |= POLICY_TUNNEL;
	}
	if (st->st_ipcomp.present)
	{
	    policy |= POLICY_COMPRESS;
	    if (st->st_ipcomp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
		policy |= POLICY_TUNNEL;
	}
	passert(HAS_IPSEC_POLICY(policy));
	ipsecdoi_initiate(whack_sock, st, st->st_connection, policy, try
			  , st->st_serialno, st->st_import
			  , st->sec_ctx);
    }
    /* don't close whack_sock here as some caller above might have placed it in the state object */
}

/*
 * look for the existence of a non-expiring preloaded public key
 */
bool
has_preloaded_public_key(struct state *st)
{
    struct connection *c = st->st_connection;

    /* do not consider rw connections since
     * the peer's identity must be known
     */
    if (c->kind == CK_PERMANENT)
    {
	struct pubkey_list *p;

	/* look for a matching RSA public key */
	for (p = pluto_pubkeys; p != NULL; p = p->next)
	{
	    struct pubkey *key = p->key;

	    if (key->alg == PUBKEY_ALG_RSA &&
		same_id(&c->spd.that.id, &key->id) &&
		key->until_time == UNDEFINED_TIME)
	    {
		/* found a preloaded public key */
		return TRUE;
	    }
	}
    }
    return FALSE;
}


/* Decode the ID payload of Phase 1 (main_inI3_outR3 and main_inR3)
 * Note: we may change connections as a result.
 * We must be called before SIG or HASH are decoded since we
 * may change the peer's RSA key or ID.
 */

bool
extract_peer_id(struct id *peer, const pb_stream *id_pbs)
{
    switch (peer->kind)
    {
    case ID_IPV4_ADDR:
    case ID_IPV6_ADDR:
	/* failure mode for initaddr is probably inappropriate address length */
	{
	    err_t ugh = initaddr(id_pbs->cur, pbs_left(id_pbs)
		, peer->kind == ID_IPV4_ADDR? AF_INET : AF_INET6
		, &peer->ip_addr);

	    if (ugh != NULL)
	    {
		loglog(RC_LOG_SERIOUS, "improper %s identification payload: %s"
		    , enum_show(&ident_names, peer->kind), ugh);
		/* XXX Could send notification back */
		return FALSE;
	    }
	}
	break;

    case ID_USER_FQDN:
	if (memchr(id_pbs->cur, '@', pbs_left(id_pbs)) == NULL)
	{
	    loglog(RC_LOG_SERIOUS, "peer's ID_USER_FQDN contains no @: %.*s"
		, (int) pbs_left(id_pbs)
		, id_pbs->cur);
	    /* return FALSE; */
	}
	/* FALLTHROUGH */
    case ID_FQDN:
	if (memchr(id_pbs->cur, '\0', pbs_left(id_pbs)) != NULL)
	{
	    loglog(RC_LOG_SERIOUS, "Phase 1 ID Payload of type %s contains a NUL"
		, enum_show(&ident_names, peer->kind));
	    return FALSE;
	}

	/* ??? ought to do some more sanity check, but what? */

	setchunk(peer->name, id_pbs->cur, pbs_left(id_pbs));
	break;

    case ID_KEY_ID:
	setchunk(peer->name, id_pbs->cur, pbs_left(id_pbs));
	DBG(DBG_PARSING,
 	    DBG_dump_chunk("KEY ID:", peer->name));
	break;

    case ID_DER_ASN1_DN:
	setchunk(peer->name, id_pbs->cur, pbs_left(id_pbs));
 	DBG(DBG_PARSING,
 	    DBG_dump_chunk("DER ASN1 DN:", peer->name));
	break;

    default:
	/* XXX Could send notification back */
	loglog(RC_LOG_SERIOUS, "Unacceptable identity type (%s) in Phase 1 ID Payload"
	    , enum_show(&ident_names, peer->kind));
	return FALSE;
    }

    return TRUE;
}

/*
 * this routine is called from IKEv1 Main and Aggressive mode to
 * extract the ID payload, and then, using it, find a more suitable
 * connection policy to use.
 */
bool
decode_peer_id(struct msg_digest *md, bool initiator, bool aggrmode)
{
    struct state *const st = md->st;
    struct payload_digest *const id_pld = md->chain[ISAKMP_NEXT_ID];
    const pb_stream *const id_pbs = &id_pld->pbs;
    struct isakmp_id *const id = &id_pld->payload.id;
    struct id peer;

    /* I think that RFC2407 (IPSEC DOI) 4.6.2 is confused.
     * It talks about the protocol ID and Port fields of the ID
     * Payload, but they don't exist as such in Phase 1.
     * We use more appropriate names.
     * isaid_doi_specific_a is in place of Protocol ID.
     * isaid_doi_specific_b is in place of Port.
     * Besides, there is no good reason for allowing these to be
     * other than 0 in Phase 1.
     */
#ifdef NAT_TRAVERSAL
    if ((st->hidden_variables.st_nat_traversal & NAT_T_WITH_PORT_FLOATING) &&
	(id->isaid_doi_specific_a == IPPROTO_UDP) &&
	((id->isaid_doi_specific_b == 0) || (id->isaid_doi_specific_b == NAT_T_IKE_FLOAT_PORT))) {
	    DBG_log("protocol/port in Phase 1 ID Payload is %d/%d. "
		"accepted with port_floating NAT-T",
		id->isaid_doi_specific_a, id->isaid_doi_specific_b);
    }
    else
#endif
    if (!(id->isaid_doi_specific_a == 0 && id->isaid_doi_specific_b == 0)
    && !(id->isaid_doi_specific_a == IPPROTO_UDP && id->isaid_doi_specific_b == IKE_UDP_PORT))
    {
	loglog(RC_LOG_SERIOUS, "protocol/port in Phase 1 ID Payload MUST be 0/0 or %d/%d"
	    " but are %d/%d (attempting to continue)"
	    , IPPROTO_UDP, IKE_UDP_PORT
	    , id->isaid_doi_specific_a, id->isaid_doi_specific_b);
	/* we have turned this into a warning because of bugs in other vendors
	 * products. Specifically CISCO VPN3000. */
	/* return FALSE; */
    }

    peer.kind = id->isaid_idtype;

    if(!extract_peer_id(&peer, id_pbs)) {
	return FALSE;
    }

    /*
     * For interop with SoftRemote/aggressive mode we need to remember some
     * things for checking the hash
     */
    st->st_peeridentity_protocol = id->isaid_doi_specific_a;
    st->st_peeridentity_port = ntohs(id->isaid_doi_specific_b);

    {
	char buf[IDTOA_BUF];

	idtoa(&peer, buf, sizeof(buf));
	openswan_log("%s mode peer ID is %s: '%s'"
		     , aggrmode ? "Aggressive" : "Main"
		     , enum_show(&ident_names, id->isaid_idtype), buf);
    }

    /* check for certificates */
    decode_cert(md);

    /* Now that we've decoded the ID payload, let's see if we
     * need to switch connections.
     * We must not switch horses if we initiated:
     * - if the initiation was explicit, we'd be ignoring user's intent
     * - if opportunistic, we'll lose our HOLD info
     */
    if (initiator)
    {
	if (!same_id(&st->st_connection->spd.that.id, &peer))
	{
	    char expect[IDTOA_BUF]
		, found[IDTOA_BUF];

	    idtoa(&st->st_connection->spd.that.id, expect, sizeof(expect));
	    idtoa(&peer, found, sizeof(found));
	    loglog(RC_LOG_SERIOUS
		, "we require peer to have ID '%s', but peer declares '%s'"
		, expect, found);
	    return FALSE;
	}
    }
    else
    {
	struct connection *c = st->st_connection;
	struct connection *r;

	/* check for certificate requests */
	decode_cr(md, &c->requested_ca);

	r = refine_host_connection(st, &peer, initiator, aggrmode);

	/* delete the collected certificate requests */
	free_generalNames(c->requested_ca, TRUE);
	c->requested_ca = NULL;

	if (r == NULL)
	{
	    char buf[IDTOA_BUF];

	    idtoa(&peer, buf, sizeof(buf));
	    loglog(RC_LOG_SERIOUS
		   , "no suitable connection for peer '%s'"
		   , buf);
	    return FALSE;
	}

	DBG(DBG_CONTROL,
	    char buf[IDTOA_BUF];

	    dntoa_or_null(buf, IDTOA_BUF, r->spd.this.ca, "%none");
	    DBG_log("offered CA: '%s'", buf));

        if (r->kind == CK_TEMPLATE || r->kind == CK_GROUP) {
            /* instantiate it, filling in peer's ID */
            r = rw_instantiate(r, &st->st_remoteaddr,
                               NULL,
                               &peer);
        }

        if (r != c)
	{
            openswan_log("switched from \"%s\" to \"%s\"", c->name, r->name);

	    st->st_connection = r;	/* kill reference to c */

	    /* this ensures we don't move cur_connection from NULL to
	     * something, requiring a reset_cur_connection() */
	    if (cur_connection == c) {
		set_cur_connection(r);
	    }

	    connection_discard(c);
	}
    }

    return TRUE;
}

void initialize_new_state(struct state *st
			, struct connection *c
			, lset_t policy
			, int try
			, int whack_sock
			, enum crypto_importance importance)
{
    struct spd_route *sr;

    st->st_connection = c;

    set_state_ike_endpoints(st, c);

    set_cur_state(st);	/* we must reset before exit */
    st->st_policy     = policy & ~POLICY_IPSEC_MASK;   /* clear bits */
    st->st_whack_sock = whack_sock;
    st->st_try   = try;

    st->st_import = importance;
    st->st_msgid_nextuse = 1;     /* first non-INIT message is 1 */
    st->st_msgid_lastack = INVALID_MSGID;

    for(sr=&c->spd; sr!=NULL; sr=sr->next) {
	if(sr->this.xauth_client) {
	    if(sr->this.xauth_name) {
		strncpy(st->st_xauth_username, sr->this.xauth_name, sizeof(st->st_xauth_username));
		break;
	    }
	}
    }

    insert_state(st);	/* needs cookies, connection */

#ifdef DEBUG
    extra_debugging(c);
#endif
}

void
send_delete(struct state *st)
{
    if(st->st_ikev2) {
	ikev2_delete_out(st);
    } else {
	ikev1_delete_out(st);
    }
}

void fmt_ipsec_sa_established(struct state *st, char *sadetails, int sad_len)
{
    char *b = sadetails;
    const char *ini = " {";
    const char *fin = "";

    passert(st->st_connection != NULL);
    strcpy(sadetails,
	   (st->st_connection->policy & POLICY_TUNNEL ?
	    " tunnel mode" : " transport mode"));
    b += strlen(sadetails);

    /* -1 is to leave space for "fin" */

    if(st->st_esp.present)
    {
	const char *natinfo="";

	if((st->st_connection->spd.that.host_port != IKE_UDP_PORT
	    && st->st_connection->spd.that.host_port != 0)
	   || st->st_connection->forceencaps) {
	    natinfo="/NAT";
	}
	snprintf(b, sad_len-(b-sadetails)-1
		 , "%sESP%s=>0x%08lx <0x%08lx xfrm=%s_%d-%s"
		 , ini
		 , natinfo
		 , (unsigned long)ntohl(st->st_esp.attrs.spi)
		 , (unsigned long)ntohl(st->st_esp.our_spi)
		 , enum_show(&esp_transformid_names, st->st_esp.attrs.transattrs.encrypt)+strlen("ESP_")
		 , st->st_esp.attrs.transattrs.enckeylen
		 , enum_show(&auth_alg_names, st->st_esp.attrs.transattrs.integ_hash)+strlen("AUTH_ALGORITHM_"));
	ini = " ";
	fin = "}";
    }
    /* advance b to end of string */
    b = b + strlen(b);

    if(st->st_ah.present)
    {
	snprintf(b, sad_len-(b-sadetails)-1
		 , "%sAH=>0x%08lx <0x%08lx"
		 , ini
		 , (unsigned long)ntohl(st->st_ah.attrs.spi)
		 , (unsigned long)ntohl(st->st_ah.our_spi));
	ini = " ";
	fin = "}";
    }
    /* advance b to end of string */
    b = b + strlen(b);

    if(st->st_ipcomp.present)
    {
	snprintf(b, sad_len-(b-sadetails)-1
		 , "%sIPCOMP=>0x%08lx <0x%08lx"
		 , ini
		 , (unsigned long)ntohl(st->st_ipcomp.attrs.spi)
		 , (unsigned long)ntohl(st->st_ipcomp.our_spi));
	ini = " ";
	fin = "}";
    }

    /* advance b to end of string */
    b = b + strlen(b);
#ifdef NAT_TRAVERSAL
    {
	char oa[ADDRTOT_BUF];

	strcpy(oa, "none");
	if(!isanyaddr(&st->hidden_variables.st_nat_oa)) {
	    addrtot(&st->hidden_variables.st_nat_oa, 0
		    , oa, sizeof(oa));
	}
	snprintf(b, sad_len-(b-sadetails)-1
		 , "%sNATOA=%s"
		 , ini, oa);
	ini = " ";
	fin = "}";
    }

    b = b + strlen(b);
    {
	char oa[ADDRTOT_BUF+sizeof(":00000")];

	strcpy(oa, "none");
	if(!isanyaddr(&st->hidden_variables.st_natd)) {
	    char oa2[ADDRTOT_BUF];
	    addrtot(&st->hidden_variables.st_natd, 0
		    , oa2, sizeof(oa2));
	    snprintf(oa, sizeof(oa)
		     , "%s:%d", oa2, st->st_remoteport);
	}
	snprintf(b, sad_len-(b-sadetails)-1
		 , "%sNATD=%s"
		 , ini, oa);
	ini = " ";
	fin = "}";
    }
#endif

    /* advance b to end of string */
    b = b + strlen(b);

    snprintf(b, sad_len-(b-sadetails)-1
	     , "%sDPD=%s"
	     , ini
	     , st->hidden_variables.st_dpd_local ?
	     "enabled" : "none");

    ini = " ";
    fin = "}";

    strcat(b, fin);
}

void fmt_isakmp_sa_established(struct state *st, char *sadetails, int sad_len)
{

    /* document ISAKMP SA details for admin's pleasure */
    char *b = sadetails;
    const char *authname;
    const char *integstr, *integname;
    char integname_tmp[20];

    passert(st->st_oakley.encrypter != NULL);
    passert(st->st_oakley.prf_hasher != NULL);
    passert(st->st_oakley.group != NULL);

    if(st->st_ikev2) {
	authname="IKEv2";
	integstr=" integ=";
	snprintf(integname_tmp, sizeof(integname_tmp), "%s_%zu", st->st_oakley.integ_hasher->common.officname
		, st->st_oakley.integ_hasher->hash_integ_len*BITS_PER_BYTE);
	integname=(const char*)integname_tmp;
    } else {
	authname = enum_show(&oakley_auth_names, st->st_oakley.auth);
	integstr="";
	integname="";
    }

    snprintf(b, sad_len-(b-sadetails)-1
	     , " {auth=%s cipher=%s_%d%s%s prf=%s group=modp%d}"
	     , authname
	     , st->st_oakley.encrypter->common.name
	     , st->st_oakley.enckeylen
	     , integstr, integname
	     , st->st_oakley.prf_hasher->common.name
	     , (int)st->st_oakley.group->bytes*8);
    st->hidden_variables.st_logged_p1algos = TRUE;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
