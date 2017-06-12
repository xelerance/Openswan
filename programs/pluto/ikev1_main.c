/* IPsec DOI and Oakley resolution routines
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003-2008 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2008 Ilia Sotnikov
 * Copyright (C) 2009 Seong-hun Lim
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
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
#include "state.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "pluto/connections.h"	/* needs id.h */
#include "hostpair.h"
#include "pluto/keys.h"
#include "keys.h"
#include "packet.h"
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

#include "oswcrypto.h"

#ifdef XAUTH
#include "xauth.h"
#endif
#include "vendor.h"
#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif
#ifdef VIRTUAL_IP
#include "pluto/virtual.h"
#endif
#include "dpd.h"
#include "x509more.h"

#include "tpm/tpm.h"

/* Initiate an Oakley Main Mode exchange.
 * --> HDR;SA
 * Note: this is not called from demux.c
 */
stf_status
main_outI1(int whack_sock
	   , struct connection *c
	   , struct state *predecessor
           , so_serial_t  *newstateno
	   , lset_t policy
	   , unsigned long try
	   , enum crypto_importance importance
	   , struct xfrm_user_sec_ctx_ike * uctx
	   )
{
    struct state *st = new_state();
    struct msg_digest md;   /* use reply/rbody found inside */

    int numvidtosend = 1;  /* we always send DPD VID */
#ifdef NAT_TRAVERSAL
    if (nat_traversal_enabled) {
	numvidtosend++;
    }
#endif
#if SEND_PLUTO_VID || defined(openpgp_peer)
    numvidtosend++;
#endif
#ifdef XAUTH
    if(c->spd.this.xauth_client || c->spd.this.xauth_server) {
	numvidtosend++;
    }
#endif

    /* set up new state */
    get_cookie(TRUE, st->st_icookie, COOKIE_SIZE, &c->spd.that.host_addr);
    initialize_new_state(st, c, policy, try, whack_sock, importance);
    if(newstateno) *newstateno = st->st_serialno;

    /* IKE version numbers -- used mostly in logging */
    st->st_ike_maj        = IKEv1_MAJOR_VERSION;
    st->st_ike_min        = IKEv1_MINOR_VERSION;

    change_state(st, STATE_MAIN_I1);

    if (HAS_IPSEC_POLICY(policy))
	add_pending(dup_any(whack_sock), st, c, policy, 1
	    , predecessor == NULL? SOS_NOBODY : predecessor->st_serialno
	    , uctx
                    );

#ifdef HAVE_LABELED_IPSEC
    /*For main modes states, sec ctx is always null*/
    st->sec_ctx = NULL;
#endif

    if (predecessor == NULL)
	openswan_log("initiating Main Mode");
    else
	openswan_log("initiating Main Mode to replace #%lu", predecessor->st_serialno);

    /* set up reply */
    zero(reply_buffer);
    init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer), "reply packet");

    /* HDR out */
    {
	struct isakmp_hdr hdr;

	zero(&hdr);	/* default to 0 */
	hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION;
	hdr.isa_np = ISAKMP_NEXT_SA;
	hdr.isa_xchg = ISAKMP_XCHG_IDPROT;
	memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
	/* R-cookie, flags and MessageID are left zero */

	if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream, &md.rbody))
	{
	    reset_cur_state();
	    return STF_INTERNAL_ERROR;
	}
    }

    /* SA out */
    {
	u_char *sa_start = md.rbody.cur;
	int    policy_index = POLICY_ISAKMP(policy
					    , c->spd.this.xauth_server
					    , c->spd.this.xauth_client);

	/* if we  have an OpenPGP certificate we assume an
	 * OpenPGP peer and have to send the Vendor ID
	 */
	int np = numvidtosend > 0 ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
	if (!out_sa(&md.rbody
		    , &oakley_sadb[policy_index], st, TRUE, FALSE, np))
	{
	    openswan_log("outsa fail");
	    reset_cur_state();
	    return STF_INTERNAL_ERROR;
	}
	/* save initiator SA for later HASH */
	passert(st->st_p1isa.ptr == NULL);	/* no leak!  (MUST be first time) */
	clonetochunk(st->st_p1isa, sa_start, md.rbody.cur - sa_start
	    , "sa in main_outI1");
    }

    if (SEND_PLUTO_VID || c->spd.this.cert.type == CERT_PGP)
    {
	char *vendorid = (c->spd.this.cert.type == CERT_PGP) ?
	    pgp_vendorid : pluto_vendorid;
	int np = --numvidtosend > 0 ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;

	if (!out_generic_raw(np, &isakmp_vendor_id_desc, &md.rbody
			     , vendorid, strlen(vendorid), "Vendor ID"))
	    return STF_INTERNAL_ERROR;
    }

    /* Send DPD VID */
    {
	int np = --numvidtosend > 0 ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
	if(!out_vid(np, &md.rbody, VID_MISC_DPD)) {
	    reset_cur_state();
	    return STF_INTERNAL_ERROR;
	}
    }

#ifdef NAT_TRAVERSAL
    DBG(DBG_NATT, DBG_log("nat traversal enabled: %d"
			  , nat_traversal_enabled));
    if (nat_traversal_enabled) {
	int np = --numvidtosend > 0 ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;

	/* Add supported NAT-Traversal VID */
	if (!nat_traversal_insert_vid(np, &md.rbody, st)) {
	    reset_cur_state();
	    return STF_INTERNAL_ERROR;
	}
    }
#endif

#ifdef XAUTH
    if(c->spd.this.xauth_client || c->spd.this.xauth_server) {
	int np = --numvidtosend > 0 ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
	if(!out_vid(np, &md.rbody, VID_MISC_XAUTH)) {
	    reset_cur_state();
	    return STF_INTERNAL_ERROR;
	}
    }
#endif

#ifdef DEBUG
    /* if we are not 0 then something went very wrong above */
    if(numvidtosend != 0) {
	openswan_log("payload alignment problem please check the code in main_inR1_outR2 (num=%d)", numvidtosend);
    }
#endif

    close_message(&md.rbody);
    close_output_pbs(&reply_stream);

    /* let TCL hack it before we mark the length and copy it */
    TCLCALLOUT("avoidEmitting", st, st->st_connection, &md);
    clonetochunk(st->st_tpacket, reply_stream.start, pbs_offset(&reply_stream)
	, "reply packet for main_outI1");

    /* Transmit */
    send_packet(st, "main_outI1", TRUE);

    /* Set up a retransmission event, half a minute henceforth */
    TCLCALLOUT("adjustTimers", st, st->st_connection, &md);

#ifdef TPM
 tpm_stolen:
 tpm_ignore:
#endif
    delete_event(st);
    event_schedule(EVENT_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);

    if (predecessor != NULL)
    {
	update_pending(predecessor, st);
	whack_log(RC_NEW_STATE + STATE_MAIN_I1
	    , "%s: initiate, replacing #%lu"
	    , enum_name(&state_names, st->st_state)
	    , predecessor->st_serialno);
    }
    else
    {
	whack_log(RC_NEW_STATE + STATE_MAIN_I1
	    , "%s: initiate", enum_name(&state_names, st->st_state));
    }
    reset_cur_state();
    return STF_OK;
}

/* Generate HASH_I or HASH_R for ISAKMP Phase I.
 * This will *not* generate other hash payloads (eg. Phase II or Quick Mode,
 * New Group Mode, or ISAKMP Informational Exchanges).
 * If the hashi argument is TRUE, generate HASH_I; if FALSE generate HASH_R.
 * See RFC2409 IKE 5.
 *
 * Generating the SIG_I and SIG_R for DSS is an odd perversion of this:
 * Most of the logic is the same, but SHA-1 is used in place of HMAC-whatever.
 * The extensive common logic is embodied in main_mode_hash_body().
 * See draft-ietf-ipsec-ike-01.txt 4.1 and 6.1.1.2
 */

#ifdef HAVE_LIBNSS
void
main_mode_hash_body(struct state *st
                    , bool hashi        /* Initiator? */
                    , const pb_stream *idpl     /* ID payload, as PBS */
                    , struct hmac_ctx *ctx
                    , hash_update_t hash_update_void UNUSED)
#else
void
main_mode_hash_body(struct state *st
		    , bool hashi	/* Initiator? */
		    , const pb_stream *idpl	/* ID payload, as PBS */
		    , union hash_ctx *ctx
		    , hash_update_t hash_update_void)
#endif
{
#ifndef HAVE_LIBNSS
#define HASH_UPDATE_T (union hash_ctx *, const u_char *input, unsigned int len)
    hash_update_t hash_update=(hash_update_t)  hash_update_void;
#if 0	/* if desperate to debug hashing */
#   define hash_update(ctx, input, len) { \
	DBG_dump("hash input", input, len); \
	(hash_update)(ctx, input, len); \
	}
#endif

#   define hash_update_chunk(ctx, ch) hash_update((ctx), (ch).ptr, (ch).len)
#else
 hash_update_void = NULL;
#endif

    if (hashi)
    {
#ifdef HAVE_LIBNSS
        hmac_update_chunk(ctx, st->st_gi);
        hmac_update_chunk(ctx, st->st_gr);
        hmac_update(ctx, st->st_icookie, COOKIE_SIZE);
        hmac_update(ctx, st->st_rcookie, COOKIE_SIZE);
#else
	hash_update_chunk(ctx, st->st_gi);
	hash_update_chunk(ctx, st->st_gr);
	hash_update(ctx, st->st_icookie, COOKIE_SIZE);
	hash_update(ctx, st->st_rcookie, COOKIE_SIZE);
#endif
    }
    else
    {
#ifdef HAVE_LIBNSS
        hmac_update_chunk(ctx, st->st_gr);
        hmac_update_chunk(ctx, st->st_gi);
        hmac_update(ctx, st->st_rcookie, COOKIE_SIZE);
        hmac_update(ctx, st->st_icookie, COOKIE_SIZE);
#else
	hash_update_chunk(ctx, st->st_gr);
	hash_update_chunk(ctx, st->st_gi);
	hash_update(ctx, st->st_rcookie, COOKIE_SIZE);
	hash_update(ctx, st->st_icookie, COOKIE_SIZE);
#endif
    }

    DBG(DBG_CRYPT, DBG_log("hashing %lu bytes of SA"
	, (unsigned long) (st->st_p1isa.len - sizeof(struct isakmp_generic))));

    /* SA_b */
#ifdef HAVE_LIBNSS
    hmac_update(ctx, st->st_p1isa.ptr + sizeof(struct isakmp_generic)
        , st->st_p1isa.len - sizeof(struct isakmp_generic));
#else
    hash_update(ctx, st->st_p1isa.ptr + sizeof(struct isakmp_generic)
	, st->st_p1isa.len - sizeof(struct isakmp_generic));
#endif

    /* Hash identification payload, without generic payload header.
     * We used to reconstruct ID Payload for this purpose, but now
     * we use the bytes as they appear on the wire to avoid
     * "spelling problems".
     */
#ifdef HAVE_LIBNSS
    hmac_update(ctx
        , idpl->start + sizeof(struct isakmp_generic)
        , pbs_offset(idpl) - sizeof(struct isakmp_generic));
#else
    hash_update(ctx
	, idpl->start + sizeof(struct isakmp_generic)
	, pbs_offset(idpl) - sizeof(struct isakmp_generic));
#endif

#   undef hash_update_chunk
#   undef hash_update
}

size_t	/* length of hash */
main_mode_hash(struct state *st
	       , u_char *hash_val	/* resulting bytes */
	       , bool hashi	/* Initiator? */
	       , const pb_stream *idpl)	/* ID payload, as PBS; cur must be at end */
{
    struct hmac_ctx ctx;

    hmac_init_chunk(&ctx, st->st_oakley.prf_hasher, st->st_skeyid);
#ifdef HAVE_LIBNSS
    main_mode_hash_body(st, hashi, idpl, &ctx, NULL);
#else
    main_mode_hash_body(st, hashi, idpl, &ctx.hash_ctx, ctx.h->hash_update);
#endif
    hmac_final(hash_val, &ctx);
    return ctx.hmac_digest_len;
}

#if 0	/* only needed for DSS */
static void
main_mode_sha1(struct state *st
, u_char *hash_val	/* resulting bytes */
, size_t *hash_len	/* length of hash */
, bool hashi	/* Initiator? */
, const pb_stream *idpl)	/* ID payload, as PBS */
{
    union hash_ctx ctx;

    SHA1Init(&ctx.ctx_sha1);
    SHA1Update(&ctx.ctx_sha1, st->st_skeyid.ptr, st->st_skeyid.len);
    *hash_len = SHA1_DIGEST_SIZE;
    main_mode_hash_body(st, hashi, idpl, &ctx
	, (void (*)(union hash_ctx *, const u_char *, unsigned int))&SHA1Update);
    SHA1Final(hash_val, &ctx.ctx_sha1);
}
#endif

/* Create an RSA signature of a hash.
 * Poorly specified in draft-ietf-ipsec-ike-01.txt 6.1.1.2.
 * Use PKCS#1 version 1.5 encryption of hash (called
 * RSAES-PKCS1-V1_5) in PKCS#2.
 */
size_t
RSA_sign_hash(struct connection *c
	      , u_char sig_val[RSA_MAX_OCTETS]
	      , const u_char *hash_val, size_t hash_len)
{
    size_t sz = 0;
    const struct private_key_stuff *pks = get_RSA_private_key(c);

    if (pks == NULL)
	return 0;	/* failure: no key to use */

    sz = pks->pub->u.rsa.k;
    passert(RSA_MIN_OCTETS <= sz && 4 + hash_len < sz && sz <= RSA_MAX_OCTETS);
    sign_hash(pks, hash_val, hash_len, sig_val, sz);
    return sz;
}

static stf_status
RSA_check_signature(struct state *st
		    , const u_char hash_val[MAX_DIGEST_LEN]
		    , size_t hash_len
		    , const pb_stream *sig_pbs
#ifdef USE_KEYRR
		    , const struct pubkey_list *keys_from_dns
#endif /* USE_KEYRR */
		    , const struct gw_info *gateways_from_dns
)
{
    return RSA_check_signature_gen(st, hash_val, hash_len
				   , sig_pbs
#ifdef USE_KEYRR
				   , keys_from_dns
#endif
				   , gateways_from_dns
				   , try_RSA_signature_v1);
}

notification_t
accept_v1_nonce(struct msg_digest *md, chunk_t *dest, const char *name)
{
    return accept_nonce(md, dest, name, ISAKMP_NEXT_NONCE);
}

/* encrypt message, sans fixed part of header
 * IV is fetched from st->st_new_iv and stored into st->st_iv.
 * The theory is that there will be no "backing out", so we commit to IV.
 * We also close the pbs.
 */
bool
encrypt_message(pb_stream *pbs, struct state *st)
{
    const struct encrypt_desc *e = st->st_oakley.encrypter;
    u_int8_t *enc_start = pbs->start + sizeof(struct isakmp_hdr);
    size_t enc_len = pbs_offset(pbs) - sizeof(struct isakmp_hdr);

    DBG_cond_dump(DBG_CRYPT | DBG_RAW, "encrypting:\n", enc_start, enc_len);
    DBG_cond_dump(DBG_CRYPT | DBG_RAW, "IV:\n"
		  , st->st_new_iv
		  , st->st_new_iv_len);
    DBG(DBG_CRYPT, DBG_log("unpadded size is: %u", (unsigned int)enc_len));

    /* Pad up to multiple of encryption blocksize.
     * See the description associated with the definition of
     * struct isakmp_hdr in packet.h.
     */
    {
	size_t padding = pad_up(enc_len, e->enc_blocksize);

	if (padding != 0)
	{
	    if (!out_zero(padding, pbs, "encryption padding"))
		return FALSE;
	    enc_len += padding;
	}
    }

    DBG(DBG_CRYPT
	, DBG_log("encrypting %d using %s"
		  , (unsigned int)enc_len
		  , enum_show(&oakley_enc_names, st->st_oakley.encrypt)));

    TCLCALLOUT_crypt("preEncrypt", st, pbs,sizeof(struct isakmp_hdr),enc_len);

    /* e->crypt(TRUE, enc_start, enc_len, st); */
    crypto_cbc_encrypt(e, TRUE, enc_start, enc_len, st);

    TCLCALLOUT_crypt("postEncrypt", st,pbs,sizeof(struct isakmp_hdr),enc_len);

    update_iv(st);
    DBG_cond_dump(DBG_CRYPT, "next IV:", st->st_iv, st->st_iv_len);
    close_message(pbs);
    return TRUE;
}

/* State Transition Functions.
 *
 * The definition of state_microcode_table in demux.c is a good
 * overview of these routines.
 *
 * - Called from process_packet; result handled by complete_v1_state_transition
 * - struct state_microcode member "processor" points to these
 * - these routine definitionss are in state order
 * - these routines must be restartable from any point of error return:
 *   beware of memory allocated before any error.
 * - output HDR is usually emitted by process_packet (if state_microcode
 *   member first_out_payload isn't ISAKMP_NEXT_NONE).
 *
 * The transition functions' functions include:
 * - process and judge payloads
 * - update st_iv (result of decryption is in st_new_iv)
 * - build reply packet
 */

/* Handle a Main Mode Oakley first packet (responder side).
 * HDR;SA --> HDR;SA
 */

#ifdef DMALLOC
static unsigned long _dm_mark = 0;
static unsigned long _dm_initialized = 0;
#endif

stf_status
main_inI1_outR1(struct msg_digest *md)
{
#ifdef DMALLOC
     if (_dm_initialized != 0) {
	/* log unfreed pointers that have been added to the heap since mark */
	dmalloc_log_changed(_dm_mark, 1, 0, 1);
	dmalloc_log_stats ();
     }
     _dm_mark = dmalloc_mark() ;
     _dm_initialized = 1;
#endif

    struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_SA];
    struct state *st;
    struct connection *c;
    pb_stream r_sa_pbs;
    lset_t policy_hint = 0;

    /* we are looking for an OpenPGP Vendor ID sent by the peer */
    bool openpgp_peer = FALSE;

    /* Determin how many Vendor ID payloads we will be sending */
    int next;
    int numvidtosend = 1;  /* we always send DPD VID */

#ifdef NAT_TRAVERSAL
    if (md->quirks.nat_traversal_vid && nat_traversal_enabled) {
	DBG(DBG_NATT, DBG_log("nat-t detected, sending nat-t VID"));
	numvidtosend++;
    }
#endif

#if SEND_PLUTO_VID || defined(openpgp_peer)
    numvidtosend++;
#endif

#if defined(openpgp_peer)
    {
	    struct payload_digest *p;
	    for (p = md->chain[ISAKMP_NEXT_VID]; p != NULL; p = p->next)
		{
		    int vid_len = sizeof(pgp_vendorid) - 1 < pbs_left(&p->pbs)
			? sizeof(pgp_vendorid) - 1 : pbs_left(&p->pbs);

		    if (memcmp(pgp_vendorid, p->pbs.cur, vid_len) == 0)
			{
			    openpgp_peer = TRUE;
			    DBG(DBG_PARSING,
				DBG_log("we have an OpenPGP peer")
				)
				}
		}
    }
#endif


    /* random source ports are handled by find_host_connection */
    c = find_host_connection(ANY_MATCH, &md->iface->ip_addr, pluto_port500
                             , KH_IPADDR
			     , &md->sender
			     , md->sender_port, LEMPTY, POLICY_IKEV1_DISABLE, &policy_hint);

    if (c == NULL)
    {
	pb_stream pre_sa_pbs = sa_pd->pbs;
	lset_t policy = preparse_isakmp_sa_body(&pre_sa_pbs);
	/*
	 * If there is XAUTH VID, copy it to policies.
	 */
	if (md->quirks.xauth_vid == TRUE)
	{
	  policy |= POLICY_XAUTH;
	}
	/* See if a wildcarded connection can be found.
	 * We cannot pick the right connection, so we're making a guess.
	 * All Road Warrior connections are fair game:
	 * we pick the first we come across (if any).
	 * If we don't find any, we pick the first opportunistic
	 * with the smallest subnet that includes the peer.
	 * There is, of course, no necessary relationship between
	 * an Initiator's address and that of its client,
	 * but Food Groups kind of assumes one.
	 */
	{
	    struct connection *d;
	    d = find_host_connection(ANY_MATCH, &md->iface->ip_addr, pluto_port500
                                     , KH_ANY
				     , (ip_address*)NULL
				     , md->sender_port, policy, POLICY_IKEV1_DISABLE, &policy_hint);

	    for (; d != NULL; d = d->IPhp_next)
	    {
		if (d->kind == CK_GROUP)
		{
		    /* ignore */
		}
		else
		{
		    if (d->kind == CK_TEMPLATE && !(d->policy & POLICY_OPPO))
		    {
			/* must be Road Warrior: we have a winner */
			c = d;
			break;
		    }

		    /* Opportunistic or Shunt: pick tightest match */
		    if (addrinsubnet(&md->sender, &d->spd.that.client)
		    && (c == NULL || !subnetinsubnet(&c->spd.that.client, &d->spd.that.client)))
			c = d;
		}
	    }
	}

	if (c == NULL)
	{
	    loglog(RC_LOG_SERIOUS, "initial Main Mode message received on %s:%u"
		" but no connection has been authorized%s%s"
		, ip_str(&md->iface->ip_addr), ntohs(portof(&md->iface->ip_addr))
		, (policy != LEMPTY) ? " with policy=" : ""
		, (policy != LEMPTY) ? bitnamesof(sa_policy_bit_names, policy) : "");

            if(policy_hint & POLICY_IKEV1_DISABLE) {
                md->note = INVALID_MAJOR_VERSION;
                return STF_FAIL;
            }

	    /* XXX notification is in order! */
	    return STF_IGNORE;
	}
	else if (c->kind != CK_TEMPLATE)
	{
	    loglog(RC_LOG_SERIOUS, "initial Main Mode message received on %s:%u"
		" but \"%s\" forbids connection"
		, ip_str(&md->iface->ip_addr), pluto_port500, c->name);
	    /* XXX notification is in order! */
	    return STF_IGNORE;
	}
	else
	{
	    /* Create a temporary connection that is a copy of this one.
	     * His ID isn't declared yet.
	     */
	   DBG(DBG_CONTROL, DBG_log("instantiating \"%s\" for initial Main Mode message received on %s:%u"
		, c->name, ip_str(&md->iface->ip_addr), pluto_port500));
	    c = rw_instantiate(c, &md->sender
			       , NULL, NULL);
	}
     } else {
	/* we found a non-wildcard conn. double check if it needs instantiation anyway (eg vnet=) */
	if ((c->kind == CK_TEMPLATE) && c->spd.that.virt) {
	   DBG(DBG_CONTROL, DBG_log("local endpoint has virt (vnet/vhost) set without wildcards - needs instantiation"));
	   c = rw_instantiate(c,&md->sender,NULL,NULL);
	}
    }

#ifdef XAUTH
    if(c->spd.this.xauth_server || c->spd.this.xauth_client)
    {
        numvidtosend++;
    }
#endif
    /* Set up state */
    md->st = st = new_state();
#ifdef XAUTH
    passert(st->st_oakley.xauth == 0);
#endif
    st->st_connection = c;
    st->st_remoteaddr = md->sender;
    st->st_remoteport = md->sender_port;
    st->st_localaddr  = md->iface->ip_addr;
    st->st_localport  = md->iface->port;
    st->st_interface  = md->iface;

    /* IKE version numbers -- used mostly in logging */
    st->st_ike_maj        = md->maj;
    st->st_ike_min        = md->min;

    set_cur_state(st);	/* (caller will reset cur_state) */
    st->st_try = 0;	/* not our job to try again from start */
    st->st_policy = c->policy & ~POLICY_IPSEC_MASK;	/* only as accurate as connection */
    change_state(st, STATE_MAIN_R0);

    memcpy(st->st_icookie, md->hdr.isa_icookie, COOKIE_SIZE);
    get_cookie(FALSE, st->st_rcookie, COOKIE_SIZE, &md->sender);

    insert_state(st);	/* needs cookies, connection, and msgid (0) */

    st->st_doi = ISAKMP_DOI_IPSEC;
    st->st_situation = SIT_IDENTITY_ONLY; /* We only support this */

    /* copy the quirks we might have accumulated */
    copy_quirks(&st->quirks,&md->quirks);

    if ((c->kind == CK_INSTANCE) && (c->spd.that.host_port_specific))
    {
       openswan_log("responding to Main Mode from unknown peer %s:%u"
	    , ip_str(&c->spd.that.host_addr), c->spd.that.host_port);
    }
    else if (c->kind == CK_INSTANCE)
    {
	openswan_log("responding to Main Mode from unknown peer %s"
	    , ip_str(&c->spd.that.host_addr));
    }
    else
    {
	openswan_log("responding to Main Mode");
    }

    /* parse_isakmp_sa also spits out a winning SA into our reply,
     * so we have to build our reply_stream and emit HDR before calling it.
     */

    /* HDR out.
     * We can't leave this to comm_handle() because we must
     * fill in the cookie.
     */
    zero(reply_buffer);
    init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer), "reply packet");
    {
	struct isakmp_hdr r_hdr = md->hdr;

	r_hdr.isa_flags &= ~ISAKMP_FLAG_COMMIT;	/* we won't ever turn on this bit */
	memcpy(r_hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
	r_hdr.isa_np = ISAKMP_NEXT_SA;
	if (!out_struct(&r_hdr, &isakmp_hdr_desc, &reply_stream, &md->rbody))
	    return STF_INTERNAL_ERROR;
    }

    /* start of SA out */
    {
	struct isakmp_sa r_sa = sa_pd->payload.sa;

	/* if we to send any VID, then set the NEXT payload correctly */
	r_sa.isasa_np = numvidtosend ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
	if (!out_struct(&r_sa, &isakmp_sa_desc, &md->rbody, &r_sa_pbs))
	    return STF_INTERNAL_ERROR;
    }

    /* SA body in and out */
    RETURN_STF_FAILURE(parse_isakmp_sa_body(&sa_pd->pbs, &sa_pd->payload.sa
					    , &r_sa_pbs, FALSE, st));

    if (SEND_PLUTO_VID || openpgp_peer)
    {
	char *vendorid = (openpgp_peer) ?
	    pgp_vendorid : pluto_vendorid;

	next = --numvidtosend ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
	if (!out_generic_raw(next, &isakmp_vendor_id_desc, &md->rbody
			     , vendorid, strlen(vendorid), "Vendor ID"))
	    return STF_INTERNAL_ERROR;
    }

    /*
     * NOW SEND VENDOR ID payloads
     */

    /* Announce our ability to do RFC 3706 Dead Peer Detection */
    next = --numvidtosend ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
    if( !out_vid(next, &md->rbody, VID_MISC_DPD))
      return STF_INTERNAL_ERROR;

#ifdef XAUTH
    /* If XAUTH is required, insert here Vendor ID */
    if(c->spd.this.xauth_server || c->spd.this.xauth_client)
    {
	    next = --numvidtosend ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
	    if (!out_vendorid(next, &md->rbody, VID_MISC_XAUTH))
	       return STF_INTERNAL_ERROR;
    }
#endif
#ifdef NAT_TRAVERSAL
    DBG(DBG_NATT, DBG_log("sender checking NAT-T: %d and %d"
				, nat_traversal_enabled
				, md->quirks.nat_traversal_vid));

    if (md->quirks.nat_traversal_vid && nat_traversal_enabled) {

        next = --numvidtosend ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
	/* reply if NAT-Traversal draft is supported */
	st->hidden_variables.st_nat_traversal = nat_traversal_vid_to_method(md->quirks.nat_traversal_vid);
	if ((st->hidden_variables.st_nat_traversal) && (!out_vendorid(next,
	    &md->rbody, md->quirks.nat_traversal_vid))) {
	    return STF_INTERNAL_ERROR;
	}
    }
#endif


#ifdef DEBUG
    /* if we are not 0 then something went very wrong above */
    if(numvidtosend != 0) {
	openswan_log("payload alignment problem please check the code in main_inI1_outR1 (num=%d)", numvidtosend);
    }
#endif

    close_message(&md->rbody);

    /* save initiator SA for HASH */
    clonereplacechunk(st->st_p1isa, sa_pd->pbs.start, pbs_room(&sa_pd->pbs), "sa in main_inI1_outR1()");

    return STF_OK;
}

/*
 * STATE_MAIN_I1: HDR, SA --> auth dependent
 * PSK_AUTH, DS_AUTH: --> HDR, KE, Ni
 *
 * We do heavy computation here. For Main Mode, this is mostly okay,
 * since have already done a return routeability check.
 *
 */

static stf_status
main_inR1_outI2_tail(struct pluto_crypto_req_cont *pcrc
		     , struct pluto_crypto_req *r);


static void
main_inR1_outI2_continue(struct pluto_crypto_req_cont *pcrc
			 , struct pluto_crypto_req *r
			 , err_t ugh)
{
    struct ke_continuation *ke = (struct ke_continuation *)pcrc;
    struct msg_digest *md = ke->md;
    struct state *const st = md->st;
    stf_status e;

    DBG(DBG_CONTROLMORE
	, DBG_log("main inR1_outI2: calculated ke+nonce, sending I2"));

    if (st == NULL) {
	loglog(RC_LOG_SERIOUS, "%s: Request was disconnected from state",
		__FUNCTION__);
	if (ke->md)
	    release_md(ke->md);
	return;
    }

    /* XXX should check out ugh */
    passert(ugh == NULL);
    passert(cur_state == NULL);
    passert(st != NULL);

    passert(st->st_suspended_md == ke->md);
    set_suspended(st, NULL);	/* no longer connected or suspended */

    set_cur_state(st);

    st->st_calculating = FALSE;

    e = main_inR1_outI2_tail(pcrc, r);

    if(ke->md != NULL) {
	complete_v1_state_transition(&ke->md, e);
	if(ke->md) release_md(ke->md);
    }

    reset_cur_state();
}

stf_status
main_inR1_outI2(struct msg_digest *md)
{
    struct state *const st = md->st;

    /* verify echoed SA */
    {
	struct payload_digest *const sapd = md->chain[ISAKMP_NEXT_SA];

	RETURN_STF_FAILURE(parse_isakmp_sa_body(&sapd->pbs
						, &sapd->payload.sa
						, NULL, TRUE, st));
    }

#ifdef NAT_TRAVERSAL
    DBG(DBG_NATT, DBG_log("sender checking NAT-T: %d and %d"
				 , nat_traversal_enabled
				 , md->quirks.nat_traversal_vid))

    if (nat_traversal_enabled && md->quirks.nat_traversal_vid) {
	st->hidden_variables.st_nat_traversal = nat_traversal_vid_to_method(md->quirks.nat_traversal_vid);
	openswan_log("enabling possible NAT-traversal with method %s"
	     , bitnamesof(natt_type_bitnames, st->hidden_variables.st_nat_traversal));
    }
#endif

    {
	struct ke_continuation *ke = alloc_thing(struct ke_continuation
						 , "outI2 KE");
	ke->md = md;

	passert(st->st_sec_in_use==FALSE);
	pcrc_init(&ke->ke_pcrc);
	ke->ke_pcrc.pcrc_func = main_inR1_outI2_continue;
	set_suspended(st, md);
	return build_ke(&ke->ke_pcrc, st, st->st_oakley.group, st->st_import);
    }
}

/*
 * package up the calculate KE value, and emit it as a KE payload.
 * used by IKEv1: main, aggressive, and quick (in PFS mode).
 */
bool
justship_KE(chunk_t *g
	    , pb_stream *outs, u_int8_t np)
{
    return out_generic_chunk(np, &isakmp_keyex_desc, outs, *g, "keyex value");
}

bool
ship_KE(struct state *st
	, struct pluto_crypto_req *r
	, chunk_t *g
	, pb_stream *outs, u_int8_t np)
{
    unpack_KE(st, r, g);
    return justship_KE(g, outs, np);
}

/* STATE_MAIN_I1: HDR, SA --> auth dependent
 * PSK_AUTH, DS_AUTH: --> HDR, KE, Ni
 *
 * The following are not yet implemented:
 * PKE_AUTH: --> HDR, KE, [ HASH(1), ] <IDi1_b>PubKey_r, <Ni_b>PubKey_r
 * RPKE_AUTH: --> HDR, [ HASH(1), ] <Ni_b>Pubkey_r, <KE_b>Ke_i,
 *                <IDi1_b>Ke_i [,<<Cert-I_b>Ke_i]
 *
 * We must verify that the proposal received matches one we sent.
 */
static stf_status
main_inR1_outI2_tail(struct pluto_crypto_req_cont *pcrc
		     , struct pluto_crypto_req *r)
{
    struct ke_continuation *ke = (struct ke_continuation *)pcrc;
    struct msg_digest *md = ke->md;
    struct state *const st = md->st;

    /**************** build output packet HDR;KE;Ni ****************/
    init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer), "reply packet");

    /* HDR out.
     * We can't leave this to comm_handle() because the isa_np
     * depends on the type of Auth (eventually).
     */
    echo_hdr(md, FALSE, ISAKMP_NEXT_KE);

    /* KE out */
    if (!ship_KE(st, r , &st->st_gi
		 , &md->rbody, ISAKMP_NEXT_NONCE))
	return STF_INTERNAL_ERROR;

#ifdef DEBUG
    /* Ni out */
    if (!ship_nonce(&st->st_ni, r, &md->rbody
		    , (cur_debugging & IMPAIR_BUST_MI2)? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE
		    , "Ni"))
	return STF_INTERNAL_ERROR;

    if (cur_debugging & IMPAIR_BUST_MI2)
    {
	/* generate a pointless large VID payload to push message over MTU */
	pb_stream vid_pbs;

	if (!out_generic(ISAKMP_NEXT_NONE, &isakmp_vendor_id_desc, &md->rbody
	    , &vid_pbs))
	    return STF_INTERNAL_ERROR;
	if (!out_zero(1500 /*MTU?*/, &vid_pbs, "Filler VID"))
	    return STF_INTERNAL_ERROR;
	close_output_pbs(&vid_pbs);
    }
#else
    /* Ni out */
    if (!ship_nonce(&st->st_ni, r, &md->rbody, ISAKMP_NEXT_NONE, "Ni"))
	return STF_INTERNAL_ERROR;
#endif

#ifdef NAT_TRAVERSAL
    DBG(DBG_NATT, DBG_log("NAT-T checking st_nat_traversal for NAT_T_WITH_NATD"));
    if (st->hidden_variables.st_nat_traversal & NAT_T_WITH_NATD) {
        DBG(DBG_NATT, DBG_log("NAT-T found NAT_T_WITH_NATD"));
	if (!nat_traversal_add_natd(ISAKMP_NEXT_NONE, &md->rbody, md))
	    return STF_INTERNAL_ERROR;
    }
#endif

    /* finish message */
    close_message(&md->rbody);

    /* Reinsert the state, using the responder cookie we just received */
    unhash_state(st);
    memcpy(st->st_rcookie, md->hdr.isa_rcookie, COOKIE_SIZE);
    insert_state(st);	/* needs cookies, connection, and msgid (0) */

    return STF_OK;
}

/* STATE_MAIN_R1:
 * PSK_AUTH, DS_AUTH: HDR, KE, Ni --> HDR, KE, Nr
 *
 * The following are not yet implemented:
 * PKE_AUTH: HDR, KE, [ HASH(1), ] <IDi1_b>PubKey_r, <Ni_b>PubKey_r
 *	    --> HDR, KE, <IDr1_b>PubKey_i, <Nr_b>PubKey_i
 * RPKE_AUTH:
 *	    HDR, [ HASH(1), ] <Ni_b>Pubkey_r, <KE_b>Ke_i, <IDi1_b>Ke_i [,<<Cert-I_b>Ke_i]
 *	    --> HDR, <Nr_b>PubKey_i, <KE_b>Ke_r, <IDr1_b>Ke_r
 */
static stf_status
main_inI2_outR2_tail(struct pluto_crypto_req_cont *pcrc
		     , struct pluto_crypto_req *r);

static void
main_inI2_outR2_continue(struct pluto_crypto_req_cont *pcrc
			 , struct pluto_crypto_req *r
			 , err_t ugh)
{
    struct ke_continuation *ke = (struct ke_continuation *)pcrc;
    struct msg_digest *md = ke->md;
    struct state *const st = md->st;
    stf_status e;

    DBG(DBG_CONTROLMORE
	, DBG_log("main inI2_outR2: calculated ke+nonce, sending R2"));

    if (st == NULL) {
	loglog(RC_LOG_SERIOUS, "%s: Request was disconnected from state",
		__FUNCTION__);
	if (ke->md)
	    release_md(ke->md);
	return;
    }

    /* XXX should check out ugh */
    passert(ugh == NULL);
    passert(cur_state == NULL);
    passert(st != NULL);

    passert(st->st_suspended_md == ke->md);
    set_suspended(st, NULL);	/* no longer connected or suspended */

    set_cur_state(st);

    st->st_calculating = FALSE;
    e = main_inI2_outR2_tail(pcrc, r);

    if(ke->md != NULL) {
        complete_v1_state_transition(&ke->md, e);
        if(ke->md) release_md(ke->md);
    }
    reset_cur_state();
}

stf_status
main_inI2_outR2(struct msg_digest *md)
{
    struct state *const st = md->st;
    pb_stream *keyex_pbs = &md->chain[ISAKMP_NEXT_KE]->pbs;
    /* KE in */
    RETURN_STF_FAILURE(accept_KE(&st->st_gi, "Gi"
				 , st->st_oakley.group, keyex_pbs));

    /* Ni in */
    RETURN_STF_FAILURE(accept_v1_nonce(md, &st->st_ni, "Ni"));

    /* decode certificate requests */
    decode_cr(md, &st->st_connection->requested_ca);

    if(st->st_connection->requested_ca != NULL)
    {
	st->hidden_variables.st_got_certrequest = TRUE;
    }


#ifdef NAT_TRAVERSAL
    DBG(DBG_NATT
	, DBG_log("inI2: checking NAT-T: %d and %d"
		  , nat_traversal_enabled
		  , st->hidden_variables.st_nat_traversal));

    if (st->hidden_variables.st_nat_traversal & NAT_T_WITH_NATD) {
       DBG(DBG_NATT, DBG_log(" NAT_T_WITH_NATD detected"));
       nat_traversal_natd_lookup(md);
    }
    if (st->hidden_variables.st_nat_traversal) {
       nat_traversal_show_result(st->hidden_variables.st_nat_traversal
				 , md->sender_port);
    }
    if (st->hidden_variables.st_nat_traversal & NAT_T_WITH_KA) {
       DBG(DBG_NATT, DBG_log(" NAT_T_WITH_KA detected"));
       nat_traversal_new_ka_event();
    }
#endif

    {
	struct ke_continuation *ke = alloc_thing(struct ke_continuation
					     , "inI2_outR2 KE");

	ke->md = md;
	set_suspended(st, md);

	passert(st->st_sec_in_use == FALSE);
	pcrc_init(&ke->ke_pcrc);
	ke->ke_pcrc.pcrc_func = main_inI2_outR2_continue;
	return build_ke(&ke->ke_pcrc, st
			, st->st_oakley.group, st->st_import);
    }
}


static void
main_inI2_outR2_calcdone(struct pluto_crypto_req_cont *pcrc
			 , struct pluto_crypto_req *r
			 , err_t ugh)
{
    struct dh_continuation *dh = (struct dh_continuation *)pcrc;
    struct state *st;

    DBG(DBG_CONTROLMORE
	, DBG_log("main inI2_outR2: calculated DH finished"));

    st = state_with_serialno(dh->serialno);
    if(st == NULL) {
	openswan_log("state %ld disappeared during crypto\n", dh->serialno);
	return;
    }

    set_cur_state(st);
    if(ugh) {
	loglog(RC_LOG_SERIOUS, "DH crypto failed: %s\n", ugh);
	return;
    }

    finish_dh_secretiv(st, r);
    if(!r->pcr_success) {
        loglog(RC_LOG_SERIOUS, "DH crypto failed, invalid keys");
        return;
    }

    st->hidden_variables.st_skeyid_calculated = TRUE;
    update_iv(st);
    /* XXX: Do we need to free dh here? If so, how about the other exits?
     * pfree(dh); dh = NULL;
     */

    /*
     * if there was a packet received while we were calculating, then
     * process it now.
     */
    if(st->st_suspended_md != NULL) {
	struct msg_digest *md = st->st_suspended_md;

	set_suspended(st, NULL);
	process_packet_tail(&md);
	if(md != NULL) {
	    release_md(md);
	}
    }
    reset_cur_state();
    return;
}

/*
 * this routine gets called after any DH exponentiation that needs to be done
 * has been done, and we are ready to send our g^y.
 */
stf_status
main_inI2_outR2_tail(struct pluto_crypto_req_cont *pcrc
		     , struct pluto_crypto_req *r)
{
    struct ke_continuation *ke = (struct ke_continuation *)pcrc;
    struct msg_digest *md = ke->md;
    struct state *st = md->st;

    /* send CR if auth is RSA and no preloaded RSA public key exists*/
    bool send_cr = FALSE;

    /**************** build output packet HDR;KE;Nr ****************/

    send_cr = !no_cr_send
	&& (st->st_oakley.auth == OAKLEY_RSA_SIG)
	&& !has_preloaded_public_key(st)
	&& st->st_connection->spd.that.ca.ptr != NULL;

    /* HDR out */
    echo_hdr(md, FALSE, ISAKMP_NEXT_KE);

    /* KE out */
    if (!ship_KE(st, r, &st->st_gr
		 , &md->rbody, ISAKMP_NEXT_NONCE))
	{
	    osw_abort();
	return STF_INTERNAL_ERROR;
	}

#ifdef DEBUG
 {
    /* Nr out */
    int next_payload;
    next_payload = ISAKMP_NEXT_NONE;

    if(cur_debugging & IMPAIR_BUST_MR2)
    {
	next_payload = ISAKMP_NEXT_VID;
    }
    if(send_cr)
    {
        next_payload = ISAKMP_NEXT_CR;
    }
    if (!ship_nonce(&st->st_nr, r
		    , &md->rbody
		    , next_payload
		    , "Nr"))
	return STF_INTERNAL_ERROR;

    if (cur_debugging & IMPAIR_BUST_MR2)
    {
	/* generate a pointless large VID payload to push message over MTU */
	pb_stream vid_pbs;

	if (!out_generic((send_cr)? ISAKMP_NEXT_CR : ISAKMP_NEXT_NONE,
	    &isakmp_vendor_id_desc, &md->rbody, &vid_pbs))
	    return STF_INTERNAL_ERROR;
	if (!out_zero(1500 /*MTU?*/, &vid_pbs, "Filler VID"))
	    return STF_INTERNAL_ERROR;
	close_output_pbs(&vid_pbs);
    }
 }
#else
    /* Nr out */
    if (!ship_nonce(&st->st_nr, r
		    , &md->rbody
		    , (send_cr)? ISAKMP_NEXT_CR : ISAKMP_NEXT_NONE
		    , "Nr"))
	return STF_INTERNAL_ERROR;
#endif

    /* CR out */
    if (send_cr)
    {
	if (st->st_connection->kind == CK_PERMANENT)
	{
	    if (!build_and_ship_CR(CERT_X509_SIGNATURE
				   , st->st_connection->spd.that.ca
				   , &md->rbody, ISAKMP_NEXT_NONE))
		return STF_INTERNAL_ERROR;
	}
	else
	{
	    generalName_t *ca = NULL;

	    if (collect_rw_ca_candidates(md, &ca))
	    {
		generalName_t *gn;

		for (gn = ca; gn != NULL; gn = gn->next)
		{
		    if (!build_and_ship_CR(CERT_X509_SIGNATURE, gn->name
		    , &md->rbody
		    , gn->next == NULL ? ISAKMP_NEXT_NONE : ISAKMP_NEXT_CR))
			return STF_INTERNAL_ERROR;
		}
		free_generalNames(ca, FALSE);
	    }
	    else
	    {
		if (!build_and_ship_CR(CERT_X509_SIGNATURE, empty_chunk
		, &md->rbody, ISAKMP_NEXT_NONE))
		    return STF_INTERNAL_ERROR;
	    }
	}
    }

#ifdef NAT_TRAVERSAL
    if (st->hidden_variables.st_nat_traversal & NAT_T_WITH_NATD) {
	if (!nat_traversal_add_natd(ISAKMP_NEXT_NONE, &md->rbody, md))
	    return STF_INTERNAL_ERROR;
    }
#endif

    /* finish message */
    close_message(&md->rbody);

    /*
     * next message will be encrypted, so, we need to have
     * the DH value calculated. We can do this in the background,
     * sending the reply right away. We have to be careful on the next
     * state, since the other end may reply faster than we can calculate
     * things. If it is the case, then the packet is placed in the
     * continuation, and we let the continuation process it. If there
     * is a retransmit, we keep only the last packet.
     *
     * Also, note that this is not a suspended state, since we are
     * actually just doing work in the background.
     *
     */
    {
    /* Looks like we missed perform_dh() declared at
     * programs/pluto/pluto_crypt.h as external and implemented nowhere.
     * Following code regarding dh_continuation allocation seems useless
     * as it's never used. At least, we should free it.
     */
	struct dh_continuation *dh = alloc_thing(struct dh_continuation
						 , "main_inI2_outR2_tail");
	stf_status e;

	dh->md = NULL;
	dh->serialno = st->st_serialno;
	pcrc_init(&dh->dh_pcrc);
	dh->dh_pcrc.pcrc_func = main_inI2_outR2_calcdone;
	passert(st->st_suspended_md == NULL);

	DBG(DBG_CONTROLMORE
	    , DBG_log("main inI2_outR2: starting async DH calculation (group=%d)", st->st_oakley.group->group));

	e = start_dh_secretiv(&dh->dh_pcrc, st
			      , st->st_import
			      , RESPONDER
			      , st->st_oakley.group->group);

	DBG(DBG_CONTROLMORE,
	    DBG_log("started dh_secretiv, returned: stf=%s\n"
		    , enum_name(&stfstatus_name, e)));

	if(e == STF_FAIL) {
	    loglog(RC_LOG_SERIOUS, "failed to start async DH calculation, stf=%s\n"
		   , enum_name(&stfstatus_name, e));
	    return e;
	}

	/* we are calculating in the background, so it doesn't count */
	if(e == STF_SUSPEND) {
	    st->st_calculating = FALSE;
	}
    }
    return STF_OK;
}

static void
doi_log_cert_thinking(struct msg_digest *md UNUSED
		      , u_int16_t auth
		      , enum ipsec_cert_type certtype
		      , enum certpolicy policy
		      , bool gotcertrequest
		      , bool send_cert)
{
    DBG(DBG_CONTROL
	, DBG_log("thinking about whether to send my certificate:"));

    DBG(DBG_CONTROL
	, DBG_log("  I have RSA key: %s cert.type: %s "
		  , enum_show(&oakley_auth_names, auth)
		  , enum_show(&cert_type_names, certtype)));

    DBG(DBG_CONTROL
	, DBG_log("  sendcert: %s and I did%s get a certificate request "
		  , enum_show(&certpolicy_type_names, policy)
		  , gotcertrequest ? "" : " not"));

    DBG(DBG_CONTROL
	, DBG_log("  so %ssend cert.", send_cert ? "" : "do not "));

    if(!send_cert) {
	if(auth == OAKLEY_PRESHARED_KEY) {
	    DBG(DBG_CONTROL, DBG_log("I did not send a certificate because digital signatures are not being used. (PSK)"));
	} else if(certtype == CERT_NONE) {
	    DBG(DBG_CONTROL, DBG_log("I did not send a certificate because I do not have one."));
	} else if(policy == cert_sendifasked) {
	    DBG(DBG_CONTROL, DBG_log("I did not send my certificate because I was not asked to."));
	}
    }
}

/* STATE_MAIN_I2:
 * SMF_PSK_AUTH: HDR, KE, Nr --> HDR*, IDi1, HASH_I
 * SMF_DS_AUTH: HDR, KE, Nr --> HDR*, IDi1, [ CERT, ] SIG_I
 *
 * The following are not yet implemented.
 * SMF_PKE_AUTH: HDR, KE, <IDr1_b>PubKey_i, <Nr_b>PubKey_i
 *	    --> HDR*, HASH_I
 * SMF_RPKE_AUTH: HDR, <Nr_b>PubKey_i, <KE_b>Ke_r, <IDr1_b>Ke_r
 *	    --> HDR*, HASH_I
 */
static stf_status
main_inR2_outI3_continue(struct msg_digest *md
			 , struct pluto_crypto_req *r)
{
    struct state *const st = md->st;
    int auth_payload = st->st_oakley.auth == OAKLEY_PRESHARED_KEY
	? ISAKMP_NEXT_HASH : ISAKMP_NEXT_SIG;
    pb_stream id_pbs;	/* ID Payload; also used for hash calculation */
    bool send_cert = FALSE;
    bool send_cr = FALSE;
    generalName_t *requested_ca = NULL;
    cert_t mycert = st->st_connection->spd.this.cert;

    finish_dh_secretiv(st, r);
    if(!r->pcr_success) {
        return STF_FAIL + INVALID_KEY_INFORMATION;
    }

    /* decode certificate requests */
    decode_cr(md, &requested_ca);

    if(requested_ca != NULL)
    {
	st->hidden_variables.st_got_certrequest = TRUE;
    }

    /*
     * send certificate if we have one and auth is RSA, and we were
     * told we can send one if asked, and we were asked, or we were told
     * to always send one.
     */
    send_cert = st->st_oakley.auth == OAKLEY_RSA_SIG
	&& mycert.type != CERT_NONE
	&& ((st->st_connection->spd.this.sendcert == cert_sendifasked
	     && st->hidden_variables.st_got_certrequest)
	    || st->st_connection->spd.this.sendcert==cert_alwayssend
	    || st->st_connection->spd.this.sendcert==cert_forcedtype);

    doi_log_cert_thinking(md
			  , st->st_oakley.auth
			  , mycert.type
			  , st->st_connection->spd.this.sendcert
			  , st->hidden_variables.st_got_certrequest
			  , send_cert);

    /* send certificate request, if we don't have a preloaded RSA public key */
    send_cr = !no_cr_send && send_cert && !has_preloaded_public_key(st);

    DBG(DBG_CONTROL
	, DBG_log(" I am %ssending a certificate request"
		  , send_cr ? "" : "not "));

    /*
     * free collected certificate requests since as initiator
     * we don't heed them anyway
     */
    free_generalNames(requested_ca, TRUE);

    /* done parsing; initialize crypto  */

#ifdef NAT_TRAVERSAL
    if (st->hidden_variables.st_nat_traversal & NAT_T_WITH_NATD) {
      nat_traversal_natd_lookup(md);
    }
    if (st->hidden_variables.st_nat_traversal) {
      nat_traversal_show_result(st->hidden_variables.st_nat_traversal
				, md->sender_port);
    }
    if (st->hidden_variables.st_nat_traversal & NAT_T_WITH_KA) {
      nat_traversal_new_ka_event();
    }
#endif

    /*************** build output packet HDR*;IDii;HASH/SIG_I ***************/
    /* ??? NOTE: this is almost the same as main_inI3_outR3's code */

    /* HDR* out done */

    /* IDii out */
    {
	struct isakmp_ipsec_id id_hd;
	chunk_t id_b;

	build_id_payload(&id_hd, &id_b, &st->st_connection->spd.this);
	id_hd.isaiid_np = (send_cert)? ISAKMP_NEXT_CERT : auth_payload;
	if (!out_struct(&id_hd
			, &isakmp_ipsec_identification_desc
			, &md->rbody
			, &id_pbs)
	    || !out_chunk(id_b, &id_pbs, "my identity"))
	    return STF_INTERNAL_ERROR;
	close_output_pbs(&id_pbs);
    }

    /* CERT out */
    if (send_cert)
    {
	pb_stream cert_pbs;

	struct isakmp_cert cert_hd;
	cert_hd.isacert_np = (send_cr)? ISAKMP_NEXT_CR : ISAKMP_NEXT_SIG;
	cert_hd.isacert_type = mycert.type;

	openswan_log("I am sending my cert");

	if (!out_struct(&cert_hd
			, &isakmp_ipsec_certificate_desc
			, &md->rbody
			, &cert_pbs))
	    return STF_INTERNAL_ERROR;

	if(mycert.forced) {
	  if (!out_chunk(mycert.u.blob, &cert_pbs, "forced CERT"))
	    return STF_INTERNAL_ERROR;
	} else {
	  if (!out_chunk(get_mycert(mycert), &cert_pbs, "CERT"))
	    return STF_INTERNAL_ERROR;
	}
	close_output_pbs(&cert_pbs);
    }

    /* CR out */
    if (send_cr)
    {
	openswan_log("I am sending a certificate request");
	if (!build_and_ship_CR(mycert.type
			       , st->st_connection->spd.that.ca
			       , &md->rbody, ISAKMP_NEXT_SIG))
	    return STF_INTERNAL_ERROR;
    }

#ifdef TPM
    {
	pb_stream *pbs = &md->rbody;
	size_t enc_len = pbs_offset(pbs) - sizeof(struct isakmp_hdr);

	TCLCALLOUT_crypt("preHash", st,pbs,sizeof(struct isakmp_hdr),enc_len);

	/* find location of ID PBS */
	tpm_findID(pbs, &id_pbs);
    }
#endif

    /* HASH_I or SIG_I out */
    {
	u_char hash_val[MAX_DIGEST_LEN];
	size_t hash_len = main_mode_hash(st, hash_val, TRUE, &id_pbs);

	if (auth_payload == ISAKMP_NEXT_HASH)
	{
	    /* HASH_I out */
	    if (!out_generic_raw(ISAKMP_NEXT_NONE
				 , &isakmp_hash_desc
				 , &md->rbody
				 , hash_val, hash_len, "HASH_I"))
		return STF_INTERNAL_ERROR;
	}
	else
	{
	    /* SIG_I out */
	    u_char sig_val[RSA_MAX_OCTETS];
	    size_t sig_len = RSA_sign_hash(st->st_connection
		, sig_val, hash_val, hash_len);

	    if (sig_len == 0)
	    {
		loglog(RC_LOG_SERIOUS, "unable to locate my private key for RSA Signature");
		return STF_FAIL + AUTHENTICATION_FAILED;
	    }

	    if (!out_generic_raw(ISAKMP_NEXT_NONE
				 , &isakmp_signature_desc
				 , &md->rbody
				 , sig_val
				 , sig_len
				 , "SIG_I"))
		return STF_INTERNAL_ERROR;
	}
    }

    /* encrypt message, except for fixed part of header */

    /* st_new_iv was computed by generate_skeyids_iv */
    if (!encrypt_message(&md->rbody, st))
	return STF_INTERNAL_ERROR;	/* ??? we may be partly committed */

    return STF_OK;
}

static void
main_inR2_outI3_cryptotail(struct pluto_crypto_req_cont *pcrc
			   , struct pluto_crypto_req *r
			   , err_t ugh)
{
  struct dh_continuation *dh = (struct dh_continuation *)pcrc;
  struct msg_digest *md = dh->md;
  struct state *const st = md->st;
  stf_status e;

  DBG(DBG_CONTROLMORE
      , DBG_log("main inR2_outI3: calculated DH, sending R1"));

  if (st == NULL) {
      loglog(RC_LOG_SERIOUS, "%s: Request was disconnected from state",
	      __FUNCTION__);
      if (dh->md)
          release_md(dh->md);
      return;
  }

  passert(cur_state == NULL);
  passert(st != NULL);

  passert(st->st_suspended_md == dh->md);
  set_suspended(st, NULL);	/* no longer connected or suspended */

  set_cur_state(st);
  st->st_calculating = FALSE;

  if(ugh) {
      loglog(RC_LOG_SERIOUS, "failed in DH exponentiation: %s", ugh);
      e = STF_FATAL;
  } else {
      e = main_inR2_outI3_continue(md, r);
  }

  if(dh->md != NULL) {
      complete_v1_state_transition(&dh->md, e);
      if(dh->md) release_md(dh->md);
  }
  reset_cur_state();
}

stf_status
main_inR2_outI3(struct msg_digest *md)
{
    struct dh_continuation *dh;
    pb_stream *const keyex_pbs = &md->chain[ISAKMP_NEXT_KE]->pbs;
    struct state *const st = md->st;

    /* KE in */
    RETURN_STF_FAILURE(accept_KE(&st->st_gr, "Gr"
				 , st->st_oakley.group, keyex_pbs));

    /* Nr in */
    RETURN_STF_FAILURE(accept_v1_nonce(md, &st->st_nr, "Nr"));

    dh = alloc_thing(struct dh_continuation, "aggr outR1 DH");
    if(!dh) { return STF_FATAL; }

    dh->md = md;
    set_suspended(st, md);
    pcrc_init(&dh->dh_pcrc);
    dh->dh_pcrc.pcrc_func = main_inR2_outI3_cryptotail;
    return start_dh_secretiv(&dh->dh_pcrc, st
			     , st->st_import
			     , INITIATOR
			     , st->st_oakley.group->group);
}



/* Shared logic for asynchronous lookup of DNS KEY records.
 * Used for STATE_MAIN_R2 and STATE_MAIN_I3.
 */

static void
report_key_dns_failure(struct id *id, err_t ugh)
{
    char id_buf[IDTOA_BUF];	/* arbitrary limit on length of ID reported */

    (void) idtoa(id, id_buf, sizeof(id_buf));
    loglog(RC_LOG_SERIOUS, "no RSA public key known for '%s'"
	"; DNS search for KEY failed (%s)", id_buf, ugh);
}


/* Processs the Main Mode ID Payload and the Authenticator
 * (Hash or Signature Payload).
 * If a DNS query is still needed to get the other host's public key,
 * the query is initiated and STF_SUSPEND is returned.
 * Note: parameter kc is a continuation containing the results from
 * the previous DNS query, or NULL indicating no query has been issued.
 */
stf_status
oakley_id_and_auth(struct msg_digest *md
		 , bool initiator	/* are we the Initiator? */
		 , bool aggrmode                /* aggressive mode? */
		 , cont_fn_t cont_fn	/* continuation function */
		 , const struct key_continuation *kc	/* current state, can be NULL */
)
{
    struct state *st = md->st;
    u_char hash_val[MAX_DIGEST_LEN];
    size_t hash_len;
    stf_status r = STF_OK;

    /* ID Payload in.
     * Note: this may switch the connection being used!
     */
    if (!aggrmode && !decode_peer_id(md, initiator, FALSE))
	return STF_FAIL + INVALID_ID_INFORMATION;

    /* Hash the ID Payload.
     * main_mode_hash requires idpl->cur to be at end of payload
     * so we temporarily set if so.
     */
    {
	pb_stream *idpl = &md->chain[ISAKMP_NEXT_ID]->pbs;
	u_int8_t *old_cur = idpl->cur;

	idpl->cur = idpl->roof;
	hash_len = main_mode_hash(st, hash_val, !initiator, idpl);
	idpl->cur = old_cur;
    }

    switch (st->st_oakley.auth)
    {
    case OAKLEY_PRESHARED_KEY:
	{
	    pb_stream *const hash_pbs = &md->chain[ISAKMP_NEXT_HASH]->pbs;

	    if (pbs_left(hash_pbs) != hash_len
	    || memcmp(hash_pbs->cur, hash_val, hash_len) != 0)
	    {
		DBG_cond_dump(DBG_CRYPT, "received HASH:"
		    , hash_pbs->cur, pbs_left(hash_pbs));
		loglog(RC_LOG_SERIOUS, "received Hash Payload does not match computed value");
		/* XXX Could send notification back */
		r = STF_FAIL + INVALID_HASH_INFORMATION;
	    }
	}
	break;

    case OAKLEY_RSA_SIG:
	r = RSA_check_signature(st, hash_val, hash_len
	    , &md->chain[ISAKMP_NEXT_SIG]->pbs
#ifdef USE_KEYRR
	    , kc == NULL? NULL : kc->ac.keys_from_dns
#endif /* USE_KEYRR */
	    , kc == NULL? NULL : kc->ac.gateways_from_dns
	    );

	if (r == STF_SUSPEND)
	{
	    /* initiate/resume asynchronous DNS lookup for key */
	    struct key_continuation *nkc
		= alloc_thing(struct key_continuation, "key continuation");
	    enum key_oppo_step step_done = kc == NULL? kos_null : kc->step;
	    err_t ugh;

	    /* Record that state is used by a suspended md */
	    passert(st->st_suspended_md == NULL);
	    set_suspended(st,md);

	    nkc->failure_ok = FALSE;
	    nkc->md = md;

	    switch (step_done)
	    {
	    case kos_null:
		/* first try: look for the TXT records */
		nkc->step = kos_his_txt;
#ifdef USE_KEYRR
		nkc->failure_ok = TRUE;
#endif
		ugh = start_adns_query(&st->st_connection->spd.that.id
				       , &st->st_connection->spd.that.id	/* SG itself */
				       , ns_t_txt
				       , cont_fn
				       , &nkc->ac);
		break;

#ifdef USE_KEYRR
	    case kos_his_txt:
		/* second try: look for the KEY records */
		nkc->step = kos_his_key;
		ugh = start_adns_query(&st->st_connection->spd.that.id
				       , NULL	/* no sgw for KEY */
				       , ns_t_key
				       , cont_fn
				       , &nkc->ac);
		break;
#endif /* USE_KEYRR */

	    default:
		bad_case(step_done);
	    }

	    if (ugh != NULL)
	    {
		report_key_dns_failure(&st->st_connection->spd.that.id, ugh);
		set_suspended(st, NULL);
		r = STF_FAIL + INVALID_KEY_INFORMATION;
	    } else {
		/*
		 * since this state is waiting for a DNS query, delete
		 * any events that might kill it.
		 */
		delete_event(st);
	    }
	}
	break;

    default:
	bad_case(st->st_oakley.auth);
    }
    if (r == STF_OK)
	DBG(DBG_CRYPT, DBG_log("authentication succeeded"));
    return r;
}

/* This continuation is called as part of either
 * the main_inI3_outR3 state or main_inR3 state.
 *
 * The "tail" function is the corresponding tail
 * function main_inI3_outR3_tail | main_inR3_tail,
 * either directly when the state is started, or via
 * adns continuation.
 *
 * Basically, we go around in a circle:
 *   main_in?3* -> key_continue
 *                ^            \
 *               /              V
 *             adns            main_in?3*_tail
 *              ^               |
 *               \              V
 *                main_id_and_auth
 *
 * until such time as main_id_and_auth is able
 * to find authentication, or we run out of things
 * to try.
 */
void
key_continue(struct adns_continuation *cr
	     , err_t ugh
	     , key_tail_fn *tail)
{
    struct key_continuation *kc = (void *)cr;
    struct msg_digest *md = kc->md;
    struct state *st;

    if(md == NULL) {
	return;
    }

    st= md->st;

    passert(cur_state == NULL);

    /* if st == NULL, our state has been deleted -- just clean up */
    if (st != NULL && st->st_suspended_md != NULL)
    {
	stf_status r;

	passert(st->st_suspended_md == kc->md);
	set_suspended(st,NULL);	/* no longer connected or suspended */
	cur_state = st;

	/* cancel any DNS event, since we got an anwer */
	delete_event(st);

	if (!kc->failure_ok && ugh != NULL)
	{
	    report_key_dns_failure(&st->st_connection->spd.that.id, ugh);
	    r = STF_FAIL + INVALID_KEY_INFORMATION;
	}
	else
	{

#ifdef USE_KEYRR
	    passert(kc->step == kos_his_txt || kc->step == kos_his_key);
#else
	    passert(kc->step == kos_his_txt);
#endif
	    kc->last_ugh = ugh;	/* record previous error in case we need it */
	    r = (*tail)(kc->md, kc);
	}
	complete_v1_state_transition(&kc->md, r);
    }
    if (kc->md != NULL)
	release_md(kc->md);
    cur_state = NULL;
}

/* STATE_MAIN_R2:
 * PSK_AUTH: HDR*, IDi1, HASH_I --> HDR*, IDr1, HASH_R
 * DS_AUTH: HDR*, IDi1, [ CERT, ] SIG_I --> HDR*, IDr1, [ CERT, ] SIG_R
 * PKE_AUTH, RPKE_AUTH: HDR*, HASH_I --> HDR*, HASH_R
 *
 * Broken into parts to allow asynchronous DNS lookup.
 *
 * - main_inI3_outR3 to start
 * - main_inI3_outR3_tail to finish or suspend for DNS lookup
 * - main_inI3_outR3_continue to start main_inI3_outR3_tail again
 */
static key_tail_fn main_inI3_outR3_tail;	/* forward */

stf_status
main_inI3_outR3(struct msg_digest *md)
{
    return main_inI3_outR3_tail(md, NULL);
}

static inline stf_status
main_id_and_auth(struct msg_digest *md
		 , bool initiator	/* are we the Initiator? */
		 , cont_fn_t cont_fn	/* continuation function */
		 , struct key_continuation *kc) /* argument */
{
    return oakley_id_and_auth(md, initiator, FALSE, cont_fn, kc);
}

static void
main_inI3_outR3_continue(struct adns_continuation *cr, err_t ugh)
{
    key_continue(cr, ugh, main_inI3_outR3_tail);
}

static stf_status
main_inI3_outR3_tail(struct msg_digest *md
, struct key_continuation *kc)
{
    struct state *const st = md->st;
    u_int8_t auth_payload;
    pb_stream r_id_pbs;	/* ID Payload; also used for hash calculation */
    cert_t mycert;
    bool send_cert;
    unsigned int np;

    /* ID and HASH_I or SIG_I in
     * Note: this may switch the connection being used!
     */
    {
	stf_status r = main_id_and_auth(md, FALSE
					, main_inI3_outR3_continue
					, kc);

	if (r != STF_OK)
	    return r;
    }

    /* send certificate if we have one and auth is RSA */
    mycert = st->st_connection->spd.this.cert;

    send_cert = st->st_oakley.auth == OAKLEY_RSA_SIG
	&& mycert.type != CERT_NONE
	&& ((st->st_connection->spd.this.sendcert == cert_sendifasked
	     && st->hidden_variables.st_got_certrequest)
	    || st->st_connection->spd.this.sendcert==cert_alwayssend);

    doi_log_cert_thinking(md
			  , st->st_oakley.auth
			  , mycert.type
			  , st->st_connection->spd.this.sendcert
			  , st->hidden_variables.st_got_certrequest
			  , send_cert);

    /*************** build output packet HDR*;IDir;HASH/SIG_R ***************/
    /* proccess_packet() would automatically generate the HDR*
     * payload if smc->first_out_payload is not ISAKMP_NEXT_NONE.
     * We don't do this because we wish there to be no partially
     * built output packet if we need to suspend for asynch DNS.
     */
    /* ??? NOTE: this is almost the same as main_inR2_outI3's code */

    /* HDR* out
     * If auth were PKE_AUTH or RPKE_AUTH, ISAKMP_NEXT_HASH would
     * be first payload.
     */
    echo_hdr(md, TRUE, ISAKMP_NEXT_ID);

    auth_payload = st->st_oakley.auth == OAKLEY_PRESHARED_KEY
	? ISAKMP_NEXT_HASH : ISAKMP_NEXT_SIG;

    /* IDir out */
    {
	/* id_hd should be struct isakmp_id, but struct isakmp_ipsec_id
	 * allows build_id_payload() to work for both phases.
	 */
	struct isakmp_ipsec_id id_hd;
	chunk_t id_b;

	build_id_payload(&id_hd, &id_b, &st->st_connection->spd.this);
	id_hd.isaiid_np = (send_cert)? ISAKMP_NEXT_CERT : auth_payload;
	if (!out_struct(&id_hd, &isakmp_ipsec_identification_desc, &md->rbody, &r_id_pbs)
	|| !out_chunk(id_b, &r_id_pbs, "my identity"))
	    return STF_INTERNAL_ERROR;
	close_output_pbs(&r_id_pbs);
    }

    /* CERT out, if we have one */
    if (send_cert)
    {
	pb_stream cert_pbs;

	struct isakmp_cert cert_hd;
	cert_hd.isacert_np = ISAKMP_NEXT_SIG;
	cert_hd.isacert_type = mycert.type;

	openswan_log("I am sending my cert");

	if (!out_struct(&cert_hd, &isakmp_ipsec_certificate_desc, &md->rbody, &cert_pbs))
	return STF_INTERNAL_ERROR;
	if (!out_chunk(get_mycert(mycert), &cert_pbs, "CERT"))
	    return STF_INTERNAL_ERROR;
	close_output_pbs(&cert_pbs);
    }

#ifdef TPM
    {
	pb_stream *pbs = &md->rbody;
	size_t enc_len = pbs_offset(pbs) - sizeof(struct isakmp_hdr);

	TCLCALLOUT_crypt("preHash", st,pbs,sizeof(struct isakmp_hdr),enc_len);

	/* find location of ID PBS */
	tpm_findID(pbs, &r_id_pbs);
    }
#endif

    /* IKEv2 NOTIFY payload */
    np = ISAKMP_NEXT_NONE;
    if(st->st_connection->policy & POLICY_IKEV2_ALLOW) {
	np = ISAKMP_NEXT_VID;
    }

    /* HASH_R or SIG_R out */
    {
	u_char hash_val[MAX_DIGEST_LEN];
	size_t hash_len = main_mode_hash(st, hash_val, FALSE, &r_id_pbs);

	if (auth_payload == ISAKMP_NEXT_HASH)
	{
	    /* HASH_R out */
	    if (!out_generic_raw(np, &isakmp_hash_desc, &md->rbody
	    , hash_val, hash_len, "HASH_R"))
		return STF_INTERNAL_ERROR;
	}
	else
	{
	    /* SIG_R out */
	    u_char sig_val[RSA_MAX_OCTETS];
	    size_t sig_len = RSA_sign_hash(st->st_connection
		, sig_val, hash_val, hash_len);

	    if (sig_len == 0)
	    {
		loglog(RC_LOG_SERIOUS, "unable to locate my private key for RSA Signature");
		return STF_FAIL + AUTHENTICATION_FAILED;
	    }

	    if (!out_generic_raw(np, &isakmp_signature_desc
	    , &md->rbody, sig_val, sig_len, "SIG_R"))
		return STF_INTERNAL_ERROR;
	}
    }

    if(st->st_connection->policy & POLICY_IKEV2_ALLOW) {
	if(!out_vid(ISAKMP_NEXT_NONE, &md->rbody, VID_MISC_IKEv2))
	    return STF_INTERNAL_ERROR;
    }


    /* encrypt message, sans fixed part of header */

    if (!encrypt_message(&md->rbody, st))
	return STF_INTERNAL_ERROR;	/* ??? we may be partly committed */

    /* Last block of Phase 1 (R3), kept for Phase 2 IV generation */
    DBG_cond_dump(DBG_CRYPT, "last encrypted block of Phase 1:"
	, st->st_new_iv, st->st_new_iv_len);

    st->st_ph1_iv_len = st->st_new_iv_len;
    set_ph1_iv(st, st->st_new_iv);

    /* It seems as per Cisco implementation, XAUTH and MODECFG
     * are not supposed to be performed again during rekey */

    if( st->st_connection->remotepeertype == CISCO &&
	st->st_connection->newest_isakmp_sa != SOS_NOBODY &&
        st->st_connection->spd.this.xauth_client) {
           DBG(DBG_CONTROL, DBG_log("Skipping XAUTH for rekey for Cisco Peer compatibility."));
           st->hidden_variables.st_xauth_client_done = TRUE;
           st->st_oakley.xauth = 0;

           if(st->st_connection->spd.this.modecfg_client) {
                DBG(DBG_CONTROL, DBG_log("Skipping ModeCFG for rekey for Cisco Peer compatibility."));
                st->hidden_variables.st_modecfg_vars_set = TRUE;
                st->hidden_variables.st_modecfg_started = TRUE;
           }
    }

    ISAKMP_SA_established(st->st_connection, st->st_serialno);

    /* ??? If st->st_connectionc->gw_info != NULL,
     * we should keep the public key -- it tested out.
     */

    return STF_OK;
}

/* STATE_MAIN_I3:
 * Handle HDR*;IDir;HASH/SIG_R from responder.
 *
 * Broken into parts to allow asynchronous DNS for KEY records.
 *
 * - main_inR3 to start
 * - main_inR3_tail to finish or suspend for DNS lookup
 * - main_inR3_continue to start main_inR3_tail again
 */

static key_tail_fn main_inR3_tail;	/* forward */

stf_status
main_inR3(struct msg_digest *md)
{
    return main_inR3_tail(md, NULL);
}

static void
main_inR3_continue(struct adns_continuation *cr, err_t ugh)
{
    key_continue(cr, ugh, main_inR3_tail);
}

static stf_status
main_inR3_tail(struct msg_digest *md
, struct key_continuation *kc)
{
    struct state *const st = md->st;

    /* ID and HASH_R or SIG_R in
     * Note: this may switch the connection being used!
     */
    {
	stf_status r = main_id_and_auth(md, TRUE, main_inR3_continue, kc);

	if (r != STF_OK)
	    return r;
    }

    /**************** done input ****************/

    /* save last IV from phase 1 so it can be restored later so anything
     * between the end of phase 1 and the start of phase 2 ie mode config
     * payloads etc will not loose our IV
     */
    memcpy(st->st_ph1_iv, st->st_new_iv, st->st_new_iv_len);
    st->st_ph1_iv_len = st->st_new_iv_len;

    /* It seems as per Cisco implementation, XAUTH and MODECFG
     * are not supposed to be performed again during rekey */
    if( st->st_connection->remotepeertype == CISCO &&
	st->st_connection->newest_isakmp_sa != SOS_NOBODY &&
        st->st_connection->spd.this.xauth_client) {
           DBG(DBG_CONTROL, DBG_log("Skipping XAUTH for rekey for Cisco Peer compatibility."));
           st->hidden_variables.st_xauth_client_done = TRUE;
           st->st_oakley.xauth = 0;

           if(st->st_connection->spd.this.modecfg_client) {
                DBG(DBG_CONTROL, DBG_log("Skipping ModeCFG for rekey for Cisco Peer compatibility."));
                st->hidden_variables.st_modecfg_vars_set = TRUE;
                st->hidden_variables.st_modecfg_started = TRUE;
           }
    }

    ISAKMP_SA_established(st->st_connection, st->st_serialno);

    passert((st->st_policy & POLICY_PFS)==0 || st->st_pfs_group != NULL );

    /* ??? If c->gw_info != NULL,
     * we should keep the public key -- it tested out.
     */

    st->st_ph1_iv_len = st->st_new_iv_len;
    set_ph1_iv(st, st->st_new_iv);

    /* save last IV from phase 1 so it can be restored later so anything
     * between the end of phase 1 and the start of phase 2 ie mode config
     * payloads etc will not loose our IV
     */
    memcpy(st->st_ph1_iv, st->st_new_iv, st->st_new_iv_len);
    st->st_ph1_iv_len = st->st_new_iv_len;

    update_iv(st);	/* finalize our Phase 1 IV */

    if(md->ikev2) {
	/*
	 * We cannot use POLICY_IKEV2_ALLOW here, since this will
	 * cause two IKEv2 capable but not ikev2= configured endpoints
	 * to falsely detect a bid down attack.
	 * Also, only the side that proposed IKEv2 can figure out there
	 * was a bid down attack to begin with. The side that did not propose
	 * cannot distinguish attack from regular ikev1 operation.
	 * if(st->st_connection->policy & POLICY_IKEV2_ALLOW) {
	 */
	if(st->st_connection->policy & POLICY_IKEV2_PROPOSE) {
	    openswan_log("Bid-down to IKEv1 attack detected, attempting to rekey connection with IKEv2");
	    st->st_connection->failed_ikev2 = FALSE;

	    /* schedule an event to do this as soon as possible */
	    md->event_already_set = TRUE;
	    st->st_rekeytov2 = TRUE;
	    delete_event(st);
	    event_schedule(EVENT_SA_REPLACE, 0, st);
	}
    }

    return STF_OK;
}

stf_status
send_isakmp_notification(struct state *st
			 , u_int16_t type, const void *data, size_t len)
{
    msgid_t msgid;
    pb_stream rbody;
    u_char old_new_iv[MAX_DIGEST_LEN];
    u_char old_iv[MAX_DIGEST_LEN];
    u_char
        *r_hashval,     /* where in reply to jam hash value */
        *r_hash_start;  /* start of what is to be hashed */

    msgid = generate_msgid(st);

    zero(reply_buffer);
    init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer), "ISAKMP notify");

    /* HDR* */
    {
        struct isakmp_hdr hdr;
        hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION;
        hdr.isa_np = ISAKMP_NEXT_HASH;
        hdr.isa_xchg = ISAKMP_XCHG_INFO;
        hdr.isa_msgid = msgid;
        hdr.isa_flags = ISAKMP_FLAG_ENCRYPTION;
        memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
        memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
        if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream, &rbody))
            impossible();
    }
    /* HASH -- create and note space to be filled later */
    START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_N);

    /* NOTIFY */
    {
        pb_stream notify_pbs;
        struct isakmp_notification isan;

        isan.isan_np = ISAKMP_NEXT_NONE;
        isan.isan_doi = ISAKMP_DOI_IPSEC;
        isan.isan_protoid = PROTO_ISAKMP;
        isan.isan_spisize = COOKIE_SIZE * 2;
        isan.isan_type = type;
        if (!out_struct(&isan, &isakmp_notification_desc, &rbody, &notify_pbs))
            return STF_INTERNAL_ERROR;
        if (!out_raw(st->st_icookie, COOKIE_SIZE, &notify_pbs, "notify icookie"))
            return STF_INTERNAL_ERROR;
        if (!out_raw(st->st_rcookie, COOKIE_SIZE, &notify_pbs, "notify rcookie"))
            return STF_INTERNAL_ERROR;
        if (data != NULL && len > 0)
            if (!out_raw(data, len, &notify_pbs, "notify data"))
                return STF_INTERNAL_ERROR;
        close_output_pbs(&notify_pbs);
    }

#ifdef TPM
    {
	pb_stream *pbs = &rbody;
	size_t enc_len = pbs_offset(pbs) - sizeof(struct isakmp_hdr);

	TCLCALLOUT_crypt("preHash", st,pbs,sizeof(struct isakmp_hdr),enc_len);
	r_hashval = tpm_relocateHash(pbs);
    }
#endif

    {
        /* finish computing HASH */
        struct hmac_ctx ctx;
        hmac_init_chunk(&ctx, st->st_oakley.prf_hasher, st->st_skeyid_a);
        hmac_update(&ctx, (const u_char *) &msgid, sizeof(msgid_t));
        hmac_update(&ctx, r_hash_start, rbody.cur-r_hash_start);
        hmac_final(r_hashval, &ctx);

        DBG(DBG_CRYPT,
                DBG_log("HASH computed:");
                DBG_dump("", r_hashval, ctx.hmac_digest_len));
    }
    /* save old IV (this prevents from copying a whole new state object
     * for NOTIFICATION / DELETE messages we don't need to maintain a state
     * because there are no retransmissions...
     */

    save_iv(st, old_iv);
    save_new_iv(st, old_new_iv);

    init_phase2_iv(st, &msgid);
    if (!encrypt_message(&rbody, st))
        return STF_INTERNAL_ERROR;

    {
        chunk_t saved_tpacket = st->st_tpacket;

        setchunk(st->st_tpacket, reply_stream.start, pbs_offset(&reply_stream));
        send_packet(st, "ISAKMP notify", TRUE);
        st->st_tpacket = saved_tpacket;
    }
    /* get back old IV for this state */
    set_iv(st, old_iv);
    set_new_iv(st, old_new_iv);

    return STF_IGNORE;
}

/* Send a notification to the peer.  We could decide
 * whether to send the notification, based on the type and the
 * destination, if we care to.
 */
static void
send_notification(struct state *sndst, u_int16_t type, struct state *encst,
		  msgid_t msgid, u_char *icookie, u_char *rcookie,
		  u_char *spi, size_t spisize, u_char protoid)
{
    u_char buffer[1024];
    pb_stream pbs, r_hdr_pbs;
    u_char *r_hashval, *r_hash_start;
    static time_t last_malformed;
    time_t n = time(NULL);
    struct isakmp_hdr hdr;           /* keep it around for TPM */

    r_hashval = NULL;
    r_hash_start = NULL;

    passert((sndst) && (sndst->st_connection));
    switch(type) {

    case PAYLOAD_MALFORMED:
	/* only send one per second. */
	if(n == last_malformed) {
	    return;
	}

	last_malformed = n;
	sndst->hidden_variables.st_malformed_sent++;
	if(sndst->hidden_variables.st_malformed_sent > MAXIMUM_MALFORMED_NOTIFY) {
	    openswan_log("too many (%d) malformed payloads. Deleting state"
			 , sndst->hidden_variables.st_malformed_sent);
	    delete_state(sndst);
	    return;
	}

	openswan_DBG_dump("payload malformed after IV", sndst->st_iv, sndst->st_iv_len);

	/*
	 * do not encrypt notification, since #1 reason for malformed
	 * payload is that the keys are all messed up.
	 */
	encst = NULL;
	break;

    case INVALID_FLAGS:
	/*
	 * invalid flags usually includes encryption flags, so do not
	 * send encrypted.
	 */
	encst = NULL;
	break;
    }

    if(encst!=NULL && !IS_ISAKMP_ENCRYPTED(encst->st_state)) {
	encst = NULL;
    }

    openswan_log("sending %snotification %s to %s:%u"
		 , encst ? "encrypted " : ""
		 , enum_name(&ipsec_notification_names, type)
		 , ip_str(&sndst->st_remoteaddr)
		 , sndst->st_remoteport);

    zero(buffer);
    init_pbs(&pbs, buffer, sizeof(buffer), "notification msg");

    /* HDR* */
    {
	hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION;
	hdr.isa_np = encst ? ISAKMP_NEXT_HASH : ISAKMP_NEXT_N;
	hdr.isa_xchg = ISAKMP_XCHG_INFO;
	hdr.isa_msgid = msgid;
	hdr.isa_flags = encst ? ISAKMP_FLAG_ENCRYPTION : 0;
	if (icookie)
	    memcpy(hdr.isa_icookie, icookie, COOKIE_SIZE);
	if (rcookie)
	    memcpy(hdr.isa_rcookie, rcookie, COOKIE_SIZE);
	if (!out_struct(&hdr, &isakmp_hdr_desc, &pbs, &r_hdr_pbs))
	    impossible();
    }

    /* HASH -- value to be filled later */
    if (encst)
    {
	pb_stream hash_pbs;
	if (!out_generic(ISAKMP_NEXT_N, &isakmp_hash_desc, &r_hdr_pbs,
	    &hash_pbs))
	    impossible();
	r_hashval = hash_pbs.cur;  /* remember where to plant value */
	if (!out_zero(
	    encst->st_oakley.prf_hasher->hash_digest_len,
	    &hash_pbs, "HASH(1)"))
	    impossible();
	close_output_pbs(&hash_pbs);
	r_hash_start = r_hdr_pbs.cur; /* hash from after HASH(1) */
    }

    /* Notification Payload */
    {
	pb_stream not_pbs;
	struct isakmp_notification isan;

	isan.isan_doi = ISAKMP_DOI_IPSEC;
	isan.isan_np = ISAKMP_NEXT_NONE;
	isan.isan_type = type;
	isan.isan_spisize = spisize;
	isan.isan_protoid = protoid;

	if(!out_struct(&isan, &isakmp_notification_desc
		       , &r_hdr_pbs, &not_pbs))  {
	    openswan_log("failed to build notification in send_notification\n");
	    return;
	}

	if(spisize > 0) {
	    if(!out_raw(spi, spisize, &not_pbs, "spi")) {
		openswan_log("failed to build notification for spisize=%d\n", (int)spisize);
		return;
	    }
	}

	close_output_pbs(&not_pbs);
    }

#ifdef TPM
    {
	pb_stream *pbs = &r_hdr_pbs;
	size_t enc_len = pbs_offset(pbs) - sizeof(struct isakmp_hdr);

	TCLCALLOUT_crypt("preHash",encst,pbs,sizeof(struct isakmp_hdr),enc_len);
	r_hashval = tpm_relocateHash(pbs);
    }
#endif

    /* calculate hash value and patch into Hash Payload */
    if (encst)
    {
	struct hmac_ctx ctx;
	hmac_init_chunk(&ctx, encst->st_oakley.prf_hasher, encst->st_skeyid_a);
	hmac_update(&ctx, (u_char *) &msgid, sizeof(msgid_t));
	hmac_update(&ctx, r_hash_start, r_hdr_pbs.cur-r_hash_start);
	hmac_final(r_hashval, &ctx);

	DBG(DBG_CRYPT,
	    DBG_log("HASH(1) computed:");
	    DBG_dump("", r_hashval, ctx.hmac_digest_len);
	)
    }

    /* Encrypt message (preserve st_iv) */
    if (encst)
    {
	u_char old_iv[MAX_DIGEST_LEN];
	u_int old_iv_len = encst->st_iv_len;

	if (old_iv_len > MAX_DIGEST_LEN)
	    impossible();
	memcpy(old_iv, encst->st_iv, old_iv_len);

	if (!IS_ISAKMP_SA_ESTABLISHED(encst->st_state))
	{
	    if (encst->st_new_iv_len > MAX_DIGEST_LEN)
		impossible();
	    memcpy(encst->st_iv, encst->st_new_iv, encst->st_new_iv_len);
	    encst->st_iv_len = encst->st_new_iv_len;
	}
	init_phase2_iv(encst, &msgid);
	if (!encrypt_message(&r_hdr_pbs, encst))
	    impossible();

	/* restore preserved st_iv*/
	memcpy(encst->st_iv, old_iv, old_iv_len);
	encst->st_iv_len = old_iv_len;
    }
    else
    {
	close_output_pbs(&r_hdr_pbs);
    }

    /* Send packet (preserve st_tpacket) */
    {
	chunk_t saved_tpacket = sndst->st_tpacket;

	setchunk(sndst->st_tpacket, pbs.start, pbs_offset(&pbs));
	TCLCALLOUT_notify("avoidEmittingNotification", sndst, &pbs, &hdr);
	send_packet(sndst, "notification packet", TRUE);
#ifdef TPM
    tpm_stolen:
    tpm_ignore:
#endif
	sndst->st_tpacket = saved_tpacket;
    }
}

void
send_notification_from_state(struct state *st, enum state_kind state,
    u_int16_t type)
{
    struct state *p1st;

    passert(st);

    if (state == STATE_UNDEFINED)
	state = st->st_state;

    if (IS_QUICK(state)) {
	p1st = find_phase1_state(st->st_connection, ISAKMP_SA_ESTABLISHED_STATES);
	if ((p1st == NULL) || (!IS_ISAKMP_SA_ESTABLISHED(p1st->st_state))) {
	    loglog(RC_LOG_SERIOUS,
		"no Phase1 state for Quick mode notification");
	    return;
	}
	send_notification(st, type, p1st, generate_msgid(p1st),
	    st->st_icookie, st->st_rcookie, NULL, 0, PROTO_ISAKMP);
    }
    else if (IS_ISAKMP_ENCRYPTED(state)) {
	send_notification(st, type, st, generate_msgid(st),
	    st->st_icookie, st->st_rcookie, NULL, 0, PROTO_ISAKMP);
    }
    else {
	/* no ISAKMP SA established - don't encrypt notification */
	send_notification(st, type, NULL, 0,
	    st->st_icookie, st->st_rcookie, NULL, 0, PROTO_ISAKMP);
    }
}

void
send_notification_from_md(struct msg_digest *md, u_int16_t type)
{
    /**
     * Create a dummy state to be able to use send_packet in
     * send_notification
     *
     * we need to set:
     *   st_connection->that.host_addr
     *   st_connection->that.host_port
     *   st_connection->interface
     */
    struct state st;
    struct connection cnx;

    passert(md);

    memset(&st, 0, sizeof(st));
    memset(&cnx, 0, sizeof(cnx));
    st.st_connection = &cnx;
    st.st_remoteaddr = md->sender;
    st.st_remoteport = md->sender_port;
    st.st_localaddr  = md->iface->ip_addr;
    st.st_localport  = md->iface->port;
    cnx.interface = md->iface;
    st.st_interface = md->iface;

    send_notification(&st, type, NULL, 0,
	md->hdr.isa_icookie, md->hdr.isa_rcookie, NULL, 0, PROTO_ISAKMP);
}

/** Send a Delete Notification to announce deletion of ISAKMP SA or
 * inbound IPSEC SAs.  Does nothing if no such SAs are being deleted.
 * Delete Notifications cannot announce deletion of outbound IPSEC/ISAKMP SAs.
 *
 * @param st State struct (hopefully has some SA's related to it)
 */
void
ikev1_delete_out(struct state *st)
{
    pb_stream reply_pbs;
    pb_stream r_hdr_pbs;
    msgid_t	msgid;
    u_char buffer[8192];
    struct state *p1st;
    ip_said said[EM_MAXRELSPIS];
    ip_said *ns = said;
    u_char
	*r_hashval,	/* where in reply to jam hash value */
	*r_hash_start;	/* start of what is to be hashed */
    bool isakmp_sa = FALSE;
    struct isakmp_hdr hdr;

    /* If there are IPsec SA's related to this state struct... */
    if (IS_IPSEC_SA_ESTABLISHED(st->st_state))
    {
        /* Find their phase1 state object */
	p1st = find_phase1_state(st->st_connection, ISAKMP_SA_ESTABLISHED_STATES);
	if (p1st == NULL)
	{
	    DBG(DBG_CONTROL, DBG_log("no Phase 1 state for Delete"));
	    return;
	}

	if (st->st_ah.present)
	{
	    ns->spi = st->st_ah.our_spi;
	    ns->dst = st->st_connection->spd.this.host_addr;
	    ns->proto = PROTO_IPSEC_AH;
	    ns++;
	}
	if (st->st_esp.present)
	{
	    ns->spi = st->st_esp.our_spi;
	    ns->dst = st->st_connection->spd.this.host_addr;
	    ns->proto = PROTO_IPSEC_ESP;
	    ns++;
	}

	passert(ns != said);    /* there must be some SAs to delete */
    }
    /* or ISAKMP SA's... */
    else if (IS_ISAKMP_SA_ESTABLISHED(st->st_state))
    {
	p1st = st;
	isakmp_sa = TRUE;
    }
    else
    {
	return; /* nothing to do */
    }

    msgid = generate_msgid(p1st);

    zero(buffer);
    init_pbs(&reply_pbs, buffer, sizeof(buffer), "delete msg");

    /* HDR* */
    {
	hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION;
	hdr.isa_np = ISAKMP_NEXT_HASH;
	hdr.isa_xchg = ISAKMP_XCHG_INFO;
	hdr.isa_msgid = msgid;
	hdr.isa_flags = ISAKMP_FLAG_ENCRYPTION;
	memcpy(hdr.isa_icookie, p1st->st_icookie, COOKIE_SIZE);
	memcpy(hdr.isa_rcookie, p1st->st_rcookie, COOKIE_SIZE);
	if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_pbs, &r_hdr_pbs))
	    impossible();
    }

    /* HASH -- value to be filled later */
    {
	pb_stream hash_pbs;

	if (!out_generic(ISAKMP_NEXT_D, &isakmp_hash_desc, &r_hdr_pbs, &hash_pbs))
	    impossible();
	r_hashval = hash_pbs.cur;	/* remember where to plant value */
	if (!out_zero(p1st->st_oakley.prf_hasher->hash_digest_len, &hash_pbs, "HASH(1)"))
	    impossible();
	close_output_pbs(&hash_pbs);
	r_hash_start = r_hdr_pbs.cur;	/* hash from after HASH(1) */
    }

    /* Delete Payloads */
    if (isakmp_sa)
    {
	pb_stream del_pbs;
	struct isakmp_delete isad;
	u_char isakmp_spi[2*COOKIE_SIZE];

	isad.isad_doi = ISAKMP_DOI_IPSEC;
	isad.isad_np = ISAKMP_NEXT_NONE;
	isad.isad_spisize = (2 * COOKIE_SIZE);
	isad.isad_protoid = PROTO_ISAKMP;
	isad.isad_nospi = 1;

	memcpy(isakmp_spi, st->st_icookie, COOKIE_SIZE);
	memcpy(isakmp_spi+COOKIE_SIZE, st->st_rcookie, COOKIE_SIZE);

	if (!out_struct(&isad, &isakmp_delete_desc, &r_hdr_pbs, &del_pbs)
	|| !out_raw(&isakmp_spi, (2*COOKIE_SIZE), &del_pbs, "delete payload"))
	    impossible();
	close_output_pbs(&del_pbs);
    }
    else
    {
	while (ns != said)
	{

	    pb_stream del_pbs;
	    struct isakmp_delete isad;

	    ns--;
	    isad.isad_doi = ISAKMP_DOI_IPSEC;
	    isad.isad_np = ns == said? ISAKMP_NEXT_NONE : ISAKMP_NEXT_D;
	    isad.isad_spisize = sizeof(ipsec_spi_t);
	    isad.isad_protoid = ns->proto;

	    isad.isad_nospi = 1;
	    if (!out_struct(&isad, &isakmp_delete_desc, &r_hdr_pbs, &del_pbs)
	    || !out_raw(&ns->spi, sizeof(ipsec_spi_t), &del_pbs, "delete payload"))
		impossible();
	    close_output_pbs(&del_pbs);
	}
    }

    /* calculate hash value and patch into Hash Payload */
    {
	struct hmac_ctx ctx;
	hmac_init_chunk(&ctx, p1st->st_oakley.prf_hasher, p1st->st_skeyid_a);
	hmac_update(&ctx, (u_char *) &msgid, sizeof(msgid_t));
	hmac_update(&ctx, r_hash_start, r_hdr_pbs.cur-r_hash_start);
	hmac_final(r_hashval, &ctx);

	DBG(DBG_CRYPT,
	    DBG_log("HASH(1) computed:");
	    DBG_dump("", r_hashval, ctx.hmac_digest_len);
	)
    }

    /* Do a dance to avoid needing a new state object.
     * We use the Phase 1 State.  This is the one with right
     * IV, for one thing.
     * The tricky bits are:
     * - we need to preserve (save/restore) st_iv (but not st_iv_new)
     * - we need to preserve (save/restore) st_tpacket.
     */
    {
	u_char old_iv[MAX_DIGEST_LEN];
	chunk_t saved_tpacket = p1st->st_tpacket;

	save_iv(p1st, old_iv);
	init_phase2_iv(p1st, &msgid);

	if (!encrypt_message(&r_hdr_pbs, p1st))
	    impossible();

	setchunk(p1st->st_tpacket, reply_pbs.start, pbs_offset(&reply_pbs));
	TCLCALLOUT_notify("avoidEmittingDelete", p1st, &reply_pbs, &hdr);
	send_packet(p1st, "delete notify", TRUE);
#ifdef TPM
    tpm_stolen:
    tpm_ignore:
#endif
	p1st->st_tpacket = saved_tpacket;

	/* get back old IV for this state */
	set_iv(p1st, old_iv);
    }
}

/** Accept a Delete SA notification, and process it if valid.
 *
 * @param st State structure
 * @param md Message Digest
 * @param p Payload digest
 */
void
accept_delete(struct state *st, struct msg_digest *md, struct payload_digest *p)
{
    struct isakmp_delete *d = &(p->payload.delete);
    size_t sizespi;
    int i;

    /* We only listen to encrypted notifications */
    if (!md->encrypted)
    {
	loglog(RC_LOG_SERIOUS, "ignoring Delete SA payload: not encrypted");
	return;
    }

    /* If there is no SA related to this request, but it was encrypted */
    if (!IS_ISAKMP_SA_ESTABLISHED(st->st_state))
    {
	/* can't happen (if msg is encrypt), but just to be sure */
	loglog(RC_LOG_SERIOUS, "ignoring Delete SA payload: "
	"ISAKMP SA not established");
	return;
    }

    if (d->isad_nospi == 0)
    {
	loglog(RC_LOG_SERIOUS, "ignoring Delete SA payload: no SPI");
	return;
    }

    switch (d->isad_protoid)
    {
    case PROTO_ISAKMP:
	sizespi = 2 * COOKIE_SIZE;
	break;
    case PROTO_IPSEC_AH:
    case PROTO_IPSEC_ESP:
	sizespi = sizeof(ipsec_spi_t);
	break;
    case PROTO_IPCOMP:
	/* nothing interesting to delete */
	return;
    default:
	loglog(RC_LOG_SERIOUS
	    , "ignoring Delete SA payload: unknown Protocol ID (%s)"
	    , enum_show(&protocol_names, d->isad_protoid));
	return;
    }

    if (d->isad_spisize != sizespi)
    {
	loglog(RC_LOG_SERIOUS
	    , "ignoring Delete SA payload: bad SPI size (%d) for %s"
	    , d->isad_spisize, enum_show(&protocol_names, d->isad_protoid));
	return;
    }

    if (pbs_left(&p->pbs) != d->isad_nospi * sizespi)
    {
	loglog(RC_LOG_SERIOUS
	    , "ignoring Delete SA payload: invalid payload size");
	return;
    }

    for (i = 0; i < d->isad_nospi; i++)
    {
	u_char *spi = p->pbs.cur + (i * sizespi);

	if (d->isad_protoid == PROTO_ISAKMP)
	{
	    /**
	     * ISAKMP
	     */
	    struct state *dst = find_state_ikev1(spi /*iCookie*/
		, spi+COOKIE_SIZE /*rCookie*/
		, &st->st_connection->spd.that.host_addr
		, MAINMODE_MSGID);

	    if (dst == NULL)
	    {
		loglog(RC_LOG_SERIOUS, "ignoring Delete SA payload: "
		    "ISAKMP SA not found (maybe expired)");
	    }
	    else if (!same_peer_ids(st->st_connection, dst->st_connection, NULL))
	    {
		/* we've not authenticated the relevant identities */
		loglog(RC_LOG_SERIOUS, "ignoring Delete SA payload: "
		    "ISAKMP SA used to convey Delete has different IDs from ISAKMP SA it deletes");
	    }
	    else
	    {
		struct connection *oldc;

		oldc = cur_connection;
		set_cur_connection(dst->st_connection);
#ifdef NAT_TRAVERSAL
		if (nat_traversal_enabled) {
		    nat_traversal_change_port_lookup(md, dst);
		}
#endif
		loglog(RC_LOG_SERIOUS, "received Delete SA payload: "
		    "deleting ISAKMP State #%lu", dst->st_serialno);
		delete_state(dst);
		set_cur_connection(oldc);
	    }
	}
	else
	{
	    /**
	     * IPSEC (ESP/AH)
	     */
	    bool bogus;
	    struct state *dst = find_phase2_state_to_delete(st
		, d->isad_protoid
		, *(ipsec_spi_t *)spi	/* network order */
		, &bogus);

	    if (dst == NULL)
	    {
		loglog(RC_LOG_SERIOUS
		       , "ignoring Delete SA payload: %s SA(0x%08lx) not found (%s)"
		       , enum_show(&protocol_names, d->isad_protoid)
		       , (unsigned long)ntohl((unsigned long)*(ipsec_spi_t *)spi)
		       , bogus ? "our SPI - bogus implementation" : "maybe expired");
	    }
	    else
	    {
		struct connection *rc = dst->st_connection;
		struct connection *oldc;

		oldc = cur_connection;
		set_cur_connection(rc);

#ifdef NAT_TRAVERSAL
		if (nat_traversal_enabled) {
		    nat_traversal_change_port_lookup(md, dst);
		}
#endif
		if (rc->newest_ipsec_sa == dst->st_serialno
		&& (rc->policy & POLICY_UP))
		    {
		    /* Last IPSec SA for a permanent connection that we
		     * have initiated.  Replace it in a few seconds.
		     *
		     * Useful if the other peer is rebooting.
		     */
#define DELETE_SA_DELAY  EVENT_RETRANSMIT_DELAY_0
		    if (dst->st_event != NULL
		    && dst->st_event->ev_type == EVENT_SA_REPLACE
		    && dst->st_event->ev_time <= DELETE_SA_DELAY + now())
		    {
			/* Patch from Angus Lees to ignore retransmited
			 * Delete SA.
			 */
			loglog(RC_LOG_SERIOUS, "received Delete SA payload: "
			    "already replacing IPSEC State #%lu in %d seconds"
			    , dst->st_serialno, (int)(dst->st_event->ev_time - now()));
		    }
		    else
		    {
			loglog(RC_LOG_SERIOUS, "received Delete SA payload: "
			    "replace IPSEC State #%lu in %d seconds"
			    , dst->st_serialno, DELETE_SA_DELAY);
			dst->st_margin = DELETE_SA_DELAY;
			delete_event(dst);
			event_schedule(EVENT_SA_REPLACE, DELETE_SA_DELAY, dst);
		    }
		}
		else
		{
		    loglog(RC_LOG_SERIOUS, "received Delete SA(0x%08lx) payload: "
			   "deleting IPSEC State #%lu"
			   , (unsigned long)ntohl((unsigned long)*(ipsec_spi_t *)spi)
			   , dst->st_serialno);
		    delete_state(dst);
		}

		/* reset connection */
		set_cur_connection(oldc);
	    }
	}
    }
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
