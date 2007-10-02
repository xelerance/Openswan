/* IPsec DOI and Oakley resolution routines
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003-2006  Michael Richardson <mcr@xelerance.com>
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
 *
 * Modifications to use OCF interface written by
 * Daniel Djamaludin <danield@cyberguard.com>
 * Copyright (C) 2004-2005 Intel Corporation.  All Rights Reserved.
 *
 * RCSID $Id: ipsec_doi.c,v 1.304.2.11 2006/04/16 02:24:19 mcr Exp $
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>	/* missing from <resolv.h> on old systems */
#include <sys/time.h>		/* for gettimeofday */
#include <gmp.h>

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
#include "smartcard.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "connections.h"	/* needs id.h */
#include "keys.h"
#include "packet.h"
#include "demux.h"	/* needs packet.h */
#include "adns.h"	/* needs <resolv.h> */
#include "dnskey.h"	/* needs keys.h and adns.h */
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "cookie.h"
#include "server.h"
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

#ifdef XAUTH
#include "xauth.h"
#endif
#include "vendor.h"
#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif
#ifdef VIRTUAL_IP
#include "virtual.h"
#endif
#include "dpd.h"
#include "x509more.h"

#include "tpm/tpm.h"

#ifdef HAVE_OCF
#include "ocf_pk.h"
#endif

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

    pluto_vendorid[0] = 'O';	/* Opportunistic Encryption Rules */
    pluto_vendorid[1] = 'E';

#if PLUTO_VENDORID_SIZE - 2 <= MD5_DIGEST_SIZE
    /* truncate hash to fit our vendor ID */
    memcpy(pluto_vendorid + 2, hash, PLUTO_VENDORID_SIZE - 2);
#else
    /* pad to fill our vendor ID */
    memcpy(pluto_vendorid + 2, hash, MD5_DIGEST_SIZE);
    memset(pluto_vendorid + 2 + MD5_DIGEST_SIZE, '\0'
	, PLUTO_VENDORID_SIZE - 2 - MD5_DIGEST_SIZE);
#endif

    /* Make it printable!  Hahaha - MCR */
    for (i = 2; i < PLUTO_VENDORID_SIZE; i++)
    {
	/* Reset bit 7, force bit 6.  Puts it into 64-127 range */
	pluto_vendorid[i] &= 0x7f;
	pluto_vendorid[i] |= 0x40;
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

    r_hdr.isa_flags &= ~ISAKMP_FLAG_COMMIT;	/* we won't ever turn on this bit */
    if (enc)
	r_hdr.isa_flags |= ISAKMP_FLAG_ENCRYPTION;
    /* some day, we may have to set r_hdr.isa_version */
    r_hdr.isa_np = np;
    if (!out_struct(&r_hdr, &isakmp_hdr_desc, &md->reply, &md->rbody)) {
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

	n_to_mpz(&st->st_sec
		 , wire_chunk_ptr(kn, &(kn->secret))
		 , kn->secret.len);
	clonetochunk(st->st_sec_chunk
		     , wire_chunk_ptr(kn, &(kn->secret))
		     , kn->secret.len, "long term secret");
    }
}

/*
 * package up the calculate KE value, and emit it as a KE payload.
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
    time_t n = time((time_t)NULL);
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

    memset(buffer, 0, sizeof(buffer));
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
	    encst->st_oakley.hasher->hash_digest_len,
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
	    if(out_raw(spi, spisize, &not_pbs, "spi")) {
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
	hmac_init_chunk(&ctx, encst->st_oakley.hasher, encst->st_skeyid_a);
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
send_delete(struct state *st)
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
	if (!out_zero(p1st->st_oakley.hasher->hash_digest_len, &hash_pbs, "HASH(1)"))
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
	hmac_init_chunk(&ctx, p1st->st_oakley.hasher, p1st->st_skeyid_a);
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

void
ipsecdoi_initiate(int whack_sock
		  , struct connection *c
		  , lset_t policy
		  , unsigned long try
		  , so_serial_t replacing
		  , enum crypto_importance importance)
{
    /* If there's already an ISAKMP SA established, use that and
     * go directly to Quick Mode.  We are even willing to use one
     * that is still being negotiated, but only if we are the Initiator
     * (thus we can be sure that the IDs are not going to change;
     * other issues around intent might matter).
     * Note: there is no way to initiate with a Road Warrior.
     */
    struct state *st = find_phase1_state(c
	, ISAKMP_SA_ESTABLISHED_STATES | PHASE1_INITIATOR_STATES);

    if (st == NULL)
    {
	initiator_function *initiator = c->policy & POLICY_AGGRESSIVE ?
#if defined(AGGRESSIVE)	    
	    aggr_outI1
#else
	    aggr_not_present
#endif	    
	    : main_outI1;
	(void) initiator(whack_sock, c, NULL, policy, try, importance);
    }
    else if (HAS_IPSEC_POLICY(policy)) {

      /* boost priority if necessary */
      if(st->st_import < importance) st->st_import = importance;

      if (!IS_ISAKMP_SA_ESTABLISHED(st->st_state)) {
	/* leave our Phase 2 negotiation pending */
	add_pending(whack_sock, st, c, policy, try
		    , replacing);
      }
      else {
	/* ??? we assume that peer_nexthop_sin isn't important:
	 * we already have it from when we negotiated the ISAKMP SA!
	 * It isn't clear what to do with the error return.
	 */
	(void) quick_outI1(whack_sock, st, c, policy, try
			   , replacing);
      }
    }
    else
    {
	close_any(whack_sock);
    }
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
ipsecdoi_replace(struct state *st, unsigned long try)
{
    int whack_sock = dup_any(st->st_whack_sock);
    lset_t policy = st->st_policy;

    if (IS_PHASE1(st->st_state) || IS_PHASE15(st->st_state))
    {
	initiator_function *initiator = policy & POLICY_AGGRESSIVE ?
#if defined(AGGRESSIVE)
	    aggr_outI1
#else
	    aggr_not_present
#endif	    
	    : main_outI1;
	passert(!HAS_IPSEC_POLICY(policy));
	(void) initiator(whack_sock, st->st_connection, st, policy
			 , try, st->st_import);
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
	if (st->st_esp.present && st->st_esp.attrs.transid != ESP_NULL)
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
	ipsecdoi_initiate(whack_sock, st->st_connection, policy, try
			  , st->st_serialno, st->st_import);
    }
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
	loglog(RC_LOG_SERIOUS, "protocol/port in Phase 1 ID Payload must be 0/0 or %d/%d"
	    " but are %d/%d"
	    , IPPROTO_UDP, IKE_UDP_PORT
	    , id->isaid_doi_specific_a, id->isaid_doi_specific_b);
	/* we have turned this into a warning because of bugs in other vendors
	 * products. Specifically CISCO VPN3000. */
	/* return FALSE; */
    }

    peer.kind = id->isaid_idtype;

    switch (peer.kind)
    {
    case ID_IPV4_ADDR:
    case ID_IPV6_ADDR:
	/* failure mode for initaddr is probably inappropriate address length */
	{
	    err_t ugh = initaddr(id_pbs->cur, pbs_left(id_pbs)
		, peer.kind == ID_IPV4_ADDR? AF_INET : AF_INET6
		, &peer.ip_addr);

	    if (ugh != NULL)
	    {
		loglog(RC_LOG_SERIOUS, "improper %s identification payload: %s"
		    , enum_show(&ident_names, peer.kind), ugh);
		/* XXX Could send notification back */
		return FALSE;
	    }
	}
	break;

    case ID_USER_FQDN:
	if (memchr(id_pbs->cur, '@', pbs_left(id_pbs)) == NULL)
	{
	    char idbuf[IDTOA_BUF];
	    int len = pbs_left(id_pbs);
	    if(len>(IDTOA_BUF-1)) len = IDTOA_BUF;

	    memcpy(idbuf, id_pbs->cur, len-1);
	    idbuf[len]='\0';
	    loglog(RC_LOG_SERIOUS, "peer's ID_USER_FQDN contains no @: %s", idbuf);
	    //return FALSE;
	}
	/* FALLTHROUGH */
    case ID_FQDN:
	if (memchr(id_pbs->cur, '\0', pbs_left(id_pbs)) != NULL)
	{
	    loglog(RC_LOG_SERIOUS, "Phase 1 ID Payload of type %s contains a NUL"
		, enum_show(&ident_names, peer.kind));
	    return FALSE;
	}

	/* ??? ought to do some more sanity check, but what? */

	setchunk(peer.name, id_pbs->cur, pbs_left(id_pbs));
	break;

    case ID_KEY_ID:
	setchunk(peer.name, id_pbs->cur, pbs_left(id_pbs));
	DBG(DBG_PARSING,
 	    DBG_dump_chunk("KEY ID:", peer.name));
	break;

    case ID_DER_ASN1_DN:
	setchunk(peer.name, id_pbs->cur, pbs_left(id_pbs));
 	DBG(DBG_PARSING,
 	    DBG_dump_chunk("DER ASN1 DN:", peer.name));
	break;

    default:
	/* XXX Could send notification back */
	loglog(RC_LOG_SERIOUS, "Unacceptable identity type (%s) in Phase 1 ID Payload"
	    , enum_show(&ident_names, peer.kind));
	return FALSE;
    }

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
	    DBG_log("offered CA: '%s'", buf);
	)

	if (r != c)
	{
	    /* apparently, r is an improvement on c -- replace */

	    openswan_log("switched from \"%s\" to \"%s\"", c->name, r->name);
	    if (r->kind == CK_TEMPLATE || r->kind == CK_GROUP)
	    {
		/* instantiate it, filling in peer's ID */
		r = rw_instantiate(r, &c->spd.that.host_addr,
				   NULL,
				   &peer);
	    }

	    st->st_connection = r;	/* kill reference to c */
	    set_cur_connection(r);
	    connection_discard(c);
	}
	else if (c->spd.that.has_id_wildcards)
	{
	    free_id_content(&c->spd.that.id);
	    c->spd.that.id = peer;
	    c->spd.that.has_id_wildcards = FALSE;
	    unshare_id_content(&c->spd.that.id);
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

    for(sr=&c->spd; sr!=NULL; sr=sr->next) {
	if(sr->this.xauth_client) {
	    if(sr->this.xauth_name) {
		strncpy(st->st_xauth_username, sr->this.xauth_name, sizeof(st->st_xauth_username));
		break;
	    }
	}
    }

    get_cookie(TRUE, st->st_icookie, COOKIE_SIZE, &c->spd.that.host_addr);
    insert_state(st);	/* needs cookies, connection */
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
