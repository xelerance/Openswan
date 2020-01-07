/*
 * IKEv2 parent SA creation routines
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi
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
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <gmp.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "pluto/state.h"
#include "id.h"
#include "pluto/connections.h"
#include "hostpair.h"

#include "pluto/crypto.h" /* requires sha1.h and md5.h */
#include "x509.h"
#include "x509more.h"
#include "pluto/ike_alg.h"
#include "kernel_alg.h"
#include "pluto/plutoalg.h"
#include "pluto_crypt.h"
#include "packet.h"
#include "demux.h"
#include "ikev2.h"
#include "log.h"
#include "pluto/spdb.h"          /* for out_sa */
#include "ipsec_doi.h"
#include "vendor.h"
#include "timer.h"
#include "ike_continuations.h"
#include "cookie.h"
#include "rnd.h"
#include "pending.h"
#include "kernel.h"
#include "pluto/nat_traversal.h"
#include "pluto/db2_ops.h"

#include "tpm/tpm.h"

static void ikev2_parent_outI1_continue(struct pluto_crypto_req_cont *pcrc
                                        , struct pluto_crypto_req *r
                                        , err_t ugh);

static stf_status ikev2_parent_outI1_tail(struct pluto_crypto_req_cont *pcrc
                                          , struct pluto_crypto_req *r);

static bool ikev2_get_dcookie(u_char *dcookie, chunk_t st_ni
	,ip_address *addr, u_int8_t *spiI);

static stf_status ikev2_parent_outI1_common(struct msg_digest *md
                                            , struct state *st);

static void ikev2_update_nat_ports(struct state *st);


/*
 * unpack the calculate KE value, store it in state.
 * used by IKEv2: parent, child (PFS)
 */
int
unpack_v2KE(struct state *st
            , struct pluto_crypto_req *r
            , chunk_t *g)
{
    struct pcr_kenonce *kn = &r->pcr_d.kn;

    unpack_KE(st, r, g);
    return kn->oakley_group;
}

/*
 * package up the calculate KE value, and emit it as a KE payload.
 * used by IKEv2: parent, child (PFS)
 */
bool
justship_v2KE(struct state *st UNUSED
              , chunk_t *g, unsigned int oakley_group
              , pb_stream *outs, u_int8_t np)
{
    struct ikev2_ke v2ke;
    pb_stream kepbs;

    pbs_set_np(outs, ISAKMP_NEXT_v2KE);

    memset(&v2ke, 0, sizeof(v2ke));
    v2ke.isak_np      = np;
    v2ke.isak_group   = oakley_group;
    if(!out_struct(&v2ke, &ikev2_ke_desc, outs, &kepbs)) {
        return FALSE;
    }
    if (!g->len) {
        loglog(RC_FATAL, "ikev2 g^x is not initialized (zero length), aborting");
        return FALSE;
    }
    if(!out_chunk(*g, &kepbs, "ikev2 g^x")) {
        return FALSE;
    }
    close_output_pbs(&kepbs);
    return TRUE;
}

static bool
ship_v2KE(struct state *st
          , struct pluto_crypto_req *r
          , chunk_t *g
          , pb_stream *outs, u_int8_t np)
{
    int oakley_group = unpack_v2KE(st, r, g);
    return justship_v2KE(st, g, oakley_group, outs, np);
}

bool justship_v2Nonce(struct state *st UNUSED, pb_stream *outpbs, chunk_t *nonce, unsigned int np)
{
    struct ikev2_generic in;
    pb_stream pb;

    memset(&in, 0, sizeof(in));
    pbs_set_np(outpbs, ISAKMP_NEXT_v2Ni);

    in.isag_np = np;
    in.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;
    if(DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
        openswan_log(" setting bogus ISAKMP_PAYLOAD_OPENSWAN_BOGUS flag in ISAKMP payload");
        in.isag_critical |= ISAKMP_PAYLOAD_OPENSWAN_BOGUS;
    }

    if(!out_struct(&in, &ikev2_nonce_desc, outpbs, &pb) ||
       !out_raw(nonce->ptr, nonce->len, &pb, "IKEv2 nonce"))
        return FALSE;
    close_output_pbs(&pb);

    return TRUE;
}

bool justship_v2nat(struct state *st, pb_stream *outpbs)
{
    unsigned char digest[SHA1_DIGEST_SIZE];
    chunk_t hash_chunk;
    bool success;

    calculate_nat_hash(st->st_icookie, st->st_rcookie,
                       st->st_localaddr, st->st_localport, digest);
    setchunk(hash_chunk, digest, SHA1_DIGEST_SIZE);

    success = ship_v2N(ISAKMP_NEXT_NONE, ISAKMP_PAYLOAD_NONCRITICAL,
                       v2N_noSA, NULL, v2N_NAT_DETECTION_SOURCE_IP,
                       &hash_chunk, outpbs);
    if(!success) return FALSE;

    /* now send the notify about NAT_DETECTION_DESTINATION_IP */
    calculate_nat_hash(st->st_icookie, st->st_rcookie, st->st_remoteaddr, st->st_remoteport, digest);
    setchunk(hash_chunk, digest, SHA1_DIGEST_SIZE);
    success = ship_v2N(ISAKMP_NEXT_NONE, ISAKMP_PAYLOAD_NONCRITICAL,
                       v2N_noSA, NULL, v2N_NAT_DETECTION_DESTINATION_IP,
                       &hash_chunk, outpbs);
    if(!success) return FALSE;

    return TRUE;
}

void ikev2_padup_pre_encrypt(struct msg_digest *md
                             , pb_stream *e_pbs_cipher)
{
    struct state *st = md->st;
    struct state *pst= st;

    if(st->st_clonedfrom != 0) {
        pst = state_with_serialno(st->st_clonedfrom);
    }

    /* pads things up to message size boundary */
    {
        size_t blocksize = pst->st_oakley.encrypter->enc_blocksize;
        char  *b = alloca(blocksize);
        unsigned int    i;
        size_t padding =  pad_up(pbs_offset(e_pbs_cipher), blocksize);
        if (padding == 0) padding=blocksize;

        for(i=0; i<padding; i++) {
            b[i]=i;
        }
        out_raw(b, padding, e_pbs_cipher, "padding and length");
    }
}

unsigned char *ikev2_authloc(struct msg_digest *md
                             , pb_stream *e_pbs)
{
    unsigned char *b12;
    struct state *st = md->st;
    struct state *pst = st;

    if(st->st_clonedfrom != 0) {
        pst = state_with_serialno(st->st_clonedfrom);
        if( pst == NULL) {
            return NULL;
        }
    }

    b12 = e_pbs->cur;
    if(!out_zero(pst->st_oakley.integ_hasher->hash_integ_len, e_pbs, "length of truncated HMAC"))
        return NULL;

    return b12;
}

stf_status ikev2_encrypt_msg(struct msg_digest *md,
                                    enum phase1_role init,
                                    unsigned char *authstart,
                                    unsigned char *iv,
                                    unsigned char *encstart,
                                    unsigned char *authloc,
                                    pb_stream *e_pbs UNUSED,
                                    pb_stream *e_pbs_cipher)
{
    struct state *st = md->st;
    struct state *pst = st;
    chunk_t *cipherkey, *authkey;

    /* IKEv2 crypto state is in parent */
    if(st->st_clonedfrom != 0) {
        pst = state_with_serialno(st->st_clonedfrom);
    }

    /* sanity check on inputs */
    if(authloc < authstart) {
       loglog(RC_CRYPTOFAILED, "ikev2 encrypt internal error: authloc<authstart. Please report.");
       return STF_FAIL;
    }

    if(init == INITIATOR) {
        DBG(DBG_CONTROLMORE, DBG_log("encrypting as INITIATOR, parent SA #%lu",
				     pst->st_serialno));
        cipherkey = &pst->st_skey_ei;
        authkey   = &pst->st_skey_ai;
    } else {
        DBG(DBG_CONTROLMORE, DBG_log("encrypting as RESPONDER, parent SA #%lu",
				     pst->st_serialno));
        cipherkey = &pst->st_skey_er;
        authkey   = &pst->st_skey_ar;
    }

    ikev2_validate_key_lengths(st);

    /* encrypt the block */
    {
        size_t  blocksize = pst->st_oakley.encrypter->enc_blocksize;
        unsigned char *savediv = alloca(blocksize);
        unsigned int   cipherlen = e_pbs_cipher->cur - encstart;

        DBG(DBG_CRYPT,
            DBG_dump("data before encryption:", encstart, cipherlen));

        memcpy(savediv, iv, blocksize);

        /* now, encrypt */
        (pst->st_oakley.encrypter->do_crypt)(encstart,
                                            cipherlen,
                                            cipherkey->ptr,
                                            cipherkey->len,
                                            savediv, TRUE);

        DBG(DBG_CRYPT,
            DBG_dump("data after encryption:", encstart, cipherlen));
    }

    /* okay, authenticate from beginning of IV */
    {
        struct hmac_ctx ctx;
        hmac_init_chunk(&ctx, pst->st_oakley.integ_hasher, *authkey);
        hmac_update(&ctx, authstart, authloc-authstart);
        hmac_final(authloc, &ctx);

        DBG(DBG_PARSING,
            DBG_dump("data being hmac:", authstart, authloc-authstart);
            DBG_dump("out calculated auth:", authloc, pst->st_oakley.integ_hasher->hash_integ_len);
            );
    }

    return STF_OK;
}

stf_status ikev2_decrypt_msg(struct msg_digest *md
                             , enum phase1_role init)
{
    struct state *st = md->st;
    unsigned char *encend;
    pb_stream     *e_pbs;
    unsigned int   np;
    unsigned char *iv;
    chunk_t       *cipherkey, *authkey;
    unsigned char *authstart;
    struct state *pst = st;

    /* IKEv2 crypto state is in parent */
    if(st->st_clonedfrom != 0) {
        pst = state_with_serialno(st->st_clonedfrom);
    }

    if(pst->st_oakley.integ_hasher == NULL
       || pst->st_oakley.encrypter == NULL) {
        DBG(DBG_CONTROL
            , DBG_log("can not decyrpt message as no ciphers/hashers selected"));
        return STF_FATAL;
    }
    if(init == INITIATOR) {
        DBG(DBG_CONTROLMORE, DBG_log("decrypting as INITIATOR, using RESPONDER keys"));
        cipherkey = &pst->st_skey_er;
        authkey   = &pst->st_skey_ar;
    } else {
        DBG(DBG_CONTROLMORE, DBG_log("decrypting as RESPONDER, using INITIATOR keys"));
        cipherkey = &pst->st_skey_ei;
        authkey   = &pst->st_skey_ai;
    }

    ikev2_validate_key_lengths(st);

    e_pbs = &md->chain[ISAKMP_NEXT_v2E]->pbs;
    np    = md->chain[ISAKMP_NEXT_v2E]->payload.generic.isag_np;

    authstart=md->packet_pbs.start;
    iv     = e_pbs->cur;
    encend = e_pbs->roof - pst->st_oakley.integ_hasher->hash_integ_len;

    /* start by checking authenticator */
    {
        unsigned char  *b12 = alloca(pst->st_oakley.integ_hasher->hash_digest_len);
        struct hmac_ctx ctx;

        hmac_init_chunk(&ctx, pst->st_oakley.integ_hasher, *authkey);
        hmac_update(&ctx, authstart, encend-authstart);
        hmac_final(b12, &ctx);

        DBG(DBG_PARSING,
            DBG_dump("data being hmac:", authstart, encend-authstart);
            DBG_dump("R2 calculated auth:", b12, pst->st_oakley.integ_hasher->hash_integ_len);
            DBG_dump("R2  provided  auth:", encend, pst->st_oakley.integ_hasher->hash_integ_len);
            );

        /* compare first 96 bits == 12 bytes */
        /* It is not always 96 bytes, it depends upon which integ algo is used*/
        if(memcmp(b12, encend, pst->st_oakley.integ_hasher->hash_integ_len)!=0) {
            openswan_log("R2 failed to match authenticator");

            /* force the notification to go out on the next message ID */
            st->st_msgid = md->msgid_received;

            return STF_FAIL + AUTHENTICATION_FAILED;
        }
    }

    DBG(DBG_PARSING, DBG_log("authenticator matched, np=%u", np));

    /*
     * since the authenticator matched, we update the interface
     * attached to the state, which (might)  change what port/IP we send
     * to from now on.  We only do this if we are the responder.
     */
    if(md->role == RESPONDER) {
        if(st->st_interface != md->iface) {
            DBG(DBG_CONTROL
                , DBG_log("changing iface from %s:%u to %s:%u"
                          , st->st_interface->addrname, st->st_interface->port
                          , md->iface->addrname,md->iface->port));
            st->st_interface = md->iface;
        }
        if(st->st_remoteport != md->sender_port
           || addrcmp(&st->st_remoteaddr, &md->sender)!=0) {
            char b1[ADDRTOT_BUF], b2[ADDRTOT_BUF];

            addrtot(&st->st_remoteaddr, 0, b1, sizeof(b1));
            addrtot(&md->sender,        0, b2, sizeof(b2));
            openswan_log("changing remote addr from %s:%u to %s:%u"
                         , b1, st->st_remoteport
                         , b2, md->sender_port);
            st->st_remoteport = md->sender_port;
            st->st_remoteaddr = md->sender;
        }
    }

    /* decrypt */
    {
        size_t         blocksize = pst->st_oakley.encrypter->enc_blocksize;
        unsigned char *encstart  = iv + blocksize;
        unsigned int   enclen    = encend - encstart;
        unsigned int   padlen;

        DBG(DBG_CRYPT,
            DBG_dump("data before decryption:", encstart, enclen));

        /* now, decrypt */
        (pst->st_oakley.encrypter->do_crypt)(encstart,
                                             enclen,
                                             cipherkey->ptr,
                                             cipherkey->len,
                                             iv, FALSE);

        padlen = encstart[enclen-1];
        encend = encend - padlen+1;

        if(encend < encstart) {
            openswan_log("invalid pad length: %u", padlen);
            return STF_FAIL;
        }

        DBG(DBG_CRYPT,
            DBG_dump("decrypted payload:", encstart, enclen);
            DBG_log("striping %u bytes as pad", padlen+1);
            );

        init_pbs(&md->clr_pbs, encstart, enclen - (padlen+1), "cleartext");
    }

    return ikev2_process_encrypted_payloads(md, &md->clr_pbs, np);
}

static stf_status ikev2_send_auth(struct connection *c
                                  , struct state *st
                                  , enum phase1_role role
                                  , unsigned char *idhash_out
                                  , pb_stream *outpbs)
{
    struct ikev2_a a;
    pb_stream      a_pbs;
    struct state *pst = st;

    if(st->st_clonedfrom != 0) {
        pst = state_with_serialno(st->st_clonedfrom);
    }


    a.isaa_critical = ISAKMP_PAYLOAD_NONCRITICAL;
    if(DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
        openswan_log(" setting bogus ISAKMP_PAYLOAD_OPENSWAN_BOGUS flag in ISAKMP payload");
        a.isaa_critical |= ISAKMP_PAYLOAD_OPENSWAN_BOGUS;
    }

    a.isaa_np = ISAKMP_NEXT_NONE;

    if(c->policy & POLICY_RSASIG) {
        a.isaa_type = v2_AUTH_RSA;
    } else if(c->policy & POLICY_PSK) {
        a.isaa_type = v2_AUTH_SHARED;
    } else {
        /* what else is there?... DSS not implemented. */
        return STF_FAIL;
    }

    /* set the next payload here just in case */
    pbs_set_np(outpbs, ISAKMP_NEXT_v2AUTH);

    if (!out_struct(&a
                    , &ikev2_a_desc
                    , outpbs
                    , &a_pbs))
        return STF_INTERNAL_ERROR;

    if(c->policy & POLICY_RSASIG) {
        if(!ikev2_calculate_rsa_sha1(pst, role, idhash_out, &a_pbs))
            return STF_FATAL + AUTHENTICATION_FAILED;

    } else if(c->policy & POLICY_PSK) {
        if(!ikev2_calculate_psk_auth(pst, role, idhash_out, &a_pbs))
            return STF_FAIL + AUTHENTICATION_FAILED;

        /* hard to identify PSKs without giving them away */
        strcpy(st->st_our_keyid, "psk");
    }

    close_output_pbs(&a_pbs);
    return STF_OK;
}

static void
ikev2_update_nat_ports(struct state *st)
{
    if(st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) {
        if(st->st_remoteport == pluto_port500) {
            loglog(RC_COMMENT, "NAT-T detected, moving to port 4500");
            st->st_remoteport = pluto_port4500;
        }

        /* now pick a new local interface definition for sending traffic out of */
        st->st_interface = pick_matching_interfacebyfamily(interfaces, pluto_port4500
                                                           , st->st_remoteaddr.u.v4.sin_family
                                                           , &st->st_connection->spd);
        if(st->st_interface) {
            st->st_localport = st->st_interface->port;
        } else {
            loglog(RC_COMMENT, "failed to find port 4500 interface");
        }
    }
}

/*
 * Cookie = <VersionIDofSecret> | Hash(Ni | IPi | SPIi | <secret>)
 * where <secret> is a randomly generated secret known only to the
 * in OSW implementation <VersionIDofSecret> is not used.
 */
static bool ikev2_get_dcookie(u_char *dcookie,  chunk_t st_ni
                              ,ip_address *addr, u_int8_t *spiI)
{
    size_t addr_length;
    SHA1_CTX        ctx_sha1;
    unsigned char addr_buff[
                            sizeof(union {struct in_addr A; struct in6_addr B;})];


    addr_length = addrbytesof(addr, addr_buff, sizeof(addr_buff));
    SHA1Init(&ctx_sha1);
    SHA1Update(&ctx_sha1, st_ni.ptr, st_ni.len);
    SHA1Update(&ctx_sha1, addr_buff, addr_length);
    SHA1Update(&ctx_sha1, spiI, sizeof(*spiI));
    SHA1Update(&ctx_sha1, ikev2_secret_of_the_day
               , SHA1_DIGEST_SIZE);
    SHA1Final(dcookie, &ctx_sha1);
    DBG(DBG_PRIVATE
        ,DBG_log("ikev2 secret_of_the_day used %s, length %d"
                 , ikev2_secret_of_the_day
                 , SHA1_DIGEST_SIZE););

    DBG(DBG_CRYPT
        ,DBG_dump("computed dcookie: HASH(Ni | IPi | SPIi | <secret>)"
                  , dcookie, SHA1_DIGEST_SIZE));
#if 0
    ikev2_secrets_recycle++;
    if(ikev2_secrets_recycle >= 32768) {
        /* handed out too many cookies, cycle secrets */
        ikev2_secrets_recycle = 0;
        /* can we call init_secrets() without adding an EVENT? */
        init_secrets();
    }
#endif
    return TRUE;
}

/* details moved to seperate files for readability */
#include "ikev2_parent_I1.c"
#include "ikev2_parent_R1.c"
#include "ikev2_parent_I2.c"
#include "ikev2_parent_R2.c"
#include "ikev2_parent_I3.c"

static inline bool isakmp_xchg_type_is_valid(enum isakmp_xchg_types xchg)
{
    switch (xchg) {
    default:
        return FALSE;

    case ISAKMP_XCHG_NONE:
    case ISAKMP_XCHG_BASE:
    case ISAKMP_XCHG_IDPROT:
    case ISAKMP_XCHG_AO:
    case ISAKMP_XCHG_AGGR:
    case ISAKMP_XCHG_INFO:
    case ISAKMP_XCHG_MODE_CFG:

    /* Private exchanges to pluto -- tried to write an RFC */
    case ISAKMP_XCHG_ECHOREQUEST:
    case ISAKMP_XCHG_ECHOREPLY:

    /* Extra exchange types, defined by Oakley
     * RFC2409 "The Internet Key Exchange (IKE)", near end of Appendix A
     */
    case ISAKMP_XCHG_QUICK:
    case ISAKMP_XCHG_NGRP:

    /* IKEv2 things */
    case ISAKMP_v2_SA_INIT:
    case ISAKMP_v2_AUTH:
    case ISAKMP_v2_CHILD_SA:
    case ISAKMP_v2_INFORMATIONAL:

    case ISAKMP_XCHG_ECHOREQUEST_PRIVATE:
    case ISAKMP_XCHG_ECHOREPLY_PRIVATE:
        return TRUE;
    }
}

/*
 *
 ***************************************************************
 *                       NOTIFICATION_OUT Complete packet  *****
 ***************************************************************
 *
 */

void
send_v2_notification(struct state *p1st
		       , enum isakmp_xchg_types xchg_type
		       , notification_t ntf_type
		       , u_char *icookie
		       , u_char *rcookie
		       , chunk_t *notify_data)
{
    pb_stream reply;
    pb_stream rbody;

    /* this function is not generic enough yet just enough for 6msg
     * TBD accept HDR FLAGS as arg. default ISAKMP_FLAGS_R
     * TBD when there is a child SA use that SPI in the notify paylod.
     * TBD accept Critical bit as an argument. default is set.
     * do we need to send a notify with empty data?
     * do we need to support more Protocol ID? more than PROTO_ISAKMP
     */

    openswan_log("sending notification %s/%s to %s:%u"
                 , enum_name(&exchange_names, xchg_type)
                 , enum_name(&ikev2_notify_names, ntf_type)
                 , p1st ? ip_str(&p1st->st_remoteaddr) : "-"
                 , p1st ? p1st->st_remoteport : 0);

    passert(isakmp_xchg_type_is_valid(xchg_type));

    zero(reply_buffer);
    init_pbs(&reply, reply_buffer, sizeof(reply_buffer), "notification msg");

    /* HDR out */
    {
        struct isakmp_hdr n_hdr ;
        zero(&n_hdr);     /* default to 0 */  /* AAA should we copy from MD? */
        if(DBGP(IMPAIR_MAJOR_VERSION_BUMP)) /* testing fake major new IKE version, should fail */
            n_hdr.isa_version = IKEv2_MAJOR_BUMP << ISA_MAJ_SHIFT | IKEv2_MINOR_VERSION;
        else if(DBGP(IMPAIR_MINOR_VERSION_BUMP)) /* testing fake minor new IKE version, should success */
            n_hdr.isa_version = IKEv2_MAJOR_VERSION << ISA_MAJ_SHIFT | IKEv2_MINOR_BUMP;
        else /* normal production case with real version */
            n_hdr.isa_version = IKEv2_MAJOR_VERSION << ISA_MAJ_SHIFT | IKEv2_MINOR_VERSION;
        memcpy(n_hdr.isa_rcookie, rcookie, COOKIE_SIZE);
        memcpy(n_hdr.isa_icookie, icookie, COOKIE_SIZE);
        n_hdr.isa_xchg = xchg_type;
        n_hdr.isa_np = ISAKMP_NEXT_v2N;

        n_hdr.isa_flags = ISAKMP_FLAGS_R|IKEv2_ORIG_INITIATOR_FLAG(p1st);
        n_hdr.isa_msgid = htonl(p1st->st_msgid);

        if (!out_struct(&n_hdr, &isakmp_hdr_desc, &reply, &rbody)) {
	    openswan_log("error initializing hdr for notify message");
	    return;
	}
    }

    /* build and add v2N payload to the packet */
    ship_v2N (ISAKMP_NEXT_NONE, ISAKMP_PAYLOAD_NONCRITICAL, PROTO_ISAKMP,
	      NULL, ntf_type, notify_data, &rbody);

    close_message(&rbody);
    close_output_pbs(&reply);

    clonetochunk(p1st->st_tpacket, reply.start, pbs_offset(&reply)
		 , "notification packet");

    send_packet(p1st, __FUNCTION__, TRUE);
}

#if 0
static void breakpoint_here(void)
{
DBG_log("%s:%u", __FUNCTION__, __LINE__);
}
#endif

int
send_v2_notification_enc(struct msg_digest *md
		       , enum isakmp_xchg_types xchg_type
		       , notification_t ntf_type
		       , chunk_t *notify_data)

{
    struct state *st;
    struct ikev2_generic e;
    unsigned char *encstart;
    pb_stream      e_pbs, e_pbs_cipher;
    unsigned char *iv;
    int            ivsize;
    stf_status     ret;
    unsigned char *authstart;

    st = md->st;
    if (!st) {
        openswan_log("cannot send notification %s/%s, state is NULL"
                     , enum_name(&exchange_names, xchg_type)
                     , enum_name(&ikev2_notify_names, ntf_type));
        return STF_INTERNAL_ERROR;
    }

    zero(&e);
    zero(&e_pbs);
    zero(&e_pbs_cipher);

    /* beginning of data going out */
    authstart = reply_stream.cur;

    /* make sure HDR is at start of a clean buffer */
    zero(reply_buffer);
    init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer), "enc notification msg");

    openswan_log("sending encrypted notification %s/%s to %s:%u"
                 , enum_name(&exchange_names, xchg_type)
                 , enum_name(&ikev2_notify_names, ntf_type)
                 , ip_str(&st->st_remoteaddr)
                 , st->st_remoteport);

    /* HDR out */
    {
        struct isakmp_hdr r_hdr = md->hdr;

        r_hdr.isa_version = IKEv2_MAJOR_VERSION << ISA_MAJ_SHIFT | IKEv2_MINOR_VERSION;
        r_hdr.isa_np    = ISAKMP_NEXT_v2E;
        r_hdr.isa_xchg  = xchg_type;

        /* we should set the I bit, if we are the original initiator of the
         * the parent SA.
         */
        r_hdr.isa_flags = ISAKMP_FLAGS_R|ISAKMP_FLAGS_E|IKEv2_ORIG_INITIATOR_FLAG(st);
        r_hdr.isa_msgid = htonl(st->st_msgid);
        memcpy(r_hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
        memcpy(r_hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
        if (!out_struct(&r_hdr, &isakmp_hdr_desc, &reply_stream, &md->rbody))
            return STF_INTERNAL_ERROR;
    }

    e.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;
    pbs_set_np(&md->rbody, ISAKMP_NEXT_v2E);
    if(!out_struct(&e, &ikev2_e_desc, &md->rbody, &e_pbs)) {
        return STF_INTERNAL_ERROR;
    }

    /* insert IV */
    iv     = e_pbs.cur;
    ivsize = st->st_oakley.encrypter->iv_size;
    if(!out_zero(ivsize, &e_pbs, "iv")) {
        return STF_INTERNAL_ERROR;
    }
    get_rnd_bytes(iv, ivsize);

    /* note where cleartext starts */
    init_sub_pbs(&e_pbs, &e_pbs_cipher, "cleartext");
    encstart = e_pbs_cipher.cur;

    /* send Notification */
    ret = ship_v2N (ISAKMP_NEXT_NONE, ISAKMP_PAYLOAD_NONCRITICAL, PROTO_ISAKMP,
		   NULL, ntf_type, notify_data, &e_pbs_cipher);
    if (!ret)
	return STF_INTERNAL_ERROR;

    /*
     * need to extend the packet so that we will know how big it is
     * since the length is under the integrity check
     */
    ikev2_padup_pre_encrypt(md, &e_pbs_cipher);
    close_output_pbs(&e_pbs_cipher);

    {
	enum phase1_role i_am;
        unsigned char *authloc = ikev2_authloc(md, &e_pbs);

        if(authloc == NULL || authloc < encstart) return STF_INTERNAL_ERROR;

        close_output_pbs(&e_pbs);
        close_output_pbs(&md->rbody);
        close_output_pbs(&reply_stream);

	i_am = IKEv2_IS_ORIG_INITIATOR(st) ? INITIATOR : RESPONDER;
        ret = ikev2_encrypt_msg(md, i_am,
                                authstart,
                                iv, encstart, authloc,
                                &e_pbs, &e_pbs_cipher);

        if(ret != STF_OK) return ret;
    }

    /* keep it for a retransmit if necessary, but on initiator
     * we never do that, but send_packet() uses it.
     */
    freeanychunk(st->st_tpacket);
    clonetochunk(st->st_tpacket, reply_stream.start, pbs_offset(&reply_stream)
                 , "encrypted notification packet");

    send_packet(st, __FUNCTION__, TRUE);

    return STF_OK;
}

/*
 *
 ***************************************************************
 *                       INFORMATIONAL                     *****
 ***************************************************************
 *  -
 * XXX -- wow this function is a mess.
 *
 */
stf_status process_informational_ikev2(struct msg_digest *md)
{
    /* verify that there is in fact an encrypted payload */
    if(!md->chain[ISAKMP_NEXT_v2E]) {
        openswan_log("Ignoring informational exchange outside encrypted payload (rfc5996 section 1.4)");
        return STF_IGNORE;
    }

    /* decrypt things. */
    {
	stf_status ret;
        if(IKEv2_ORIGINAL_INITIATOR(md->hdr.isa_flags)) {
           DBG(DBG_CONTROLMORE
              , DBG_log("received informational exchange %s from INITIATOR"
                        , IKEv2_MSG_FROM_INITIATOR(md->hdr.isa_flags)
                            ? "request" : "response"));
           ret = ikev2_decrypt_msg(md, RESPONDER);
        }
        else {
           DBG(DBG_CONTROLMORE
              , DBG_log("received informational exchange %s from RESPONDER"
                        , IKEv2_MSG_FROM_INITIATOR(md->hdr.isa_flags)
                            ? "request" : "response"));
           ret = ikev2_decrypt_msg(md, INITIATOR);
        }

        if(ret != STF_OK) return ret;
    }


    {
        struct payload_digest *p;
        struct ikev2_delete *v2del=NULL;
        stf_status ret;
        struct state *st = md->st;

        /* Only send response if it is request (we are responder!) */
        if (IKEv2_MSG_FROM_INITIATOR(md->hdr.isa_flags)) {
            unsigned char *authstart;
            pb_stream      e_pbs, e_pbs_cipher;
            struct ikev2_generic e;
            unsigned char *iv;
            int            ivsize;
            unsigned char *encstart;

            /* make sure HDR is at start of a clean buffer */
            zero(reply_buffer);
            init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer), "information exchange reply packet");

            /* beginning of data going out */
            authstart = reply_stream.cur;

            /* HDR out */
            {
                struct isakmp_hdr r_hdr ;
                zero(&r_hdr);     /* default to 0 */  /* AAA should we copy from MD? */
                r_hdr.isa_version = IKEv2_MAJOR_VERSION << ISA_MAJ_SHIFT | IKEv2_MINOR_VERSION;
                memcpy(r_hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
                memcpy(r_hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
                r_hdr.isa_xchg = ISAKMP_v2_INFORMATIONAL;
                r_hdr.isa_np = ISAKMP_NEXT_v2E;
                r_hdr.isa_msgid = htonl(md->msgid_received);
                r_hdr.isa_flags = ISAKMP_FLAGS_R|IKEv2_ORIG_INITIATOR_FLAG(st);

                if (!out_struct(&r_hdr, &isakmp_hdr_desc, &reply_stream, &md->rbody))
                    {
                        openswan_log("error initializing hdr for informational message");
                        return STF_INTERNAL_ERROR;
                    }

            }/*HDR Done*/


            /* insert an Encryption payload header */
            if(md->chain[ISAKMP_NEXT_v2D])
                {
                    bool ikesa_flag = FALSE;
                    /* Search if there is a IKE SA delete payload*/
                    for(p = md->chain[ISAKMP_NEXT_v2D]; p!=NULL; p = p->next) {
                        if(p->payload.v2delete.isad_protoid == PROTO_ISAKMP)
                            {
                                e.isag_np = ISAKMP_NEXT_NONE;
                                ikesa_flag = TRUE;
                                break;
                            }
                    }
                    /* if there is no IKE SA DELETE PAYLOAD*/
                    /* That means, there are AH OR ESP*/
                    if(!ikesa_flag) {
                        e.isag_np = ISAKMP_NEXT_v2D;
                    }


                }
            else
                {
                    e.isag_np = ISAKMP_NEXT_NONE;
                }

            e.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;

            if(!out_struct(&e, &ikev2_e_desc, &md->rbody, &e_pbs)) {
                return STF_INTERNAL_ERROR;
            }

            /* insert IV */
            iv     = e_pbs.cur;
            ivsize = st->st_oakley.encrypter->iv_size;
            if(!out_zero(ivsize, &e_pbs, "iv")) {
                return STF_INTERNAL_ERROR;
            }
            get_rnd_bytes(iv, ivsize);

            /* note where cleartext starts */
            init_sub_pbs(&e_pbs, &e_pbs_cipher, "cleartext");
            encstart = e_pbs_cipher.cur;

            if(md->chain[ISAKMP_NEXT_v2D]) {
                for(p = md->chain[ISAKMP_NEXT_v2D]; p!=NULL; p = p->next) {
                    v2del = &p->payload.v2delete;

                    switch (v2del->isad_protoid) {
                    case PROTO_ISAKMP:
                        /* My understanding is that delete payload for IKE SA
                         *  should be the only payload in the informational exchange
                         */
                        break;

                    case PROTO_IPSEC_AH:
                    case PROTO_IPSEC_ESP: {
                        char spi_buf[1024];
                        pb_stream del_pbs;
                        struct ikev2_delete v2del_tmp;
                        u_int16_t i, j=0;
                        u_char *spi;

                        for(i = 0; i < v2del->isad_nrspi; i++ ) {
                            spi = p->pbs.cur + (i * v2del->isad_spisize);
                            DBG(DBG_CONTROLMORE, DBG_log("received delete request for %s SA(0x%08lx)"
                                                         , enum_show(&protocol_names, v2del->isad_protoid)
                                                         , (unsigned long)ntohl((unsigned long)*(ipsec_spi_t *)spi)));

                            struct state *dst = find_state_ikev2_child_to_delete (st->st_icookie
                                                                                  , st->st_rcookie
                                                                                  , v2del->isad_protoid
                                                                                  , *(ipsec_spi_t *)spi);

                            if(dst != NULL) {
                                struct ipsec_proto_info *pr = v2del->isad_protoid == PROTO_IPSEC_AH? &dst->st_ah : &dst->st_esp;
                                DBG(DBG_CONTROLMORE, DBG_log("our side spi that needs to be sent: %s SA(0x%08lx)"
                                                             , enum_show(&protocol_names, v2del->isad_protoid)
                                                             , (unsigned long)ntohl(pr->our_spi)));

                                memcpy(spi_buf + (j * v2del->isad_spisize), (u_char *)&pr->our_spi, v2del->isad_spisize);
                                j++;
                            }
                            else {
                                DBG(DBG_CONTROLMORE, DBG_log("received delete request for %s SA(0x%08lx) but local state is not found"
                                                             , enum_show(&protocol_names, v2del->isad_protoid)
                                                             , (unsigned long)ntohl((unsigned long)*(ipsec_spi_t *)spi)));
                            }
                        }

                        if( !j ) {
                            DBG(DBG_CONTROLMORE, DBG_log("This delete payload does not contain a single spi that has any local state, ignoring"));
                            return STF_IGNORE;
                        }
                        else {
                            DBG(DBG_CONTROLMORE, DBG_log("Number of SPIs to be sent %d", j);
                                DBG_dump(" Emit SPIs", spi_buf, j*v2del->isad_spisize));
                        }

                        zero(&v2del_tmp);

                        if(p->next != NULL) {
                            v2del_tmp.isad_np = ISAKMP_NEXT_v2D;
                        }
                        else {
                            v2del_tmp.isad_np = ISAKMP_NEXT_NONE;
                        }

                        v2del_tmp.isad_protoid = v2del->isad_protoid;
                        v2del_tmp.isad_spisize = v2del->isad_spisize;
                        v2del_tmp.isad_nrspi = j;

                        /* Emit delete payload header out*/
                        if (!out_struct(&v2del_tmp, &ikev2_delete_desc, &e_pbs_cipher, &del_pbs)) {
                            openswan_log("error initializing hdr for delete payload");
                            return STF_INTERNAL_ERROR;
                        }

                        /* Emit values of spi to be sent to the peer*/
                        if (!out_raw(spi_buf, j* v2del->isad_spisize, &del_pbs, "local spis")) {
                            openswan_log("error sending spi values in delete payload");
                            return STF_INTERNAL_ERROR;
                        }

                        close_output_pbs(&del_pbs);

                    }
                        break;
                    default:
                        /*Unrecongnized protocol */
                        return STF_IGNORE;
                    }

                    /* this will break from for loop*/
                    if(v2del->isad_protoid == PROTO_ISAKMP) {
                        break;
                    }
                }
            }

            /*If there are no payloads or in other words empty payload in request
             * that means it is check for liveliness, so send an empty payload message
             * this will end up sending an empty payload
             */

            ikev2_padup_pre_encrypt(md, &e_pbs_cipher);
            close_output_pbs(&e_pbs_cipher);

            {
                unsigned char *authloc = ikev2_authloc(md, &e_pbs);
                if(authloc == NULL || authloc < encstart) return STF_INTERNAL_ERROR;

                close_output_pbs(&e_pbs);
                close_output_pbs(&md->rbody);
                close_output_pbs(&reply_stream);

		if (IKEv2_ORIGINAL_INITIATOR(md->hdr.isa_flags)) {
			/* packet arrived from INITIATOR, we encrypt as RESPONDER */
			ret = ikev2_encrypt_msg(md, RESPONDER,
						authstart,
						iv, encstart, authloc,
						&e_pbs, &e_pbs_cipher);
		} else {
			/* packet arrived from RESPONDER, we encrypt as INITIATOR */
			ret = ikev2_encrypt_msg(md, INITIATOR,
						authstart,
						iv, encstart, authloc,
						&e_pbs, &e_pbs_cipher);
		}
                if(ret != STF_OK) return ret;
            }

            /* let TCL hack it before we mark the length. */
            TCLCALLOUT("v2_avoidEmitting", st, st->st_connection, md);

            /* keep it for a retransmit if necessary */
            freeanychunk(st->st_tpacket);
            clonetochunk(st->st_tpacket, reply_stream.start, pbs_offset(&reply_stream)
                         , "reply packet for informational exchange");

            send_packet(st, __FUNCTION__, TRUE);
	}

	/* Now carry out the actualy task, we can not carry the actual task since
         * we need to send informational responde using existing SAs
         */

        if(md->chain[ISAKMP_NEXT_v2D]) {
            for(p = md->chain[ISAKMP_NEXT_v2D]; p!=NULL; p = p->next) {
                v2del = &p->payload.v2delete;

                /* catch and report additional delete payloads after we deleted
                 * the parent SA state already */
                if (!st) {
                    DBG(DBG_CONTROLMORE, DBG_log("received delete request for %s but parent ISAKMP SA already deleted; ignoring"
                                                 , enum_show(&protocol_names, v2del->isad_protoid)));
                    continue;
                }

                switch (v2del->isad_protoid) {
                case PROTO_ISAKMP:
                    /* My understanding is that delete payload for IKE SA
                     *  should be the only payload in the informational */
                    if (IS_CHILD_SA(st)) {
                        DBG(DBG_CONTROLMORE,
                            DBG_log("received delete request for %s via #%ld child SA; looking up parent #%ld..."
                                    , enum_show(&protocol_names, v2del->isad_protoid)
                                    , st->st_serialno, st->st_clonedfrom));
                        st = state_with_serialno(st->st_clonedfrom);
                        if (!st) {
                            DBG(DBG_CONTROLMORE,
                                DBG_log("parent SA #%ld not found; ignoring"
                                        , md->st->st_clonedfrom));
                            continue;
                        }
                    }
                    DBG(DBG_CONTROLMORE, DBG_log("received delete request for %s via #%ld; deleting #%ld"
                                                 , enum_show(&protocol_names, v2del->isad_protoid)
                                                 , md->st->st_serialno, st->st_serialno));

                    /* Now delete the IKE SA state and all its child states */
                    delete_state_family(st, TRUE);
                    /* we cannot trust st after it's deleted */
                    st = md->st = NULL;
                    break;

                case PROTO_IPSEC_AH:
                case PROTO_IPSEC_ESP:
                    {
                        //pb_stream del_pbs;
                        struct ikev2_delete;
                        u_int16_t i;
                        u_char *spi;

                        for(i = 0; i < v2del->isad_nrspi; i++ )
                            {
                                spi = p->pbs.cur + (i * v2del->isad_spisize);
                                DBG(DBG_CONTROLMORE, DBG_log("Now doing actual deletion for request: %s SA(0x%08lx)"
                                                             , enum_show(&protocol_names, v2del->isad_protoid)
                                                             , (unsigned long)ntohl((unsigned long)*(ipsec_spi_t *)spi)));

                                struct state *dst = find_state_ikev2_child_to_delete (st->st_icookie
                                                                                      , st->st_rcookie
                                                                                      , v2del->isad_protoid
                                                                                      , *(ipsec_spi_t *)spi);

                                if(dst != NULL)
                                    {
                                        struct ipsec_proto_info *pr = v2del->isad_protoid == PROTO_IPSEC_AH? &dst->st_ah : &dst->st_esp;
                                        DBG(DBG_CONTROLMORE, DBG_log("received delete request for #%lu via #%lu, our %s SA spi: 0x%08lx"
								     , dst->st_serialno, st->st_serialno
                                                                     , enum_show(&protocol_names, v2del->isad_protoid)
                                                                     , (unsigned long)ntohl(pr->our_spi)));

                                        /* now delete the state*/
                                        change_state(dst, STATE_CHILDSA_DEL);
                                        delete_state(dst);
                                    }
                                else
                                    {
                                        DBG(DBG_CONTROLMORE, DBG_log("received delete request for %s SA(0x%08lx) but local state is not found"
                                                                     , enum_show(&protocol_names, v2del->isad_protoid)
                                                                     , (unsigned long)ntohl((unsigned long)*(ipsec_spi_t *)spi)));
                                    }
                            }
                    }
                    break;

                default:
                    /*Unrecongnized protocol */
                    return STF_IGNORE;
                }

                /* this will break from for loop*/
                if(v2del->isad_protoid == PROTO_ISAKMP) {
                    break;
                }

            } /* for */

        } /* if have D payload */
	else {
	    /* empty response to our IKESA delete request*/
	    if((md->hdr.isa_flags & ISAKMP_FLAGS_R)) {
		/* My understanding is that delete payload for IKE SA
		 *  should be the only payload in the informational */
		if (IS_CHILD_SA(st)) {
		    DBG(DBG_CONTROLMORE,
			DBG_log("received empty delete response via #%ld child SA; looking up parent #%ld..."
				, st->st_serialno, st->st_clonedfrom));
		    st = state_with_serialno(st->st_clonedfrom);
		    if (!st) {
			DBG(DBG_CONTROLMORE,
			    DBG_log("parent SA #%ld not found; ignoring"
				    , md->st->st_clonedfrom));
			return STF_IGNORE;
		    }
		}

		if (st->st_state != STATE_IKESA_DEL) {
		    DBG(DBG_CONTROLMORE,
			DBG_log("parent SA #%ld in %s; ignoring"
				, st->st_serialno
				, enum_name(&state_names, st->st_state)));
		    return STF_IGNORE;
		}


		DBG(DBG_CONTROLMORE,
		    DBG_log("received empty delete response via #%ld; deleting #%ld"
			    , md->st->st_serialno, st->st_serialno));

		/* Now delete the IKE SA state and all its child states */
		delete_state_family(st, TRUE);

		/* we cannot trust st after it's deleted */
		st = md->st = NULL;
	    }
	}
    }

    return STF_IGNORE;
}

/*
 *
 ***************************************************************
 *                       DELETE_OUT                        *****
 ***************************************************************
 *
 */
void ikev2_delete_out(struct state *st)
{
    struct state *pst = st;
    int ret = STF_OK;

    if(st->st_clonedfrom != 0) {
        /*child SA*/
        pst = state_with_serialno(st->st_clonedfrom);

        if(!pst) {
            DBG(DBG_CONTROL, DBG_log("IKE SA does not exist for this child SA"));
            DBG(DBG_CONTROL, DBG_log("INFORMATIONAL exchange can not be sent, deleting state"));
            goto end;
        }
    }

    {
        unsigned char *authstart;
        pb_stream      e_pbs, e_pbs_cipher;
        pb_stream rbody;
        struct ikev2_generic e;
        unsigned char *iv;
        int            ivsize;
        unsigned char *encstart;
        struct msg_digest md;
        enum phase1_role role;

        md.st = st;
        md.pst= pst;

        /* make sure HDR is at start of a clean buffer */
        zero(reply_buffer);
        init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer), "information exchange request packet");

        ret = allocate_msgid_from_parent(pst, &st->st_msgid);
        if(ret != STF_OK) {
            loglog(RC_LOG_SERIOUS, "can not allocate new msgid, delete not sent");
            goto end;
        }

        /* beginning of data going out */
        authstart = reply_stream.cur;

        /* HDR out */
        {
            struct isakmp_hdr r_hdr ;
            zero(&r_hdr);     /* default to 0 */  /* AAA should we copy from MD? */
            r_hdr.isa_version = IKEv2_MAJOR_VERSION << ISA_MAJ_SHIFT | IKEv2_MINOR_VERSION;
            memcpy(r_hdr.isa_rcookie, pst->st_rcookie, COOKIE_SIZE);
            memcpy(r_hdr.isa_icookie, pst->st_icookie, COOKIE_SIZE);
            r_hdr.isa_xchg = ISAKMP_v2_INFORMATIONAL;
            r_hdr.isa_np = ISAKMP_NEXT_v2E;
            r_hdr.isa_msgid = htonl(st->st_msgid);

            /*set initiator bit if we are initiator*/
	    role = IKEv2_ORIGINAL_ROLE(pst);
            r_hdr.isa_flags = IKEv2_ORIG_INITIATOR_FLAG(pst);

           DBG(DBG_CONTROLMORE
              , DBG_log("preparing to delete #%ld, we are the original %s of parent #%ld"
			, st->st_serialno
                        , (role == INITIATOR) ? "INITIATOR" : (role == RESPONDER) ? "RESPONDER" : "?"
			, pst->st_serialno));

            if (!out_struct(&r_hdr, &isakmp_hdr_desc, &reply_stream, &rbody))
                {
                    openswan_log("error initializing hdr for informational message");
                    goto end;
                }

        }/*HDR Done*/


        /* insert an Encryption payload header */
        e.isag_np = ISAKMP_NEXT_v2D;
        e.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;

        if(!out_struct(&e, &ikev2_e_desc, &rbody, &e_pbs)) {
            goto end;
        }

        /* insert IV */
        iv     = e_pbs.cur;
        ivsize = pst->st_oakley.encrypter->iv_size;
        if(!out_zero(ivsize, &e_pbs, "iv")) {
            goto end;
        }
        get_rnd_bytes(iv, ivsize);

        /* note where cleartext starts */
        init_sub_pbs(&e_pbs, &e_pbs_cipher, "cleartext");
        encstart = e_pbs_cipher.cur;

        {
            pb_stream del_pbs;
            struct ikev2_delete v2del_tmp;

            zero(&v2del_tmp);
            v2del_tmp.isad_np = ISAKMP_NEXT_NONE;

            if(st->st_clonedfrom != 0 ) {
                v2del_tmp.isad_protoid = PROTO_IPSEC_ESP;
                v2del_tmp.isad_spisize = sizeof(ipsec_spi_t);
                v2del_tmp.isad_nrspi = 1;
            }
            else {
                v2del_tmp.isad_protoid = PROTO_ISAKMP;
                v2del_tmp.isad_spisize = 0;
                v2del_tmp.isad_nrspi = 0;
            }

            /* Emit delete payload header out*/
            if (!out_struct(&v2del_tmp, &ikev2_delete_desc, &e_pbs_cipher, &del_pbs))
                {
                    openswan_log("error initializing hdr for delete payload");
                    goto end;
                }

            /* Emit values of spi to be sent to the peer*/
            if(st->st_clonedfrom != 0){
                if (!out_raw( (u_char *)&st->st_esp.our_spi ,sizeof(ipsec_spi_t), &del_pbs, "local spis"))
                    {
                        openswan_log("error sending spi values in delete payload");
                        goto end;
                    }
            }

            close_output_pbs(&del_pbs);

        }

        ikev2_padup_pre_encrypt(&md, &e_pbs_cipher);
        close_output_pbs(&e_pbs_cipher);

        {
            stf_status ret;
            unsigned char *authloc = ikev2_authloc(&md, &e_pbs);
            if(authloc == NULL || authloc < encstart)  goto end;
            close_output_pbs(&e_pbs);
            close_output_pbs(&rbody);
            close_output_pbs(&reply_stream);

            ret = ikev2_encrypt_msg(&md, role,
                                    authstart,
                                    iv, encstart, authloc,
                                    &e_pbs, &e_pbs_cipher);
            if(ret != STF_OK) goto end;
        }


        /* let TCL hack it before we mark the length. */
        TCLCALLOUT("v2_avoidEmitting", pst, pst->st_connection, &md);

        /* keep it for a retransmit if necessary */
        freeanychunk(pst->st_tpacket);
        clonetochunk(pst->st_tpacket, reply_stream.start, pbs_offset(&reply_stream)
                     , "request packet for informational exchange");

        send_packet(pst, __FUNCTION__, TRUE);

        /* update state */
        ikev2_update_counters(&md);

    }

    /* If everything is fine, and we sent packet, goto real_end*/
    goto real_end;

 end:
    /* If some error occurs above that prevents us sending a request packet*/
    /* delete the states right now*/

    if(st->st_clonedfrom != SOS_NOBODY) {
        change_state(st, STATE_CHILDSA_DEL);
        delete_state(st);
    } else {

        struct state *current_st = pst;
        struct state *next_st = NULL;
        struct state *first_st = NULL;

        /* Find the first state in the hash chain*/
        while(current_st != (struct state *) NULL) {
            first_st = current_st;
            current_st = first_st->st_hashchain_prev;
        }

        current_st = first_st;
        while (current_st != (struct state *) NULL) {
            next_st = current_st->st_hashchain_next;
            if(current_st->st_clonedfrom !=0 ) {
                change_state(current_st, STATE_CHILDSA_DEL);
            } else {
                change_state(current_st, STATE_IKESA_DEL);
            }
            delete_state(current_st);
            current_st = next_st;
        }
    }

 real_end:;
}


/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
