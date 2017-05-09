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
#include "state.h"
#include "id.h"
#include "pluto/connections.h"
#include "hostpair.h"

#include "crypto.h" /* requires sha1.h and md5.h */
#include "x509.h"
#include "x509more.h"
#include "ike_alg.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "pluto_crypt.h"
#include "packet.h"
#include "demux.h"
#include "ikev2.h"
#include "log.h"
#include "spdb.h"          /* for out_sa */
#include "ipsec_doi.h"
#include "vendor.h"
#include "timer.h"
#include "ike_continuations.h"
#include "cookie.h"
#include "rnd.h"
#include "pending.h"
#include "kernel.h"
#include "pluto/nat_traversal.h"

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

    success = ship_v2N(0, ISAKMP_PAYLOAD_NONCRITICAL,
                       v2N_noSA, NULL, v2N_NAT_DETECTION_SOURCE_IP,
                       &hash_chunk, outpbs);
    if(!success) return FALSE;

    /* now send the notify about NAT_DETECTION_DESTINATION_IP */
    calculate_nat_hash(st->st_icookie, st->st_rcookie, st->st_remoteaddr, st->st_remoteport, digest);
    setchunk(hash_chunk, digest, SHA1_DIGEST_SIZE);
    success = ship_v2N(0, ISAKMP_PAYLOAD_NONCRITICAL,
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
        cipherkey = &pst->st_skey_ei;
        authkey   = &pst->st_skey_ai;
    } else {
        cipherkey = &pst->st_skey_er;
        authkey   = &pst->st_skey_ar;
    }

    /* encrypt the block */
    {
        size_t  blocksize = pst->st_oakley.encrypter->enc_blocksize;
        unsigned char *savediv = alloca(blocksize);
        unsigned int   cipherlen = e_pbs_cipher->cur - encstart;

        DBG(DBG_CRYPT,
            DBG_dump("data before encryption:", encstart, cipherlen));

        memcpy(savediv, iv, blocksize);

        /* now, encrypt */
        (st->st_oakley.encrypter->do_crypt)(encstart,
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

    if(st->st_clonedfrom != 0) {
        pst = state_with_serialno(st->st_clonedfrom);
    }

    if(init == INITIATOR) {
        cipherkey = &st->st_skey_er;
        authkey   = &st->st_skey_ar;
    } else {
        cipherkey = &st->st_skey_ei;
        authkey   = &st->st_skey_ai;
    }

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
            return STF_FAIL;
        }
    }

    DBG(DBG_PARSING, DBG_log("authenticator matched, np=%u", np));

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
                                  , unsigned int np
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

    a.isaa_np = np;

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
            openswan_log("NAT-T detected, moving to port 4500");
            st->st_remoteport = pluto_port4500;
        }

        /* now pick a new local interface definition for sending traffic out of */
        st->st_interface = pick_matching_interfacebyfamily(interfaces, pluto_port4500
                                                           , st->st_remoteaddr.u.v4.sin_family
                                                           , &st->st_connection->spd);
    }
}

/* details moved to seperate files for readability */
#include "ikev2_parent_I1.c"
#include "ikev2_parent_R1.c"
#include "ikev2_parent_I2.c"


/*
 *
 ***************************************************************
 *                       PARENT_inI2                       *****
 ***************************************************************
 *  - note that in IKEv1, the child states are identified by msgid,
 *  - but in IKEv2, the msgid is just about retransmissions.
 *  - child states are therefore just contains IPsec SAs, and
 *     so that they can be manipulated, and eventually rekeyed or deleted.
 *
 */
static void ikev2_parent_inI2outR2_continue(struct pluto_crypto_req_cont *pcrc
                                            , struct pluto_crypto_req *r
                                            , err_t ugh);

static stf_status
ikev2_parent_inI2outR2_tail(struct pluto_crypto_req_cont *pcrc
                            , struct pluto_crypto_req *r);

stf_status ikev2parent_inI2outR2(struct msg_digest *md)
{
    struct state *st = md->st;
    /* struct connection *c = st->st_connection; */

    /*
     * the initiator sent us an encrypted payload. We need to calculate
     * our g^xy, and skeyseed values, and then decrypt the payload.
     */

    DBG(DBG_CONTROLMORE
        , DBG_log("ikev2 parent inI2outR2: calculating g^{xy} in order to decrypt I2"));

    /* verify that there is in fact an encrypted payload */
    if(!md->chain[ISAKMP_NEXT_v2E]) {
        openswan_log("R2 state should receive an encrypted payload");
        reset_globals();
        return STF_FATAL;
    }

    /* now. we need to go calculate the g^xy */
    {
        struct dh_continuation *dh = alloc_thing(struct dh_continuation
                                                 , "ikev2_inI2outR2 KE");
        stf_status e;

        dh->md = md;
        set_suspended(st, dh->md);

        pcrc_init(&dh->dh_pcrc);
        dh->dh_pcrc.pcrc_func = ikev2_parent_inI2outR2_continue;
        e = start_dh_v2(&dh->dh_pcrc, st, st->st_import, RESPONDER, st->st_oakley.groupnum);
        if(e != STF_SUSPEND && e != STF_INLINE) {
            loglog(RC_CRYPTOFAILED, "system too busy");
            delete_state(st);
        }

        reset_globals();

        return e;
    }
}

static void
ikev2_parent_inI2outR2_continue(struct pluto_crypto_req_cont *pcrc
                                , struct pluto_crypto_req *r
                                , err_t ugh)
{
    struct dh_continuation *dh = (struct dh_continuation *)pcrc;
    struct msg_digest *md = dh->md;
    struct state *const st = md->st;
    stf_status e;

    DBG(DBG_CONTROLMORE
        , DBG_log("ikev2 parent inI2outR2: calculating g^{xy}, sending R2"));

    if (st == NULL) {
        loglog(RC_LOG_SERIOUS, "%s: Request was disconnected from state",
               __FUNCTION__);
        if (dh->md)
            release_md(dh->md);
        return;
    }

    /* XXX should check out ugh */
    passert(ugh == NULL);
    passert(cur_state == NULL);
    passert(st != NULL);

    passert(st->st_suspended_md == dh->md);
    set_suspended(st,NULL);        /* no longer connected or suspended */

    set_cur_state(st);

    st->st_calculating = FALSE;

    e = ikev2_parent_inI2outR2_tail(pcrc, r);
    if( e > STF_FAIL) {
        /* we do not send a notify because we are the initiator that could be responding to an error notification */
        int v2_notify_num = e - STF_FAIL;
        DBG_log("ikev2_parent_inI2outR2_tail returned STF_FAIL with %s", enum_name(&ikev2_notify_names, v2_notify_num));
    } else if( e != STF_OK) {
        DBG_log("ikev2_parent_inI2outR2_tail returned %s", enum_name(&stfstatus_name, e));
    }

    if(dh->md != NULL) {
        complete_v2_state_transition(&dh->md, e);
        if(dh->md) release_md(dh->md);
    }
    reset_globals();

    passert(GLOBALS_ARE_RESET());
}

static stf_status
ikev2_parent_inI2outR2_tail(struct pluto_crypto_req_cont *pcrc
                            , struct pluto_crypto_req *r)
{
    struct dh_continuation *dh = (struct dh_continuation *)pcrc;
    struct msg_digest *md  = dh->md;
    struct state *const st = md->st;
    struct connection *c   = st->st_connection;
    struct IDhost_pair *hp = NULL;
    unsigned char *idhash_in, *idhash_out;
    unsigned char *authstart;
    unsigned int np;
    int v2_notify_num = 0;

    md->transition_state = st;

    /* extract calculated values from r */
    finish_dh_v2(st, r);

    if(DBGP(DBG_PRIVATE) && DBGP(DBG_CRYPT)) {
        ikev2_log_parentSA(st);
    }

    /* decrypt things. */
    {
        stf_status ret;
        ret = ikev2_decrypt_msg(md, RESPONDER);
        if(ret != STF_OK) return ret;
    }


    /*Once the message has been decrypted, then only we can check for auth payload*/
    /*check the presense of auth payload now so that it does not crash in rehash_state if auth payload has not been received*/
    if(!md->chain[ISAKMP_NEXT_v2AUTH]) {
        openswan_log("no authentication payload found");
        return STF_FAIL;
    }

    strcpy(st->ikev2.st_peer_buf, "<unknown>");
    strcpy(st->ikev2.st_local_buf, "<myid>");

    if(!ikev2_decode_peer_id(md, RESPONDER)) {
        return STF_FAIL + v2N_AUTHENTICATION_FAILED;
    }

    ikev2_decode_local_id(md, RESPONDER);

    /* here we have to see if we can find a better SA now that we know the ID */
    hp = find_ID_host_pair(st->ikev2.st_local_id
                           , st->ikev2.st_peer_id);

    /*
     * now we should have at least one conn that matches the actual
     * ID values. It might be a template, though.
     */
    if(hp == NULL) {
        loglog(RC_LOG_SERIOUS, "No policy for initiator with id=%s (me:%s)"
               , st->ikev2.st_peer_buf, st->ikev2.st_local_buf);
        return STF_FAIL + v2N_AUTHENTICATION_FAILED;
    }

    {
        struct hmac_ctx id_ctx;
        const pb_stream *id_pbs = &md->chain[ISAKMP_NEXT_v2IDi]->pbs;
        unsigned char *idstart=id_pbs->start + 4;
        unsigned int   idlen  =pbs_room(id_pbs)-4;

        hmac_init_chunk(&id_ctx, st->st_oakley.prf_hasher, st->st_skey_pi);

        /* calculate hash of IDi for AUTH below */
        DBG(DBG_CRYPT, DBG_dump_chunk("idhash verify pi", st->st_skey_pi));
        DBG(DBG_CRYPT, DBG_dump("idhash verify I2", idstart, idlen));
        hmac_update(&id_ctx, idstart, idlen);
        idhash_in = alloca(st->st_oakley.prf_hasher->hash_digest_len);
        hmac_final(idhash_in, &id_ctx);
    }

    /* process CERT payload */
    {
        if(md->chain[ISAKMP_NEXT_v2CERT])
            {
                /* should we check if we should accept a cert payload ?
                 *  has_preloaded_public_key(st)
                 */
                openswan_log("v2_CERT received on reponder, attempting to validate");
                ikev2_decode_cert(md);
            }
    }

    /* process CERTREQ payload */
    if(md->chain[ISAKMP_NEXT_v2CERTREQ])
        {
            DBG(DBG_CONTROLMORE
                ,DBG_log("has a v2CERTREQ payload going to decode it"));
            ikev2_decode_cr(md, &st->st_connection->requested_ca);
        }

    /* process AUTH payload now */
    /* now check signature from RSA key */
    switch(md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type)
        {
        case v2_AUTH_RSA:
            {
                stf_status authstat = ikev2_verify_rsa_sha1(st
                                                            , RESPONDER
                                                            , idhash_in
                                                            , NULL /* keys from DNS */
                                                            , NULL /* gateways from DNS */
                                                            , &md->chain[ISAKMP_NEXT_v2AUTH]->pbs);
                if(authstat != STF_OK) {
                    openswan_log("RSA authentication failed");
                    SEND_V2_NOTIFICATION(AUTHENTICATION_FAILED);
                    return STF_FATAL;
                }
                break;
            }
        case v2_AUTH_SHARED:
            {
                stf_status authstat = ikev2_verify_psk_auth(st
                                                            , RESPONDER
                                                            , idhash_in
                                                            , &md->chain[ISAKMP_NEXT_v2AUTH]->pbs);
                if(authstat != STF_OK) {
                    openswan_log("PSK authentication failed AUTH mismatch!");
                    SEND_V2_NOTIFICATION(v2N_AUTHENTICATION_FAILED);
                    return STF_FATAL;
                }
                break;
            }
        default:
            openswan_log("authentication method: %s not supported"
                         , enum_name(&ikev2_auth_names
                                     ,md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type));
            return STF_FATAL;
        }

    /* Is there a notify about an error ? */
    if(md->chain[ISAKMP_NEXT_v2N] != NULL) {
        DBG(DBG_CONTROL,DBG_log(" notify payload detected, should be processed...."));
    }

    /* good, things checked out!. now create child state */
    DBG(DBG_CONTROL, DBG_log("PARENT SA now authenticated, building child and reply"));

    /* now that we now who they are, give them a higher crypto priority! */
    st->st_import = pcim_known_crypto;

    /* note: as we will switch to child state, we force the parent to the
     * new state now, but note also that child state exists just to contain
     * the IPsec SA, and to provide for it's eventual rekeying
     */
    change_state(st, STATE_PARENT_R2);
    c->newest_isakmp_sa = st->st_serialno;
    md->pst = st;

    delete_event(st);
    event_schedule(EVENT_SA_REPLACE, c->sa_ike_life_seconds, st);

    authstart = reply_stream.cur;
    /* send response */
    {
        unsigned char *encstart;
        unsigned char *iv;
        unsigned int ivsize;
        struct ikev2_generic e;
        pb_stream      e_pbs, e_pbs_cipher;
        stf_status     ret;
        bool send_cert = FALSE;

        /* make sure HDR is at start of a clean buffer */
        zero(reply_buffer);
        init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer), "reply packet");

        /* HDR out */
        {
            struct isakmp_hdr r_hdr = md->hdr;

            /* let the isa_version reply be the same as what the sender had */
            r_hdr.isa_np    = ISAKMP_NEXT_v2E;
            r_hdr.isa_xchg  = ISAKMP_v2_AUTH;
            r_hdr.isa_flags = ISAKMP_FLAGS_R;
            r_hdr.isa_msgid = htonl(md->msgid_received);
            memcpy(r_hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
            memcpy(r_hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
            if (!out_struct(&r_hdr, &isakmp_hdr_desc, &reply_stream, &md->rbody))
                return STF_INTERNAL_ERROR;
        }

        /* insert an Encryption payload header */
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

        /* decide to send CERT payload before we generate IDr */
        send_cert = doi_send_ikev2_cert_thinking(st);

        /* send out the IDr payload */
        {
            struct ikev2_id r_id;
            pb_stream r_id_pbs;
            chunk_t id_b;
            struct hmac_ctx id_ctx;
            unsigned char *id_start;
            unsigned int   id_len;

            hmac_init_chunk(&id_ctx, st->st_oakley.prf_hasher
                            , st->st_skey_pr);
            build_id_payload((struct isakmp_ipsec_id *)&r_id, &id_b,
                             &c->spd.this);
            r_id.isai_critical = ISAKMP_PAYLOAD_NONCRITICAL;

            if(send_cert)
                r_id.isai_np = ISAKMP_NEXT_v2CERT;
            else
                r_id.isai_np = ISAKMP_NEXT_v2AUTH;

            id_start = e_pbs_cipher.cur;

            pbs_set_np(&e_pbs_cipher, ISAKMP_NEXT_v2IDr);
            if (!out_struct(&r_id
                            , &ikev2_id_desc
                            , &e_pbs_cipher
                            , &r_id_pbs)
                || !out_chunk(id_b, &r_id_pbs, "my identity"))
                return STF_INTERNAL_ERROR;
            close_output_pbs(&r_id_pbs);

            id_start += 4;

            /* calculate hash of IDi for AUTH below */
            id_len = e_pbs_cipher.cur - id_start;
            DBG(DBG_CRYPT, DBG_dump_chunk("idhash calc pr", st->st_skey_pr));
            DBG(DBG_CRYPT, DBG_dump("idhash calc R2",id_start, id_len));
            hmac_update(&id_ctx, id_start, id_len);
            idhash_out = alloca(st->st_oakley.prf_hasher->hash_digest_len);
            hmac_final(idhash_out, &id_ctx);
        }

        DBG(DBG_CONTROLMORE
            , DBG_log("assembled IDr payload -- CERT next"));

        /* send CERT payload RFC 4306 3.6, 1.2:([CERT,] ) */
        if(send_cert) {
            stf_status certstat = ikev2_send_cert(st, md
                                                  , RESPONDER
                                                  , ISAKMP_NEXT_v2AUTH
                                                  , &e_pbs_cipher);
            if(certstat != STF_OK) return certstat;
            }

        /* since authentication good,
         * see if there is a child SA being proposed */
        if(md->chain[ISAKMP_NEXT_v2SA] == NULL
           || md->chain[ISAKMP_NEXT_v2TSi] == NULL
           || md->chain[ISAKMP_NEXT_v2TSr] == NULL) {

            /* initiator didn't propose anything. Weird. Try unpending out end. */
            /* UNPEND XXX */
            openswan_log("No CHILD SA proposals received.");
            np = ISAKMP_NEXT_NONE;
        } else {
            DBG_log("CHILD SA proposals received");
            np = ISAKMP_NEXT_v2SA;
        }

        DBG(DBG_CONTROLMORE
            , DBG_log("going to assemble AUTH payload"));

        /* now send AUTH payload */
        {
            stf_status authstat = ikev2_send_auth(c, st
                                                  , RESPONDER, np
                                                  , idhash_out, &e_pbs_cipher);
            if(authstat != STF_OK) return authstat;
        }

        if(np == ISAKMP_NEXT_v2SA) {
            /* must have enough to build an CHILD_SA... go do that! */
            ret = ikev2_child_sa_respond(md, NULL, &e_pbs_cipher);
            if(ret > STF_FAIL) {
                v2_notify_num = ret - STF_FAIL;
                DBG(DBG_CONTROL,DBG_log("ikev2_child_sa_respond returned STF_FAIL with %s", enum_name(&ikev2_notify_names, v2_notify_num)))
                np = ISAKMP_NEXT_NONE;
            } else if(ret != STF_OK) {
                DBG_log("ikev2_child_sa_respond returned %s", enum_name(&stfstatus_name, ret));
                np = ISAKMP_NEXT_NONE;
            }
        }

        ikev2_padup_pre_encrypt(md, &e_pbs_cipher);
        close_output_pbs(&e_pbs_cipher);

        {
            unsigned char *authloc = ikev2_authloc(md, &e_pbs);

            if(authloc == NULL || authloc < encstart) return STF_INTERNAL_ERROR;

            close_output_pbs(&e_pbs);

            close_output_pbs(&md->rbody);
            close_output_pbs(&reply_stream);

            ret = ikev2_encrypt_msg(md, RESPONDER,
                                    authstart,
                                    iv, encstart, authloc,
                                    &e_pbs, &e_pbs_cipher);
            if(ret != STF_OK) return ret;
        }
    }


    /* let TCL hack it before we mark the length. */
    TCLCALLOUT("v2_avoidEmitting", st, st->st_connection, md);

    /* keep it for a retransmit if necessary */
    freeanychunk(st->st_tpacket);
    clonetochunk(st->st_tpacket, reply_stream.start, pbs_offset(&reply_stream)
                 , "reply packet for ikev2_parent_inI2outR2_tail");

    /* note: retransimission is driven by initiator */

    /* if the child failed, delete its state here - we sent the packet */
    return STF_OK;

}

/*
 *
 ***************************************************************
 *                       PARENT_inR2    (I3 state)         *****
 ***************************************************************
 *  - there are no cryptographic continuations, but be certain
 *    that there will have to be DNS continuations, but they
 *    just aren't implemented yet.
 *
 *  - note that the md->st here will be the child state,
 *    as demux used find_state_ikev2_child when msgid > 0.
 *
 */
stf_status ikev2parent_inR2(struct msg_digest *md)
{
    struct state *st = md->st;
    struct connection *c = st->st_connection;
    unsigned char *idhash_in;
    struct state *pst = st;
    stf_status e;

    if(st->st_clonedfrom != 0) {
        pst = state_with_serialno(st->st_clonedfrom);
    }

    /*
     * the initiator sent us an encrypted payload. We need to calculate
     * our g^xy, and skeyseed values, and then decrypt the payload.
     */

    DBG(DBG_CONTROLMORE
        , DBG_log("ikev2 parent inR2: calculating g^{xy} in order to decrypt I2"));

    /* verify that there is in fact an encrypted payload */
    if(!md->chain[ISAKMP_NEXT_v2E]) {
        openswan_log("R2 state should receive an encrypted payload");
        return STF_FATAL;
    }

    /* decrypt things. */
    {
        stf_status ret;
        ret = ikev2_decrypt_msg(md, INITIATOR);
        if(ret != STF_OK) return ret;
    }

    if(!ikev2_decode_peer_id(md, INITIATOR)) {
        return STF_FAIL + INVALID_ID_INFORMATION;
    }

    ikev2_decode_local_id(md, INITIATOR);

    {
        struct hmac_ctx id_ctx;
        const pb_stream *id_pbs = &md->chain[ISAKMP_NEXT_v2IDr]->pbs;
        unsigned char *idstart=id_pbs->start + 4;
        unsigned int   idlen  =pbs_room(id_pbs)-4;

        hmac_init_chunk(&id_ctx, pst->st_oakley.prf_hasher, pst->st_skey_pr);

        /* calculate hash of IDr for AUTH below */
        DBG(DBG_CRYPT, DBG_dump_chunk("idhash verify pr", pst->st_skey_pr));
        DBG(DBG_CRYPT, DBG_dump("idhash auth R2", idstart, idlen));
        hmac_update(&id_ctx, idstart, idlen);
        idhash_in = alloca(pst->st_oakley.prf_hasher->hash_digest_len);
        hmac_final(idhash_in, &id_ctx);
    }

    if(md->chain[ISAKMP_NEXT_v2CERT]) {
        /* should we check if we should accept a cert payload ?
         *  has_preloaded_public_key(st)
         */
        /* in v1 code it is  decode_cert(struct msg_digest *md) */
        openswan_log("v2_CERT received on initiator, attempting to validate");
        ikev2_decode_cert(md);
    }

    /* process AUTH payload */
    if(!md->chain[ISAKMP_NEXT_v2AUTH]) {
        openswan_log("no authentication payload found");
        return STF_FAIL;
    }

    /* now check signature from RSA key */
    switch(md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type) {
    case v2_AUTH_RSA: {
        stf_status authstat = ikev2_verify_rsa_sha1(pst
                                                    , INITIATOR
                                                    , idhash_in
                                                    , NULL /* keys from DNS */
                                                    , NULL /* gateways from DNS */
                                                    , &md->chain[ISAKMP_NEXT_v2AUTH]->pbs);
        if(authstat != STF_OK) {
            openswan_log("authentication failed");
            SEND_V2_NOTIFICATION(AUTHENTICATION_FAILED);
            return STF_FAIL;
        }
        break;
    }

    case v2_AUTH_SHARED: {
        stf_status authstat = ikev2_verify_psk_auth(pst
                                                    , INITIATOR
                                                    , idhash_in
                                                    , &md->chain[ISAKMP_NEXT_v2AUTH]->pbs);
        if(authstat != STF_OK) {
            openswan_log("PSK authentication failed");
            SEND_V2_NOTIFICATION(v2N_AUTHENTICATION_FAILED);
            return STF_FAIL;
        }
        break;
    }

    default:
        openswan_log("authentication method: %s not supported"
                     , enum_name(&ikev2_auth_names
                                 ,md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type));
        return STF_FAIL;
    }

    /*
     * update the parent state to make sure that it knows we have
     * authenticated properly.
     */
    change_state(pst, STATE_PARENT_I3);
    c->newest_isakmp_sa = pst->st_serialno;

    /* authentication good, see if there is a child SA available */
    if(md->chain[ISAKMP_NEXT_v2SA] == NULL
       || md->chain[ISAKMP_NEXT_v2TSi] == NULL
       || md->chain[ISAKMP_NEXT_v2TSr] == NULL) {
        /* not really anything to here... but it would be worth unpending again */
        DBG(DBG_CONTROLMORE, DBG_log("no v2SA, v2TSi or v2TSr received, not attempting to setup child SA"));
        DBG(DBG_CONTROLMORE, DBG_log("  Should we check for some notify?"));
        /*
         * Delete previous retransmission event.
         */
        delete_event(pst);
        return STF_OK;
    }

    /* Check TSi/TSr http://tools.ietf.org/html/rfc5996#section-2.9 */
    DBG(DBG_CONTROLMORE,DBG_log(" checking narrowing - responding to R2"));

    if ((e = ikev2_child_validate_responder_proposal(md, st)) != STF_OK) {
        return e;
    }

    {
        v2_notification_t rn;
        struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
        if (sa_pd == NULL) {
                return STF_FAIL;
        }

        rn = ikev2_parse_child_sa_body(&sa_pd->pbs, &sa_pd->payload.v2sa
                                       , NULL, st, /* selection=*/TRUE);

        if(rn != v2N_NOTHING_WRONG)
            return STF_FAIL + rn;
    }

    if ((e = ikev2_child_notify_process(md, st)) != STF_OK) {
        return e;
    }

    ikev2_derive_child_keys(st, INITIATOR);

    c->newest_ipsec_sa = st->st_serialno;

    /* now install child SAs */
    if(!install_ipsec_sa(pst, st, TRUE)) {
#ifdef DEBUG_WITH_PAUSE
        pause();
#endif
        loglog(RC_LOG_SERIOUS, "failed to installed IPsec Child SAs");
        return STF_FATAL;
    }

    /* need to force child to KEYED */
    change_state(st, STATE_CHILD_C1_KEYED);

    /*
     * Delete previous retransmission event.
     */
    delete_event(st);

    return STF_OK;
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

/*
 *
 ***************************************************************
 *                       NOTIFICATION_OUT Complete packet  *****
 ***************************************************************
 *
 */

void
send_v2_notification(struct state *p1st, u_int16_t type
                     , struct state *encst
                     , u_char *icookie
                     , u_char *rcookie
                     , chunk_t *n_data)
{
    u_char buffer[1024];
    pb_stream reply;
    pb_stream rbody;
    chunk_t child_spi, notify_data;
    /* this function is not generic enough yet just enough for 6msg
     * TBD accept HDR FLAGS as arg. default ISAKMP_FLAGS_R
     * TBD when there is a child SA use that SPI in the notify paylod.
     * TBD support encrypted notifications payloads.
     * TBD accept Critical bit as an argument. default is set.
     * TBD accept exchange type as an arg, default is ISAKMP_v2_SA_INIT
     * do we need to send a notify with empty data?
     * do we need to support more Protocol ID? more than PROTO_ISAKMP
     */

    openswan_log("sending %s notification %s to %s:%u"
                 , encst ? "encrypted " : ""
                 , enum_name(&ikev2_notify_names, type)
                 , ip_str(&p1st->st_remoteaddr)
                 , p1st->st_remoteport);

    memset(buffer, 0, sizeof(buffer));
    init_pbs(&reply, buffer, sizeof(buffer), "notification msg");

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
        n_hdr.isa_xchg = ISAKMP_v2_SA_INIT;
        n_hdr.isa_np = ISAKMP_NEXT_v2N;
        n_hdr.isa_flags &= ~ISAKMP_FLAGS_I;
        n_hdr.isa_flags  |=  ISAKMP_FLAGS_R;
        n_hdr.isa_msgid = htonl(p1st->st_msgid);

        if (!out_struct(&n_hdr, &isakmp_hdr_desc, &reply, &rbody))
            {
                openswan_log("error initializing hdr for notify message");
                return;
            }
    }
    child_spi.ptr = NULL;
    child_spi.len = 0;

    /* build and add v2N payload to the packet */
    memset(&child_spi, 0, sizeof(child_spi));
    memset(&notify_data, 0, sizeof(notify_data));
    ship_v2N (ISAKMP_NEXT_NONE, DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG) ?
              (ISAKMP_PAYLOAD_NONCRITICAL | ISAKMP_PAYLOAD_OPENSWAN_BOGUS) :
              ISAKMP_PAYLOAD_NONCRITICAL, PROTO_ISAKMP,
              &child_spi,
              type, n_data, &rbody);

    close_message(&rbody);
    close_output_pbs(&reply);

    clonetochunk(p1st->st_tpacket, reply.start, pbs_offset(&reply)
                 , "notification packet");

    send_packet(p1st, __FUNCTION__, TRUE);
}

/* add notify payload to the rbody */
bool ship_v2N(unsigned int np, u_int8_t  critical,
              u_int8_t protoid, chunk_t *spi,
              u_int16_t type, chunk_t *n_data, pb_stream *rbody)
{
    struct ikev2_notify n;
    pb_stream n_pbs;
    DBG(DBG_CONTROLMORE
        ,DBG_log("Adding a v2N Payload"));

    pbs_set_np(rbody, ISAKMP_NEXT_v2N);

    n.isan_np =  np;
    n.isan_critical = critical;
    if(DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
        openswan_log(" setting bogus ISAKMP_PAYLOAD_OPENSWAN_BOGUS flag in ISAKMP payload");
        n.isan_critical |= ISAKMP_PAYLOAD_OPENSWAN_BOGUS;
    }

    n.isan_protoid =  protoid;
    n.isan_spisize = 0;
    if(spi) {
        n.isan_spisize = spi->len;
    }
    n.isan_type = type;

    if (!out_struct(&n, &ikev2_notify_desc, rbody, &n_pbs)) {
        openswan_log("error initializing notify payload for notify message");
        return FALSE;
    }

    if(spi && spi->len > 0) {
        if (!out_raw(spi->ptr, spi->len, &n_pbs, "SPI ")) {
            openswan_log("error writing SPI to notify payload");
            return FALSE;
        }
    }
    if(n_data != NULL) {
        if (!out_raw(n_data->ptr, n_data->len, &n_pbs, "Notify data")) {
            openswan_log("error writing notify payload for notify message");
            return FALSE;
        }
    }

    close_output_pbs(&n_pbs);
    return TRUE;
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
        if(md->hdr.isa_flags & ISAKMP_FLAGS_I) {
           DBG(DBG_CONTROLMORE
              , DBG_log("received informational exchange request from INITIATOR"));
           ret = ikev2_decrypt_msg(md, RESPONDER);
        }
        else {
           DBG(DBG_CONTROLMORE
              , DBG_log("received informational exchange request from RESPONDER"));
           ret = ikev2_decrypt_msg(md, INITIATOR);
        }

        if(ret != STF_OK) return ret;
    }


    {
        struct payload_digest *p;
        struct ikev2_delete *v2del=NULL;
        stf_status ret;
        struct state *const st = md->st;

        /* Only send response if it is request (we are responder!) */
        if (!(md->hdr.isa_flags & ISAKMP_FLAGS_R)) {
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

                /*set initiator bit if we are initiator*/
                if(md->role == INITIATOR) {
                    r_hdr.isa_flags |= ISAKMP_FLAGS_I;
                }

                r_hdr.isa_flags  |=  ISAKMP_FLAGS_R;


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

                ret = ikev2_encrypt_msg(md, RESPONDER,
                                        authstart,
                                        iv, encstart, authloc,
                                        &e_pbs, &e_pbs_cipher);
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

                switch (v2del->isad_protoid) {
                case PROTO_ISAKMP:
                    {
                        /* My understanding is that delete payload for IKE SA
                         *  should be the only payload in the informational
                         * Now delete the IKE SA state and all its child states
                         */
                        struct state *current_st = st;
                        struct state *next_st = NULL;
                        struct state *first_st = NULL;

                        /* Find the first state in the hash chain*/
                        while(current_st != (struct state *) NULL)
                            {
                                first_st = current_st;
                                current_st = first_st->st_hashchain_prev;
                            }

                        current_st = first_st;
                        while (current_st != (struct state *) NULL)
                            {
                                next_st = current_st->st_hashchain_next;
                                if(current_st->st_clonedfrom !=0 )
                                    {
                                        change_state(current_st, STATE_CHILDSA_DEL);
                                    }
                                else
                                    {
                                        change_state(current_st, STATE_IKESA_DEL);
                                    }
                                delete_state(current_st);
                                current_st = next_st;
                            }
                    }
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
                                        DBG(DBG_CONTROLMORE, DBG_log("our side spi that needs to be deleted: %s SA(0x%08lx)"
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

        } /* if*/
        else
            {
                /* empty response to our IKESA delete request*/
                if((md->hdr.isa_flags & ISAKMP_FLAGS_R) && st->st_state == STATE_IKESA_DEL)
                    {
                        /* My understanding is that delete payload for IKE SA
                         *  should be the only payload in the informational
                         * Now delete the IKE SA state and all its child states
                         */
                        struct state *current_st = st;
                        struct state *next_st = NULL;
                        struct state *first_st = NULL;

                        /* Find the first state in the hash chain*/
                        while(current_st != (struct state *) NULL)
                            {
                                first_st = current_st;
                                current_st = first_st->st_hashchain_prev;
                            }

                        current_st = first_st;
                        while (current_st != (struct state *) NULL)
                            {
                                next_st = current_st->st_hashchain_next;
                                if(current_st->st_clonedfrom !=0 )
                                    {
                                        change_state(current_st, STATE_CHILDSA_DEL);
                                    }
                                else
                                    {
                                        change_state(current_st, STATE_IKESA_DEL);
                                    }
                                delete_state(current_st);
                                current_st = next_st;
                            }

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
            if(pst->st_state == STATE_PARENT_I2 || pst->st_state == STATE_PARENT_I3) {
                r_hdr.isa_flags |= ISAKMP_FLAGS_I;
                role = INITIATOR;
            }
            else {
                role = RESPONDER;
            }

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
