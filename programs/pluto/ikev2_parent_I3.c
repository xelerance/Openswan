/*
 * IKEv2 parent SA creation routines
 * Copyright (C) 2007-2017 Michael Richardson <mcr@xelerance.com>
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

/* This file is #include'ed into ikev2_parent.c */

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
        st->hidden_variables.st_got_cert_from_peer = TRUE;
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
                                                    , NULL
                                                    , idhash_in
                                                    , NULL /* keys from DNS */
                                                    , NULL /* gateways from DNS */
                                                    , &md->chain[ISAKMP_NEXT_v2AUTH]->pbs);
        if(authstat != STF_OK) {
            openswan_log("authentication failed");
            SEND_V2_NOTIFICATION(md, st, AUTHENTICATION_FAILED);
            return STF_FAIL;
        }
        break;
    }

    case v2_AUTH_SHARED: {
        stf_status authstat = ikev2_verify_psk_auth(pst
                                                    , INITIATOR
                                                    , NULL
                                                    , idhash_in
                                                    , &md->chain[ISAKMP_NEXT_v2AUTH]->pbs);
        if(authstat != STF_OK) {
            openswan_log("PSK authentication failed");
            SEND_V2_NOTIFICATION(md, st, v2N_AUTHENTICATION_FAILED);
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

    e = ikev2_derive_child_keys(st, INITIATOR);
    if (e != STF_OK)
	return e;

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
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
