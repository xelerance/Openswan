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

    /* if we are already processing a packet on this st, we will be unable
     * to start another crypto operation below */
    if (is_suspended(st)) {
        openswan_log("%s: already processing a suspended cyrpto operation "
                     "on this SA, duplicate will be dropped.", __func__);
	return STF_TOOMUCHCRYPTO;
    }

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

    assert_suspended(st, dh->md);
    set_suspended(st,NULL);        /* no longer connected or suspended */

    set_cur_state(st);

    st->st_calculating = FALSE;

    e = ikev2_parent_inI2outR2_tail(pcrc, r);
    if( e > STF_FAIL) {
        /* we do not send a notify because we are the initiator that could be responding to an error notification */
        int v2_notify_num = e - STF_FAIL;
        DBG_log("ikev2_parent_inI2outR2_tail returned STF_FAIL with %s", enum_name(&ikev2_notify_names, v2_notify_num));
    } else if( e != STF_OK) {
        DBG_log("ikev2_parent_inI2outR2_tail returned %s", stf_status_name(e));
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
	ikev2_validate_key_lengths(st);
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
                st->hidden_variables.st_got_cert_from_peer = TRUE;
            }
    }

    /* process CERTREQ payload */
    if(md->chain[ISAKMP_NEXT_v2CERTREQ])
        {
            DBG(DBG_CONTROLMORE
                ,DBG_log("has a v2CERTREQ payload going to decode it"));
            ikev2_decode_cr(md, &st->st_connection->ikev2_requested_ca_hashes);
            if(st->st_connection->ikev2_requested_ca_hashes != NULL)
                st->hidden_variables.st_got_certrequest = TRUE;
        }

    /* process AUTH payload now */
    /* now check signature from RSA key */
    switch(md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type)
        {
        case v2_AUTH_RSA:
            {
                stf_status authstat = ikev2_verify_rsa_sha1(st
                                                            , RESPONDER
                                                        , hp
                                                            , idhash_in
                                                            , NULL /* keys from DNS */
                                                            , NULL /* gateways from DNS */
                                                            , &md->chain[ISAKMP_NEXT_v2AUTH]->pbs);
                if(authstat != STF_OK) {
                    openswan_log("RSA authentication failed");
                    SEND_V2_NOTIFICATION(md, st, AUTHENTICATION_FAILED);
                    return STF_FATAL;
                }
                break;
            }
        case v2_AUTH_SHARED:
            {
                stf_status authstat = ikev2_verify_psk_auth(st
                                                            , RESPONDER
                                                        , hp
                                                            , idhash_in
                                                            , &md->chain[ISAKMP_NEXT_v2AUTH]->pbs);
                if(authstat != STF_OK) {
                    openswan_log("PSK authentication failed AUTH mismatch!");
                    SEND_V2_NOTIFICATION(md, st, v2N_AUTHENTICATION_FAILED);
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

    /* switch to port 4500, if necessary */
    ikev2_update_nat_ports(st);

    /* enable NAT-T keepalives, if necessary */
    ikev2_enable_nat_keepalives(st);

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
            r_hdr.isa_flags = ISAKMP_FLAGS_R|IKEv2_ORIG_INITIATOR_FLAG(st);
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
            if(certstat != STF_OK)
                return certstat;

            /* CERTREQ was fulfiled, don't send again */
            if (st->st_connection->spd.this.sendcert == cert_sendifasked)
                st->hidden_variables.st_got_certrequest = FALSE;
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
                DBG_log("ikev2_child_sa_respond returned %s", stf_status_name(ret));
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

    /*
     * at this point, the other end has proven who they are, and so we should stop
     * setting the I bit....
     */
    st->st_ikev2_orig_initiator = FALSE;

    /* keep it for a retransmit if necessary */
    freeanychunk(st->st_tpacket);
    clonetochunk(st->st_tpacket, reply_stream.start, pbs_offset(&reply_stream)
                 , "reply packet for ikev2_parent_inI2outR2_tail");

    /* note: retransimission is driven by initiator */

    /* if the child failed, delete its state here - we sent the packet */
    return STF_OK;

}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
