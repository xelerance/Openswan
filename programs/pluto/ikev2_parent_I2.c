/*
 * IKEv2 parent SA creation routines --- outI1 routines
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
 *                       PARENT_inR1                       *****
 ***************************************************************
 *  -
 *
 *
 */
static void ikev2_parent_inR1outI2_continue(struct pluto_crypto_req_cont *pcrc
                                            , struct pluto_crypto_req *r
                                            , err_t ugh);

static stf_status
ikev2_parent_inR1outI2_tail(struct pluto_crypto_req_cont *pcrc
                            , struct pluto_crypto_req *r);

stf_status ikev2parent_inR1outI2(struct msg_digest *md)
{
    struct state *st = md->st;
    /* struct connection *c = st->st_connection; */
    pb_stream *keyex_pbs;

    /* if we are already processing a packet on this st, we will be unable
     * to start another crypto operation below */
    if (is_suspended(st)) {
        openswan_log("%s: already processing a suspended cyrpto operation "
                     "on this SA, duplicate will be dropped.", __func__);
	return STF_TOOMUCHCRYPTO;
    }

    /* record IKE version numbers -- used mostly in logging */
    st->st_ike_maj        = md->maj;
    st->st_ike_min        = md->min;

    if(isanyaddr(&st->st_localaddr) || st->st_localport == 0) {
        /* record where packet arrived to */
        st->st_localaddr  = md->iface->ip_addr;
        st->st_localport  = md->iface->port;
    }

    /*
     * verify the NAT DETECTION notify messages before answering.
     * on the responder side, this allows us to detect when *we* are behind
     * at NAPT (probably with a port-forward).
     *
     * If we are, then we set a bit saying so, which later on will make us pick the
     * UDP encapsulation for packets.  It is up to the initiator to switch ports
     * from 500 to 4500.  Could be they have already done so, we do not care here.
     */
    if(md->chain[ISAKMP_NEXT_v2N]) {
        ikev2_process_notifies(st, md);

        /* switch to port 4500, if necessary */
        ikev2_update_nat_ports(st);

	/* enable NAT-T keepalives, if necessary */
	ikev2_enable_nat_keepalives(st);
    }


    /* check if the responder replied with v2N with DOS COOKIE */
    if( md->chain[ISAKMP_NEXT_v2N]
        && md->chain[ISAKMP_NEXT_v2N]->payload.v2n.isan_type ==  v2N_COOKIE)
        {
            u_int8_t spisize;
            const pb_stream *dc_pbs;
            DBG(DBG_CONTROLMORE
                ,DBG_log("inR1OutI2 received a DOS v2N_COOKIE from the responder");
                DBG_log("resend the I1 with a cookie payload"));
            spisize = md->chain[ISAKMP_NEXT_v2N]->payload.v2n.isan_spisize;
            dc_pbs = &md->chain[ISAKMP_NEXT_v2N]->pbs;
            clonetochunk(st->st_dcookie,  (dc_pbs->cur + spisize)
                         , (pbs_left(dc_pbs) - spisize), "saved received dcookie");

            DBG(DBG_CONTROLMORE
                ,DBG_dump_chunk("dcookie received (instead of a R1):",
                                st->st_dcookie);
                DBG_log("next STATE_PARENT_I1 resend I1 with the dcookie"));

            md->svm = &ikev2_parent_firststate_microcode;

            /* now reset state, and try again with noncense */
            change_state(st, STATE_PARENT_I1);
            st->st_msgid_lastack = INVALID_MSGID;
            md->msgid_received = INVALID_MSGID;  /* AAA hack  */
            st->st_msgid_nextuse = 0;

            return ikev2_parent_outI1_common(md, st);
        }

    /*
     * the responder sent us back KE, Gr, Nr, and it's our time to calculate
     * the shared key values.
     */

    DBG(DBG_CONTROLMORE
        , DBG_log("ikev2 parent inR1: calculating g^{xy} in order to send I2"));

    /* KE in */
    keyex_pbs = &md->chain[ISAKMP_NEXT_v2KE]->pbs;
    RETURN_STF_FAILURE(accept_KE(&st->st_gr, "Gr", st->st_oakley.group, keyex_pbs));

    /* Ni in */
    RETURN_STF_FAILURE(accept_v2_nonce(md, &st->st_nr, "Ni"));

    if(md->chain[ISAKMP_NEXT_v2SA] == NULL) {
        openswan_log("No responder SA proposal found");
        return PAYLOAD_MALFORMED;
    }

    /* process CERTREQ payload */
    if(md->chain[ISAKMP_NEXT_v2CERTREQ]) {
        DBG(DBG_CONTROLMORE
            ,DBG_log("has a v2CERTREQ payload going to decode it"));
        ikev2_decode_cr(md, &st->st_connection->ikev2_requested_ca_hashes);
        if(st->st_connection->ikev2_requested_ca_hashes != NULL)
            st->hidden_variables.st_got_certrequest = TRUE;
    }

    /* process and confirm the SA selected */
    {
        struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
        v2_notification_t rn;

        /* SA body in and out */
        rn = ikev2_parse_parent_sa_body(&sa_pd->pbs, &sa_pd->payload.v2sa,
                                        NULL, st, FALSE);

        if (rn != v2N_NOTHING_WRONG)
            return STF_FAIL + rn;
    }

    /* update state */
    ikev2_update_counters(md);

    /* now. we need to go calculate the g^xy */
    {
        struct dh_continuation *dh = alloc_thing(struct dh_continuation
                                                 , "ikev2_inR1outI2 KE");
        stf_status e;

        dh->md = md;
        set_suspended(st, dh->md);

        pcrc_init(&dh->dh_pcrc);
        dh->dh_pcrc.pcrc_func = ikev2_parent_inR1outI2_continue;
        e = start_dh_v2(&dh->dh_pcrc, st, st->st_import, INITIATOR, st->st_oakley.groupnum);
        if(e != STF_SUSPEND && e != STF_INLINE) {
            loglog(RC_CRYPTOFAILED, "system too busy");
            delete_state(st);
        }

        reset_globals();

        return e;
    }
}

static void
ikev2_parent_inR1outI2_continue(struct pluto_crypto_req_cont *pcrc
                                , struct pluto_crypto_req *r
                                , err_t ugh)
{
    struct dh_continuation *dh = (struct dh_continuation *)pcrc;
    struct msg_digest *md = dh->md;
    struct state *const st = md->st;
    stf_status e;

    DBG(DBG_CONTROLMORE
        , DBG_log("ikev2 parent inR1outI2: calculating g^{xy}, sending I2"));

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

    e = ikev2_parent_inR1outI2_tail(pcrc, r);

    if(dh->md != NULL) {
        complete_v2_state_transition(&dh->md, e);
        if(dh->md) release_md(dh->md);
    }
    reset_globals();

    passert(GLOBALS_ARE_RESET());
}

static stf_status
ikev2_parent_inR1outI2_tail(struct pluto_crypto_req_cont *pcrc
                            , struct pluto_crypto_req *r)
{
    struct dh_continuation *dh = (struct dh_continuation *)pcrc;
    struct msg_digest *md = dh->md;
    struct state *st      = md->st;
    struct connection *c  = st->st_connection;
    struct ikev2_generic e;
    unsigned char *encstart;
    pb_stream      e_pbs, e_pbs_cipher;
    unsigned char *iv;
    int            ivsize;
    stf_status     ret;
    unsigned char *idhash;
    unsigned char *authstart;
    struct state *pst = st;
    msgid_t        mid = INVALID_MSGID;

    md->transition_state = st;

    finish_dh_v2(st, r);

    if(DBGP(DBG_PRIVATE) && DBGP(DBG_CRYPT)) {
        ikev2_log_parentSA(st);
	ikev2_validate_key_lengths(st);
    }

    pst = st;
    ret = allocate_msgid_from_parent(pst, &mid);
    if(ret != STF_OK) {
        /*
         * XXX: need to return here, having enqueued our pluto_crypto_req_cont
         * onto a structure on the parent for processing when there is message
         * ID available.
         */
        return ret;
    }

    /* okay, got a transmit slot, make a child state to send this. */
    st = duplicate_state(pst);
    st->st_policy = pst->st_connection->policy & POLICY_IPSEC_MASK;

    st->st_msgid = mid;
    insert_state(st);
    md->st = st;
    md->pst= pst;

    /* parent had crypto failed, replace it with rekey! */
    delete_event(pst);
    event_schedule(EVENT_SA_REPLACE, c->sa_ike_life_seconds, pst);

    /* record first packet for later checking of signature */
    clonetochunk(pst->st_firstpacket_him, md->packet_pbs.start
                 , pbs_offset(&md->packet_pbs), "saved first received packet");

    /* beginning of data going out */
    authstart = reply_stream.cur;

    /* make sure HDR is at start of a clean buffer */
    zero(reply_buffer);
    init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer), "reply packet");

    /* HDR out */
    {
        struct isakmp_hdr r_hdr = md->hdr;

        /* should be set to version received */
        // r_hdr.isa_version = IKEv2_MAJOR_VERSION << ISA_MAJ_SHIFT | IKEv2_MINOR_VERSION;
        r_hdr.isa_np    = ISAKMP_NEXT_v2E;
        r_hdr.isa_xchg  = ISAKMP_v2_AUTH;
        r_hdr.isa_flags = IKEv2_ORIG_INITIATOR_FLAG(pst);
        r_hdr.isa_msgid = htonl(st->st_msgid);
        memcpy(r_hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
        memcpy(r_hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
        if (!out_struct(&r_hdr, &isakmp_hdr_desc, &reply_stream, &md->rbody))
            return STF_INTERNAL_ERROR;
    }

    /* insert an Encryption payload header */
    e.isag_np = ISAKMP_NEXT_v2IDi;
    e.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;
    if(DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
        openswan_log(" setting bogus ISAKMP_PAYLOAD_OPENSWAN_BOGUS flag in ISAKMP payload");
        e.isag_critical |= ISAKMP_PAYLOAD_OPENSWAN_BOGUS;
    }

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

    /* send out the IDi payload */
    {
        struct ikev2_id r_id;
        pb_stream r_id_pbs;
        chunk_t         id_b;
        struct hmac_ctx id_ctx;

        /* for calculation of hash of ID payload */
        unsigned char *id_start;
        unsigned int   id_len;

        build_id_payload((struct isakmp_ipsec_id *)&r_id, &id_b, &c->spd.this);
        r_id.isai_critical = ISAKMP_PAYLOAD_NONCRITICAL;
        if(DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
            openswan_log(" setting bogus ISAKMP_PAYLOAD_OPENSWAN_BOGUS flag in ISAKMP payload");
            r_id.isai_critical |= ISAKMP_PAYLOAD_OPENSWAN_BOGUS;
        }

        r_id.isai_np = 0;

        pbs_set_np(&e_pbs_cipher, ISAKMP_NEXT_v2IDi);
        id_start = e_pbs_cipher.cur;
        if (!out_struct(&r_id
                        , &ikev2_id_desc
                        , &e_pbs_cipher
                        , &r_id_pbs)) {
            return STF_INTERNAL_ERROR;
        }

        if(!out_chunk(id_b, &r_id_pbs, "my identity")) {
            return STF_INTERNAL_ERROR;
        }

        /* HASH of ID is not done over common (NP/length) header */
        id_start += 4;
        id_len   = r_id_pbs.cur - id_start;

        /* calculate hash of IDi for AUTH below */
        hmac_init_chunk(&id_ctx, pst->st_oakley.prf_hasher, pst->st_skey_pi);
        DBG(DBG_CRYPT, DBG_dump_chunk("idhash calc pi", pst->st_skey_pi));
        DBG(DBG_CRYPT, DBG_dump("idhash calc I2", id_start, id_len));
        hmac_update(&id_ctx, id_start, id_len);
        idhash = alloca(pst->st_oakley.prf_hasher->hash_digest_len);
        hmac_final(idhash, &id_ctx);

        close_output_pbs(&r_id_pbs);
    }

    /* send [CERT,] payload RFC 4306 3.6, 1.2) */
    if(doi_send_ikev2_cert_thinking(st)) {
        stf_status certstat = ikev2_send_cert( st, md
                                               , INITIATOR
                                               , &e_pbs_cipher);
        if(certstat != STF_OK)
            return certstat;

        /* CERTREQ was fulfiled, don't send again */
        if (st->st_connection->spd.this.sendcert == cert_sendifasked)
            st->hidden_variables.st_got_certrequest = FALSE;
    }

    /* send out the AUTH payload */
    {
        lset_t policy;
        struct connection *c0= first_pending(pst, &policy,&st->st_whack_sock);
        DBG(DBG_CONTROL,DBG_log(" payload after AUTH will be %s", (c0) ? "ISAKMP_NEXT_v2SA" : "ISAKMP_NEXT_NONE/NOTIFY"));

        stf_status authstat = ikev2_send_auth(c, st
                                              , INITIATOR
                                              , idhash, &e_pbs_cipher);
        if(authstat != STF_OK) return authstat;

        /*
         * now, find an eligible child SA from the pending list, and emit
         * SA2i, TSi and TSr and (v2N_USE_TRANSPORT_MODE notification in transport mode) for it .
         */
        if(c0) {
            chunk_t child_spi, notify_data;
            st->st_connection = c0;

	    ikev2_emit_ipsec_sa(md,&e_pbs_cipher,ISAKMP_NEXT_v2TSi,c0, policy);

	    st->st_ts_this = ikev2_end_to_ts(&c0->spd.this, st->st_localaddr);
	    st->st_ts_that = ikev2_end_to_ts(&c0->spd.that, st->st_remoteaddr);

	    ikev2_calc_emit_ts(md, &e_pbs_cipher, INITIATOR, c0, policy);

            if( !(st->st_connection->policy & POLICY_TUNNEL) ) {
                DBG_log("Initiator child policy is transport mode, sending v2N_USE_TRANSPORT_MODE");
                memset(&child_spi, 0, sizeof(child_spi));
                memset(&notify_data, 0, sizeof(notify_data));
                ship_v2N (ISAKMP_NEXT_NONE, ISAKMP_PAYLOAD_NONCRITICAL, 0,
                          &child_spi,
                          v2N_USE_TRANSPORT_MODE, &notify_data, &e_pbs_cipher);
            }

            /* need to force child to KEYING */
            change_state(st, STATE_CHILD_C0_KEYING);
        } else {
            openswan_log("no pending SAs found, PARENT SA keyed only");
        }
    }

    /*
     * need to extend the packet so that we will know how big it is
     * since the length is under the integrity check
     */
    ikev2_padup_pre_encrypt(md, &e_pbs_cipher);
    close_output_pbs(&e_pbs_cipher);

    {
        unsigned char *authloc = ikev2_authloc(md, &e_pbs);

        if(authloc == NULL || authloc < encstart) return STF_INTERNAL_ERROR;

        close_output_pbs(&e_pbs);
        close_output_pbs(&md->rbody);
        close_output_pbs(&reply_stream);

        ret = ikev2_encrypt_msg(md, INITIATOR,
                                authstart,
                                iv, encstart, authloc,
                                &e_pbs, &e_pbs_cipher);
        if(ret != STF_OK) return ret;
    }


    /* let TCL hack it before we mark the length. */
    TCLCALLOUT("v2_avoidEmitting", st, st->st_connection, md);

    /* keep it for a retransmit if necessary, but on initiator
     * we never do that, but send_packet() uses it.
     */
    freeanychunk(pst->st_tpacket);
    clonetochunk(pst->st_tpacket, reply_stream.start, pbs_offset(&reply_stream)
                 , "reply packet for ikev2_parent_outI1");

    /*
     * Delete previous retransmission event.
     */
    delete_event(st);
    event_schedule(EVENT_v2_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);

    return STF_OK;

}

/* handle a case where we received a failing notification, and we decided
 * that we can retry with a different proposal */
static stf_status ikev2parent_retry_next_proposal(struct msg_digest *md)
{
    struct state *st = md->st;
    struct state *pst = md->pst;
    struct connection *c = st->st_connection;
    stf_status stf;
    int whack_sock;
    so_serial_t created = -1;

    /* move to the next proposal */
    c->proposal_index ++;

    /* look up the parent */
    if (!pst && st->st_clonedfrom) {
        pst = state_with_serialno(st->st_clonedfrom);
    }

    /* make sure we release all algorithm SPIs */

    if (!st->st_ah.present && st->st_ah.our_spi) {
            DBG(DBG_CONTROL, DBG_log("forcing release of AH spi 0x%x",
				     st->st_ah.our_spi));
	    st->st_ah.present = 1;
    }

    if (!st->st_esp.present && st->st_esp.our_spi) {
            DBG(DBG_CONTROL, DBG_log("forcing release of ESP spi 0x%x",
				     st->st_esp.our_spi));
	    st->st_esp.present = 1;
    }

    if (!st->st_ipcomp.present && st->st_ipcomp.our_spi) {
            DBG(DBG_CONTROL, DBG_log("forcing release of IPCOMP spi 0x%x",
				     st->st_ipcomp.our_spi));
	    st->st_ipcomp.present = 1;
    }

    /* convince whack to wait for the new state, not the old */

    if (pst && pst != st) {
        /* we have a parent and a child state */
        whack_sock = pst->st_whack_sock;
        pst->st_whack_sock = NULL_FD;

        /* we don't care about the child state */
        release_whack(st);

    } else {
        /* just have a child */
        whack_sock = st->st_whack_sock;
        st->st_whack_sock = NULL_FD;
    }

    /* delete the old state */

    delete_event(st);
    change_state(st, STATE_IKESA_DEL);
    delete_state(st);

    if (pst && pst != st) {
        delete_event(pst);
	delete_state(pst);
    }

    reset_globals();

    /* start a new attempt */

    stf = ikev2parent_outI1(whack_sock
              , c
              , NULL
              , &created
              , c->policy
              , 1
              , pcim_demand_crypto
              , NULL_POLICY);

    switch (stf) {
    case STF_OK:
    case STF_SUSPEND:
        c->prospective_parent_sa = created;
        return stf;
    default:
        /* something went wrong, we must close whack_sock */
        close_any(whack_sock);
        break;
    }

    return stf;
}

/*
 * this routine deals with replies that are failures, which do not
 * contain proposal, or which require us to try initiator cookies.
 */
stf_status ikev2parent_ntf_inR1(struct msg_digest *md)
{
    struct state *st = md->st;
    struct connection *c = st->st_connection;
    bool retry = FALSE;

    set_cur_state(st);

    /* check if the responder replied with v2N with DOS COOKIE */
    if( md->chain[ISAKMP_NEXT_v2N] ) {
        struct payload_digest *notify;
        const char *action = "ignored";

        for(notify=md->chain[ISAKMP_NEXT_v2N]; notify!=NULL; notify=notify->next) {
            switch(notify->payload.v2n.isan_type) {
            case v2N_NO_PROPOSAL_CHOSEN:
                action="SA deleted";
                break;
            case v2N_INVALID_KE_PAYLOAD:
		if (c->proposal_can_retry) {
			action="will retry";
			retry = TRUE;
		} else {
			action="SA deleted";
		}
                break;
            default:
                break;
            }

            loglog(RC_NOTIFICATION + notify->payload.v2n.isan_type
                      , "received notify: %s %s"
                      ,enum_name(&ikev2_notify_names
                                 , notify->payload.v2n.isan_type)
                      ,action);
        }

    }

    if (retry)
        return ikev2parent_retry_next_proposal(md);

    /* now. nuke the state */
    delete_state(st);
    reset_globals();

    return STF_FAIL;
}

/*
 * this routine deals with replies that are failures, which do not
 * contain proposal, or which require us to try initiator cookies.
 */
stf_status ikev2parent_ntf_inR2(struct msg_digest *md)
{
    struct state *st = md->st;
    struct connection *c = st->st_connection;
    bool retry = FALSE;

    set_cur_state(st);

    /* check if the responder replied with v2N with DOS COOKIE */
    if( md->chain[ISAKMP_NEXT_v2N] ) {
        struct payload_digest *notify;
        const char *action = "ignored";

        for(notify=md->chain[ISAKMP_NEXT_v2N]; notify!=NULL; notify=notify->next) {
            switch(notify->payload.v2n.isan_type) {
            case v2N_AUTHENTICATION_FAILED:
		if (c->proposal_can_retry) {
			action="will retry";
			retry = TRUE;
		} else {
			action="SA deleted";
		}
                break;
            default:
                break;
            }

            loglog(RC_NOTIFICATION + notify->payload.v2n.isan_type
                      , "received notify: %s %s"
                      ,enum_name(&ikev2_notify_names
                                 , notify->payload.v2n.isan_type)
                      ,action);
        }

    }

    if (retry)
        return ikev2parent_retry_next_proposal(md);

    /* now. nuke the state */
    delete_state(st);
    reset_globals();

    return STF_FAIL;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
