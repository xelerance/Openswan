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
 *                       PARENT_INI1                       *****
 ***************************************************************
 *  -
 *
 *
 */
static void ikev2_parent_inI1outR1_continue(struct pluto_crypto_req_cont *pcrc
                                            , struct pluto_crypto_req *r
                                            , err_t ugh);

static stf_status
ikev2_parent_inI1outR1_tail(struct pluto_crypto_req_cont *pcrc
                            , struct pluto_crypto_req *r);

stf_status ikev2parent_inI1outR1(struct msg_digest *md)
{
    struct state *st = md->st;
    lset_t policy = POLICY_IKEV2_ALLOW;
    lset_t policy_hint = LEMPTY;
    struct connection *c;

    const struct osw_conf_options *oco = osw_init_options();

    /* if we are already processing a packet on this st, we will be unable
     * to start another crypto operation below */
    if (st && is_suspended(st)) {
        openswan_log("%s: already processing a suspended cyrpto operation "
                     "on this SA, duplicate will be dropped.", __func__);
	return STF_TOOMUCHCRYPTO;
    }

    c = find_host_connection(ANY_MATCH, &md->iface->ip_addr
                                                , md->iface->port
                                                , KH_IPADDR
                                                , &md->sender
                                                , md->sender_port
                                                , POLICY_IKEV2_ALLOW, LEMPTY, &policy_hint);
    if(c==NULL) {
        if(policy_hint & POLICY_IKEV2_ALLOW) {
            /* connection not found, because IKEv2 was not allowed */
            /* send back AUTHENTICATION_FAILED per WG mailing list discussion */
            openswan_log("connection refused, IKEv2 not authorized");
            return STF_FAIL + v2N_AUTHENTICATION_FAILED;
        }

        /*
         * be careful about responding, or logging, since it may be that we
         * are under DOS
         */
        DBG_log("no connection with matching policy found\n");
        return STF_FAIL + v2N_AUTHENTICATION_FAILED;
    }


    loglog(RC_COMMENT, "tentatively considering connection: %s\n", c ? c->name : "<none>");

    if(!st) {
	st = new_state();
	/* set up new state */
	memcpy(st->st_icookie, md->hdr.isa_icookie, COOKIE_SIZE);
	/* initialize_new_state expects valid icookie/rcookie values, so create it now */
	get_cookie(FALSE, st->st_rcookie, COOKIE_SIZE, &md->sender);
	initialize_new_state(st, c, policy, 0, NULL_FD, pcim_stranger_crypto);
	st->st_ikev2      = TRUE;
        st->st_localaddr  = md->iface->ip_addr;
        st->st_localport  = md->iface->port;
        st->st_remoteaddr = md->sender;
        st->st_remoteport = md->sender_port;
        st->st_ike_maj    = md->maj;
        st->st_ike_min    = md->min;
	change_state(st, STATE_PARENT_R1);

        md->st = st;
        md->from_state = STATE_IKEv2_BASE;
        md->transition_state = st;
    }

    /* check,as a responder, are we under dos attack or not
     * if yes go to 6 message exchange mode. it is a config option for now.
     * TBD set force_busy dynamically
     * Paul: Can we check for STF_TOOMUCHCRYPTO ?
     */
    if(oco->force_busy == TRUE)
        {
            u_char dcookie[SHA1_DIGEST_SIZE];
            chunk_t dc;
            ikev2_get_dcookie( dcookie, st->st_ni, &md->sender, st->st_icookie);
            dc.ptr = dcookie;
            dc.len = SHA1_DIGEST_SIZE;

            /* check if I1 packet contian KE and a v2N payload with type COOKIE */
            if ( md->chain[ISAKMP_NEXT_v2KE] &&   md->chain[ISAKMP_NEXT_v2N] &&
                 (md->chain[ISAKMP_NEXT_v2N]->payload.v2n.isan_type == v2N_COOKIE))
                {
                    u_int8_t spisize;
                    const pb_stream *dc_pbs;
                    chunk_t blob;
                    DBG(DBG_CONTROLMORE
                        , DBG_log("received a DOS cookie in I1 verify it"));
                    /* we received dcookie we send earlier verify it */
                    spisize = md->chain[ISAKMP_NEXT_v2N]->payload.v2n.isan_spisize;
                    dc_pbs = &md->chain[ISAKMP_NEXT_v2N]->pbs;
                    blob.ptr = dc_pbs->cur + spisize;
                    blob.len = pbs_left(dc_pbs) - spisize;
                    DBG(DBG_CONTROLMORE
                        ,DBG_dump_chunk("dcookie received in I1 Packet", blob);
                        DBG_dump("dcookie computed", dcookie, SHA1_DIGEST_SIZE));

                    if(memcmp(blob.ptr, dcookie, SHA1_DIGEST_SIZE)!=0) {
                        openswan_log("mismatch in DOS v2N_COOKIE,send a new one");
                        SEND_V2_NOTIFICATION_DATA(md, st, v2N_COOKIE, &dc);
                        return STF_FAIL + v2N_INVALID_IKE_SPI;
                    }
                    DBG(DBG_CONTROLMORE
                        ,DBG_log("dcookie received match with computed one"));
                 }
            else
                {
                    /* we are under DOS attack I1 contains no DOS COOKIE */
                    DBG(DBG_CONTROLMORE
                        ,DBG_log("busy mode on. receieved I1 without a valid dcookie");
                        DBG_log("send a dcookie and forget this state"));
                    SEND_V2_NOTIFICATION_DATA(md, st, v2N_COOKIE, &dc);
                    return STF_FAIL;
                }
        }
    else {
        DBG(DBG_CONTROLMORE ,DBG_log("will not send/process a dcookie"));

    }

    /*
     * If we did not get a KE payload, we cannot continue. There should be
     * a Notify telling us why. We inform the user, but continue to try this
     * connection via regular retransmit intervals.
     */
    if(md->chain[ISAKMP_NEXT_v2N]  && (md->chain[ISAKMP_NEXT_v2KE] == NULL))
    {
         const char *from_state_name = enum_name(&state_names, st->st_state);
         const u_int16_t isan_type = md->chain[ISAKMP_NEXT_v2N]->payload.v2n.isan_type;
         openswan_log("%s: received %s"
                     , from_state_name
                     , enum_name(&ikev2_notify_names, isan_type));
         return STF_FAIL + isan_type;
    } else if( md->chain[ISAKMP_NEXT_v2N]) {
            /* XXX/SML: KE payload came with a notification-- is there a problem? */
         DBG(DBG_CONTROL,DBG_log("received a notify.."));
    }

    /*
     * We have to agree to the DH group before we actually know who
     * we are talking to.   If we support the group, we use it.
     *
     * It is really too hard here to go through all the possible policies
     * that might permit this group.  If we think we are being DOS'ed
     * then we should demand a cookie.
     */
    {
        struct ikev2_ke *ke;
        if (md->chain[ISAKMP_NEXT_v2KE] == NULL)
                    return STF_FAIL;
        ke = &md->chain[ISAKMP_NEXT_v2KE]->payload.v2ke;

        st->st_oakley.group=lookup_group(ke->isak_group);
        if(st->st_oakley.group==NULL) {
            char fromname[ADDRTOT_BUF];

            addrtot(&md->sender, 0, fromname, ADDRTOT_BUF);
            openswan_log("rejecting I1 from %s:%u, invalid DH group=%u"
                         ,fromname, md->sender_port, ke->isak_group);
            return v2N_INVALID_KE_PAYLOAD;
        }
    }

    /* now. we need to go calculate the nonce, and the KE */
    {
        struct ke_continuation *ke = alloc_thing(struct ke_continuation
                                                 , "ikev2_inI1outR1 KE");
        stf_status e;

        ke->md = md;
        set_suspended(st, ke->md);

        if (!st->st_sec_in_use) {
            pcrc_init(&ke->ke_pcrc);
            ke->ke_pcrc.pcrc_func = ikev2_parent_inI1outR1_continue;
            e = build_ke(&ke->ke_pcrc, st, st->st_oakley.group, pcim_stranger_crypto);
            if(e != STF_SUSPEND && e != STF_INLINE) {
                loglog(RC_CRYPTOFAILED, "system too busy");
                delete_state(st);
            }
        } else {
            e = ikev2_parent_inI1outR1_tail((struct pluto_crypto_req_cont *)ke
                                            , NULL);
        }

        reset_globals();

        return e;
    }
}

static void
ikev2_parent_inI1outR1_continue(struct pluto_crypto_req_cont *pcrc
                                , struct pluto_crypto_req *r
                                , err_t ugh)
{
    struct ke_continuation *ke = (struct ke_continuation *)pcrc;
    struct msg_digest *md = ke->md;
    struct state *const st = md->st;
    stf_status e;

    DBG(DBG_CONTROLMORE
        , DBG_log("ikev2 parent inI1outR1: calculated ke+nonce, sending R1"));

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

    assert_suspended(st, ke->md);
    set_suspended(st,NULL);        /* no longer connected or suspended */

    set_cur_state(st);

    st->st_calculating = FALSE;

    e = ikev2_parent_inI1outR1_tail(pcrc, r);

    if(ke->md != NULL) {
        complete_v2_state_transition(&ke->md, e);
        if(ke->md) release_md(ke->md);
    }
    reset_globals();

    passert(GLOBALS_ARE_RESET());
}

static stf_status
ikev2_parent_inI1outR1_tail(struct pluto_crypto_req_cont *pcrc
                            , struct pluto_crypto_req *r)
{
    struct ke_continuation *ke = (struct ke_continuation *)pcrc;
    struct msg_digest *md = ke->md;
    struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
    struct state *const st = md->st;
    stf_status notok;
    int    numvidtosend=0;
#ifdef PLUTO_SENDS_VENDORID
    numvidtosend++;  /* we send Openswan VID */
#endif
    bool send_certreq = FALSE;

    if (sa_pd == NULL) {
                return STF_FAIL;
    }

    /* note that we don't update the state here yet */

    /* record first packet for later checking of signature */
    clonetochunk(st->st_firstpacket_him, md->message_pbs.start
                 , pbs_offset(&md->message_pbs), "saved first received packet");


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
    }


    /* make sure HDR is at start of a clean buffer */
    zero(reply_buffer);
    init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer), "reply packet");

    /* HDR out */
    {
        struct isakmp_hdr r_hdr = md->hdr;

        memcpy(r_hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);

        r_hdr.isa_version = IKEv2_MAJOR_VERSION << ISA_MAJ_SHIFT | IKEv2_MINOR_VERSION;
        r_hdr.isa_np = ISAKMP_NEXT_v2SA;
        r_hdr.isa_flags = ISAKMP_FLAGS_R|IKEv2_ORIG_INITIATOR_FLAG(st);
        r_hdr.isa_msgid = st->st_msgid;
        if (!out_struct(&r_hdr, &isakmp_hdr_desc, &reply_stream, &md->rbody))
            return STF_INTERNAL_ERROR;
    }

    /* start of SA out */
    {
        struct ikev2_sa r_sa = sa_pd->payload.v2sa;
        v2_notification_t rn;
        pb_stream r_sa_pbs;

        r_sa.isasa_np = ISAKMP_NEXT_v2KE;  /* XXX */
        if (!out_struct(&r_sa, &ikev2_sa_desc, &md->rbody, &r_sa_pbs))
            return STF_INTERNAL_ERROR;

        /* SA body in and out */
        rn = ikev2_parse_parent_sa_body(&sa_pd->pbs, &sa_pd->payload.v2sa,
                                        &r_sa_pbs, st, FALSE);

        if (rn != v2N_NOTHING_WRONG)
            return STF_FAIL + rn;
    }

    if((notok = accept_v2_KE(md, st, &st->st_gi, "Gi"))!=STF_OK) {
        /* error notification was already sent, kill the state */
        md->st = NULL;
        delete_state(st);
        return notok;
    }

    /* Ni in */
    RETURN_STF_FAILURE(accept_v2_nonce(md, &st->st_ni, "Ni"));

    /* send KE */
    if(!ship_v2KE(st, r, &st->st_gr, &md->rbody, ISAKMP_NEXT_v2Nr))
        return STF_INTERNAL_ERROR;

    /* send NONCE */
    unpack_nonce(&st->st_nr, r);
    if(!justship_v2Nonce(st, &md->rbody, &st->st_nr, 0)) {
        return STF_INTERNAL_ERROR;
    }

    if(!justship_v2nat(st, &md->rbody)) {
        return STF_INTERNAL_ERROR;
    }

    send_certreq = doi_send_ikev2_certreq_thinking(st, RESPONDER);
    if (send_certreq) {
        stf_status stf;

	stf = ikev2_send_certreq(st, md, RESPONDER, &md->rbody);
	if (stf != STF_OK) {
            DBG(DBG_CONTROL
                , DBG_log("sending CERTREQ failed with %s",
                          stf_status_name(stf)));
            return stf;
        }
    }

    /* Send VendrID if needed VID */
    {
        pbs_set_np(&md->rbody, ISAKMP_NEXT_v2V);
        if (!out_generic_raw(0, &isakmp_vendor_id_desc, &md->rbody
                             , pluto_vendorid, strlen(pluto_vendorid), "Vendor ID"))
            return STF_INTERNAL_ERROR;
    }

    /* IKEv2 should not add additional padding after the last payload; we used
     * to call close_message(&md->rbody) here, but that added additional
     * padding bytes after the last payload, and would mess up auth hashing */
    close_output_pbs(&md->rbody);
    close_output_pbs(&reply_stream);

    /* let TCL hack it before we mark the length. */
    TCLCALLOUT("v2_avoidEmitting", st, st->st_connection, md);

    /* keep it for a retransmit if necessary */
    freeanychunk(st->st_tpacket);
    clonetochunk(st->st_tpacket, reply_stream.start, pbs_offset(&reply_stream)
                 , "reply packet for ikev2_parent_inI1outR1_tail")

        /* save packet for later signing */
        freeanychunk(st->st_firstpacket_me);
    clonetochunk(st->st_firstpacket_me, reply_stream.start
                 , pbs_offset(&reply_stream), "saved first packet");


    /* while waiting for initiator to continue, arrange to die if nothing happens */
    delete_event(st);
    event_schedule(EVENT_SO_DISCARD, 300, st);

    return STF_OK;

}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
