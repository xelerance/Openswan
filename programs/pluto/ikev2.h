/*
 * Copyright (C) 2002  D. Hugh Redelmeier.
 * Copyright (C) 2020  Michael Richardson <mcr@xelerance.com>
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
 */
#ifndef _IKEV2_H
#define _IKEv2_H

/*
 * IKEv2 functions: that ikev2_parent.c/ikev2_child.c needs.
 *
 */
extern stf_status ikev2parent_outI1(int whack_sock
				    , struct connection *c
				    , struct state *predecessor
                                    , so_serial_t  *newstateno
				    , lset_t policy
				    , unsigned long try
				    , enum crypto_importance importance
				    , struct xfrm_user_sec_ctx_ike * uctx
				    );

extern stf_status ipsec_outI1(int whack_sock
                              , struct state *isakmp_sa
                              , struct connection *c
                              , lset_t policy
                              , unsigned long try
                              , so_serial_t replacing
                              , struct xfrm_user_sec_ctx_ike * uctx);

extern stf_status ikev2child_outC1(int whack_sock
                            , struct state *parentst
                            , struct connection *c
                            , lset_t policy
                            , unsigned long try /* how many attempts so far */
                            , so_serial_t replacing
                            , struct xfrm_user_sec_ctx_ike * uctx UNUSED
                                   );


extern stf_status ikev2parent_outI1_withstate(struct state *st
                            , int whack_sock
                            , struct connection *c
                            , struct state *predecessor
                            , lset_t policy
                            , unsigned long try /* how many attempts so far */
                            , enum crypto_importance importance
                            , struct xfrm_user_sec_ctx_ike * uctx
                                              );

extern void ikev2_delete_out(struct state *st);

extern bool ikev2_out_attr(unsigned int type
        , unsigned long val
        , struct_desc *attr_desc
        , enum_names **attr_val_descs USED_BY_DEBUG
        , pb_stream *pbs);

extern bool ikev2_out_sa(pb_stream *outs
			 , unsigned int protoid
			 , struct db_sa *sadb
			 , struct state *st
			 , bool parentSA
			 , u_int8_t np);

extern void complete_v2_state_transition(struct msg_digest **mdp
					 , stf_status result);

extern stf_status process_informational_ikev2(struct msg_digest *md);
extern stf_status ikev2parent_inI1outR1(struct msg_digest *md);
extern stf_status ikev2parent_ntf_inR1(struct msg_digest *md);
extern stf_status ikev2parent_ntf_inR2(struct msg_digest *md);
extern stf_status ikev2parent_inR1failed(struct msg_digest *md);
extern stf_status ikev2parent_inR1outI2(struct msg_digest *md);
extern stf_status ikev2parent_inI2outR2(struct msg_digest *md);
extern stf_status ikev2parent_inR2(struct msg_digest *md);
extern stf_status ikev2child_inCI1(struct msg_digest *md);
extern stf_status ikev2child_inCR1(struct msg_digest *md);
extern stf_status ikev2child_inCR1_ntf(struct msg_digest *md);
extern stf_status ikev2child_inI3(struct msg_digest *md);
extern stf_status ikev2_child_validate_responder_proposal(struct msg_digest *md
                                                          , struct state *st);
extern stf_status ikev2_child_notify_process(struct msg_digest *md
                                             , struct state *st);

#define SEND_V2_NOTIFICATION_XCHG_DATA(md, st, xchg, type, data) { \
    if (st) send_v2_notification_from_state(st, xchg, type, data); \
    else send_v2_notification_from_md(md, xchg, type, data); }

#define SEND_V2_NOTIFICATION_DATA(md, st, type, data) { \
    enum isakmp_xchg_types xchg = (md)->hdr.isa_xchg; \
    SEND_V2_NOTIFICATION_XCHG_DATA(md, st, xchg, type, data); }

#define SEND_V2_NOTIFICATION(md, st, type) \
    SEND_V2_NOTIFICATION_DATA(md, st, type, NULL)

extern const struct state_v2_microcode ikev2_parent_firststate_microcode;
extern const struct state_v2_microcode ikev2_childrekey_microcode;


extern stf_status accept_v2_KE(struct msg_digest *md, struct state *st, chunk_t *ke, const char *name);
extern v2_notification_t accept_v2_nonce(struct msg_digest *md, chunk_t *dest
				      , const char *name);

/* MAGIC: perform f, a function that returns v2_notification_t
 * and return from the ENCLOSING stf_status returning function if it fails.
 */
#define RETURN_STF_FAILURE2(f, xf)					\
    { int r = (f); if (r != NOTHING_WRONG) { \
	  if((xf)!=NULL) pfree(xf);	     \
	  return STF_FAIL + r; }}

#define RETURN_STF_FAILURE(f) RETURN_STF_FAILURE2(f, NULL)

extern v2_notification_t ikev2_parse_parent_sa_body(
	pb_stream *sa_pbs,              /* body of input SA Payload */
	const struct ikev2_sa *sa_prop UNUSED, /* header of input SA Payload */
	pb_stream *r_sa_pbs,	    /* if non-NULL, where to emit winning SA */
	struct state *st,  	            /* current state object */
	bool selection                 /* if this SA is a selection, only one
					* tranform can appear. */
	);

extern v2_notification_t ikev2_parse_child_sa_body(
	pb_stream *sa_pbs,              /* body of input SA Payload */
	const struct ikev2_sa *sa_prop UNUSED, /* header of input SA Payload */
	pb_stream *r_sa_pbs,	    /* if non-NULL, where to emit winning SA */
	struct state *st,  	            /* current state object */
	bool selection                 /* if this SA is a selection, only one
					* tranform can appear. */
	);

#if 0
extern v2_notification_t parse_ikev2_sa_body(pb_stream *sa_pbs
					  , const struct ikev2_sa *sa
					  , pb_stream *r_sa_pbs
					  , struct state *st
					  , bool selection
					  , bool parentSA);
#endif

extern void send_v2_notification_from_state(struct state *st,
					    enum isakmp_xchg_types xchg,
					    u_int16_t ntf_type, chunk_t *data);

extern void send_v2_notification_from_md(struct msg_digest *md,
					 enum isakmp_xchg_types xchg,
					 u_int16_t ntf_type, chunk_t *data);
extern stf_status ikev2_process_encrypted_payloads(struct msg_digest *md,
					 pb_stream   *in_pbs,
					 unsigned int np);

extern bool ikev2_decode_peer_id(struct msg_digest *md
				 , enum phase1_role initiator);
extern bool ikev2_decode_local_id(struct msg_digest *md
                               , enum phase1_role initiator);
extern void ikev2_log_parentSA(struct state *st);

extern bool ikev2_calculate_rsa_sha1(struct state *st
				     , enum phase1_role role
				     , unsigned char *idhash
				     , pb_stream *a_pbs);

extern bool ikev2_calculate_psk_auth(struct state *st
				     , enum phase1_role role
				     , unsigned char *idhash
				     , pb_stream *a_pbs);

extern stf_status ikev2_verify_rsa_sha1(struct state *st
					, enum phase1_role role
                                     , struct IDhost_pair *hp
				   , unsigned char *idhash
				   , const struct pubkey_list *keys_from_dns
				   , const struct gw_info *gateways_from_dns
				   , pb_stream *sig_pbs);

extern stf_status ikev2_verify_psk_auth(struct state *st
					, enum phase1_role role
                                     , struct IDhost_pair *hp
				   , unsigned char *idhash
				   , pb_stream *sig_pbs);

extern stf_status ikev2_emit_ipsec_sa(struct msg_digest *md
				      , pb_stream *outpbs
				      , unsigned int np
				      , struct connection *c
				      , lset_t policy);

extern stf_status ikev2_derive_child_keys(struct state *st
				    , enum phase1_role role);

extern int ikev2_evaluate_connection_fit(struct connection *d
                                         , struct state *st
				, struct spd_route *sr
				, enum phase1_role role
				, struct traffic_selector *tsi
				, struct traffic_selector *tsr
				, unsigned int tsi_n
				, unsigned int tsr_n);

extern int ikev2_evaluate_connection_port_fit(const struct connection *d
                                              , const struct spd_route *sr
                                              , enum phase1_role role
                                              , const struct traffic_selector *tsi
                                              , const struct traffic_selector *tsr
                                              , int tsi_n
                                              , int tsr_n
                                              , int *best_tsi_i
                                              , int *best_tsr_i);

extern int ikev2_evaluate_connection_protocol_fit(const struct connection *d,
						  const struct spd_route *sr,
						  enum phase1_role role,
						  const struct traffic_selector *tsi,
						  const struct traffic_selector *tsr,
						  int tsi_n,
						  int tsr_n,
						  int *best_tsi_i,
						  int *best_tsr_i);

extern stf_status ikev2_emit_ts(struct msg_digest *md
				, pb_stream *outpbs
				, unsigned int np
				, struct traffic_selector *ts);

extern stf_status ikev2_calc_emit_ts(struct msg_digest *md
                                     , pb_stream *outpbs
                                     , enum phase1_role role
                                     , struct connection *c0
                                     , lset_t policy);

extern int ikev2_parse_ts(struct payload_digest *ts_pd
				, struct traffic_selector *array
				, unsigned int array_max);

extern stf_status ikev2_child_ts_evaluate(struct traffic_selector tsi[16]
                                          , unsigned int tsi_n
                                          , struct traffic_selector tsr[16]
                                          , unsigned int tsr_n
                                          , enum phase1_role role
                                          , struct state *pst
                                          , struct connection *c
                                          , struct connection **b_result
                                          , struct spd_route  **bsr_result);
extern stf_status ikev2_child_sa_respond(struct msg_digest *md
                                         , struct state *childst
					 , pb_stream *outpbs);

extern struct traffic_selector ikev2_end_to_ts(struct end *e, ip_address endpoint);
extern void ikev2_update_counters(struct msg_digest *md);
extern void ikev2_print_ts(struct traffic_selector *ts);


extern void send_v2_notification(struct state *p1st
				   , enum isakmp_xchg_types xchg_type
				   , notification_t ntf_type
				   , u_char *icookie
				   , u_char *rcookie
				   , chunk_t *n_data);

extern int send_v2_notification_enc(struct msg_digest *md
				    , enum isakmp_xchg_types xchg_type
				    , notification_t ntf_type
				    , chunk_t *notify_data);

extern void calculate_nat_hash(const unsigned char cookie_i[COOKIE_SIZE]
                               , const unsigned char cookie_r[COOKIE_SIZE]
                               , const ip_address addr
                               , const unsigned short port
                               , unsigned char digest[SHA1_DIGEST_SIZE]);

extern stf_status process_nat_payload(struct state *st
                                      , struct msg_digest *md
                                      , struct payload_digest *p
                                      , const char *payload_name
                                      , v2_notification_t notify_type
                                      , chunk_t *data);

extern stf_status ikev2_process_notifies(struct state *st, struct msg_digest *md);

extern void ikev2_enable_nat_keepalives(struct state *st);




extern bool doi_send_ikev2_certreq_thinking(struct state *st, enum phase1_role role);
extern bool doi_send_ikev2_cert_thinking( struct state *st);

extern stf_status ikev2_send_certreq( struct state *st
				      , struct msg_digest *md
				      , enum phase1_role role
				      , pb_stream *outpbs);
extern stf_status ikev2_send_cert( struct state *st
				   , struct msg_digest *md
				   , enum phase1_role role
				   , pb_stream *outpbs);
extern bool ship_v2N (unsigned int np, u_int8_t  critical,
				    u_int8_t protoid, chunk_t *spi,
					u_int16_t type, chunk_t *n_data, pb_stream *rbody);

extern bool justship_v2KE(struct state *st UNUSED
                          , chunk_t *g, unsigned int oakley_group
                          , pb_stream *outs, u_int8_t np);
extern bool justship_v2Nonce(struct state *st, pb_stream *outpbs, chunk_t *nonce, unsigned int np);
extern bool justship_v2nat(struct state *st, pb_stream *outpbs);

extern void ikev2_padup_pre_encrypt(struct msg_digest *md
                                    , pb_stream *e_pbs_cipher);

extern unsigned char *ikev2_authloc(struct msg_digest *md
                                    , pb_stream *e_pbs);

extern stf_status ikev2_encrypt_msg(struct msg_digest *md,
                                    enum phase1_role init,
                                    unsigned char *authstart,
                                    unsigned char *iv,
                                    unsigned char *encstart,
                                    unsigned char *authloc,
                                    pb_stream *e_pbs UNUSED,
                                    pb_stream *e_pbs_cipher);
extern stf_status ikev2_decrypt_msg(struct msg_digest *md
                                    , enum phase1_role init);


extern bool force_busy;  /* config option to emulate responder under DOS */

/* allocate a transmit slot */
extern stf_status allocate_msgid_from_parent(struct state *pst, msgid_t *newid_p);

extern err_t try_RSA_signature_v2(const u_char hash_val[MAX_DIGEST_LEN]
                                  , size_t hash_len
                                  , const pb_stream *sig_pbs, struct pubkey *kr
                                  , struct state *st);

extern void ikev2_calculate_sighash(struct state *st
                                    , enum phase1_role role
                                    , unsigned char *idhash
                                    , chunk_t firstpacket
                                    , unsigned char *sig_octets);

extern bool spdb_v2_match_parent(struct db_sa *sadb,
                                unsigned propnum,
                                unsigned encr_transform,
                                int encr_keylen,
                                unsigned integ_transform,
                                unsigned prf_transform,
                                unsigned dh_transform);
#endif /* IKEV2H */
