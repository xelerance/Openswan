 #ifndef _IKEV1_H
#define _IKEv1_H

#include "pluto_crypt.h"
#include "ikev1_continuations.h"
#include "dnskey.h"

/* ikev1.c */
extern void complete_v1_state_transition(struct msg_digest **mdp, stf_status result);
extern void process_v1_packet(struct msg_digest **mdp);

/*
 * IKEv1 functions: that ikev1_main.c provides and ikev1_aggr.c
 * needs.
 */

/* continue with encrypted packet */
extern void process_packet_tail(struct msg_digest **mdp);


extern void unpack_nonce(chunk_t *n, struct pluto_crypto_req *r);
extern bool justship_nonce(chunk_t *n
			   , pb_stream *outs, u_int8_t np
			   , const char *name);

/* calls previous two routines */
extern bool ship_nonce(chunk_t *n, struct pluto_crypto_req *r
		       , pb_stream *outs, u_int8_t np
		       , const char *name);

extern notification_t accept_v1_nonce(struct msg_digest *md, chunk_t *dest
				      , const char *name);

extern bool justship_KE(chunk_t *g
			, pb_stream *outs, u_int8_t np);

/* just calls previous two routines now */
extern bool ship_KE(struct state *st
		    , struct pluto_crypto_req *r
		    , chunk_t *g
		    , pb_stream *outs, u_int8_t np);

/* **MAIN MODE FUNCTIONS** in ikev1_main.c */
extern stf_status main_outI1(int whack_sock
			     , struct connection *c
			     , struct state *predecessor
                             , so_serial_t  *newstateno
			     , lset_t policy
			     , unsigned long try
			     , enum crypto_importance importance
                             , struct xfrm_user_sec_ctx_ike * uctx
			     );

extern stf_status aggr_outI1(int whack_sock
                             , struct connection *c
                             , struct state *predecessor
                             , so_serial_t  *newstateno
                             , lset_t policy
                             , unsigned long try
			     , enum crypto_importance importance
			     , struct xfrm_user_sec_ctx_ike * uctx
			     );

extern stf_status aggr_not_present(int whack_sock
                                   , struct connection *c
                                   , struct state *predecessor
                                   , so_serial_t  *newstateno
                                   , lset_t policy
                                   , unsigned long try
                                   , enum crypto_importance importance
				   , struct xfrm_user_sec_ctx_ike * uctx
				   );

extern void ikev1_delete_out(struct state *st);


extern bool
decode_peer_id(struct msg_digest *md, bool initiator, bool aggrmode);

#ifdef HAVE_LIBNSS
extern void
main_mode_hash_body(struct state *st
                    , bool hashi        /* Initiator? */
                    , const pb_stream *idpl     /* ID payload, as PBS */
                    , struct hmac_ctx *ctx
                    , hash_update_t hash_update_void);
#else
extern void
main_mode_hash_body(struct state *st
		    , bool hashi	/* Initiator? */
		    , const pb_stream *idpl	/* ID payload, as PBS */
		    , union hash_ctx *ctx
		    , hash_update_t hash_update_void);
#endif

extern size_t
RSA_sign_hash(struct connection *c
	      , u_char sig_val[RSA_MAX_OCTETS]
	      , const u_char *hash_val, size_t hash_len);

extern err_t
try_RSA_signature_v1(const u_char hash_val[MAX_DIGEST_LEN], size_t hash_len
                     , const pb_stream *sig_pbs, struct pubkey *kr
                     , struct state *st);


extern size_t	/* length of hash */
main_mode_hash(struct state *st
	       , u_char *hash_val	/* resulting bytes */
	       , bool hashi	/* Initiator? */
	       , const pb_stream *idpl);	/* ID payload, as PBS; cur must be at end */

enum key_oppo_step {
    kos_null,
    kos_his_txt
#ifdef USE_KEYRR
    , kos_his_key
#endif
};

struct key_continuation {
    struct adns_continuation ac;	/* common prefix */
    struct msg_digest   *md;
    enum   key_oppo_step step;
    bool                 failure_ok;
    err_t                last_ugh;
};

typedef stf_status (key_tail_fn)(struct msg_digest *md
				  , struct key_continuation *kc);

extern void
key_continue(struct adns_continuation *cr
	     , err_t ugh
	     , key_tail_fn *tail);

extern stf_status
oakley_id_and_auth(struct msg_digest *md
		   , bool initiator	/* are we the Initiator? */
		   , bool aggrmode                /* aggressive mode? */
		   , cont_fn_t cont_fn	/* continuation function */
		   , const struct key_continuation *kc	/* current state, can be NULL */
		   );

static inline stf_status
aggr_id_and_auth(struct msg_digest *md
		 , bool initiator	/* are we the Initiator? */
		 , cont_fn_t cont_fn	/* continuation function */
		 , struct key_continuation *kc) /* argument */
{
    return oakley_id_and_auth(md, initiator, TRUE, cont_fn, kc);
}

extern bool
do_command(struct connection *c, const struct spd_route *sr
           , const char *verb, struct state *st);
#endif

extern bool out_sa(
    pb_stream *outs,
    struct db_sa *sadb,
    struct state *st,
    bool oakley_mode,
    enum phase1_role role,
    bool aggressive_mode,
    u_int8_t np);

#if 0
extern complaint_t accept_oakley_auth_method(
    struct state *st,   /* current state object */
    u_int32_t amethod,  /* room for larger values */
    bool credcheck);    /* whether we can check credentials now */
#endif

extern lset_t preparse_isakmp_sa_body(pb_stream *sa_pbs);

extern notification_t parse_isakmp_sa_body(
    pb_stream *sa_pbs,	/* body of input SA Payload */
    const struct isakmp_sa *sa,	/* header of input SA Payload */
    pb_stream *r_sa_pbs,	/* if non-NULL, where to emit winning SA */
    bool selection,	/* if this SA is a selection, only one tranform can appear */
    struct state *st);	/* current state object */

/* initialize a state with the aggressive mode parameters */
extern int init_am_st_oakley(struct state *st, lset_t policy);

extern notification_t parse_ipsec_sa_body(
    pb_stream *sa_pbs,	/* body of input SA Payload */
    const struct isakmp_sa *sa,	/* header of input SA Payload */
    pb_stream *r_sa_pbs,	/* if non-NULL, where to emit winning SA */
    bool selection,	/* if this SA is a selection, only one tranform can appear */
    struct state *st);	/* current state object */
/* spdb_v1_struct.c */
extern struct db_sa *ikev1_alg_makedb(lset_t policy UNUSED, struct alg_info_ike *ei
                                      , bool oneproposal
                                      , enum phase1_role role);
