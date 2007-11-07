/*
 * IKEv2 functions: that ikev2_parent.c/ikev2_child.c needs.
 *
 */
extern stf_status ikev2parent_outI1(int whack_sock
				    , struct connection *c
				    , struct state *predecessor
				    , lset_t policy
				    , unsigned long try
				    , enum crypto_importance importance);

extern void ikev2_delete_out(struct state *st);

extern bool ikev2_out_sa(pb_stream *outs
			 , struct db_sa *sadb
			 , struct state *st
			 , u_int8_t np);

extern void complete_v2_state_transition(struct msg_digest **mdp
					 , stf_status result);

extern stf_status ikev2parent_inI1(struct msg_digest *md);
extern stf_status ikev2parent_inR1(struct msg_digest *md);
extern const struct state_v2_microcode *ikev2_parent_firststate(void);

/* MAGIC: perform f, a function that returns notification_t
 * and return from the ENCLOSING stf_status returning function if it fails.
 */
#define RETURN_STF_FAILURE2(f, xf)					\
    { int r = (f); if (r != NOTHING_WRONG) { \
	  if((xf)!=NULL) pfree(xf);	     \
	  return STF_FAIL + r; }}

#define RETURN_STF_FAILURE(f) RETURN_STF_FAILURE2(f, NULL)

extern notification_t parse_ikev2_sa_body(pb_stream *sa_pbs
					  , const struct ikev2_sa *sa
					  , pb_stream *r_sa_pbs
					  , bool selection
					  , struct state *st);
