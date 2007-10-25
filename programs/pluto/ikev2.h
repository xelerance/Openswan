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

