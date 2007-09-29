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



