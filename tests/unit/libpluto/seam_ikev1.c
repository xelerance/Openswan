stf_status
aggr_outI1(int whack_sock,
	   struct connection *c,
	   struct state *predecessor,
	   lset_t policy,
	   unsigned long try
	   , enum crypto_importance importance)
{
	fprintf(stderr, "IKEv1 aggressive output requested\n");
	osw_abort();
}

#ifndef OMIT_MAIN_MODE
#include "seam_ikev1_main.c"
#endif

stf_status
quick_outI1(int whack_sock
	    , struct state *isakmp_sa
	    , struct connection *c
	    , lset_t policy
	    , unsigned long try
	    , so_serial_t replacing
            , struct xfrm_user_sec_ctx_ike * uctx)
{
	fprintf(stderr, "IKEv1 quick output requested\n");
	osw_abort();
}

#ifndef INCLUDE_IKEV1_PROCESSING
void
process_v1_packet(struct msg_digest **mdp)
{
	fprintf(stderr, "IKEv1 packet received\n");
	osw_abort();
}

void process_packet_tail(struct msg_digest **mdp) {}

void init_demux(void) {}
#endif

