#ifndef __seam_ikev1_aggr_c__
#define __seam_ikev1_aggr_c__
stf_status aggr_inI2(struct msg_digest *md) { return STF_OK; }
stf_status aggr_inI1_outR1_psk(struct msg_digest *md) { return STF_OK; }
stf_status aggr_inI1_outR1_rsasig(struct msg_digest *md) { return STF_OK; }
stf_status aggr_inR1_outI2(struct msg_digest *md) { return STF_OK; }
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

#endif
