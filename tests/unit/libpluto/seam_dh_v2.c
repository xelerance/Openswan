#ifndef __seam_dh_v2__
#define __seam_dh_v2__
struct pluto_crypto_req;

stf_status start_dh_v2(struct pluto_crypto_req_cont *cn
		       , struct state *st
		       , enum crypto_importance importance
		       , enum phase1_role init       /* TRUE=g_init,FALSE=g_r */
		       , u_int16_t oakley_group2)
{
	continuation = cn;
	memset(&rd, 0, sizeof(rd));

	crypto_req->pcr_len  = sizeof(struct pluto_crypto_req);
	crypto_req->pcr_type = pcr_compute_dh_v2;
	crypto_req->pcr_pcim = importance;

	pcr_init(&rd, pcr_compute_dh_v2, importance);
	crypto_req->pcr_d.kn.oakley_group   = oakley_group2;

	return STF_SUSPEND;
}

#endif
