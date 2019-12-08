#ifndef __seam_ikev1_crypto_c__
#define __seam_ikev1_crypto_c__
stf_status start_dh_secret(struct pluto_crypto_req_cont *cn
			   , struct state *st
			   , enum crypto_importance importance
			   , enum phase1_role init
			   , u_int16_t oakley_group2)
{
  /* it will get get done */
  return STF_SUSPEND;
}

stf_status start_dh_secretiv(struct pluto_crypto_req_cont *cn
			     , struct state *st
			     , enum crypto_importance importance
			     , enum phase1_role init       /* TRUE=g_init,FALSE=g_r */
			     , u_int16_t oakley_group2)
{
  return STF_SUSPEND;
}

#endif
