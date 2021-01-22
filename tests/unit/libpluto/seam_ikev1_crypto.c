#ifndef __seam_ikev1_crypto_c__
#define __seam_ikev1_crypto_c__
stf_status start_dh_secret(struct pluto_crypto_req_cont *cn
			   , struct state *st
			   , enum crypto_importance importance
			   , enum phase1_role init
			   , u_int16_t oakley_group2)
{
    struct pluto_crypto_req r;
    struct pcr_skeyid_q *dhq;
    err_t e;
    bool toomuch = FALSE;

    continuation = cn;
    pcr_init(&r, pcr_compute_dh, importance);
  return STF_SUSPEND;
}

stf_status start_dh_secretiv(struct pluto_crypto_req_cont *cn
			     , struct state *st
			     , enum crypto_importance importance
			     , enum phase1_role init       /* TRUE=g_init,FALSE=g_r */
			     , u_int16_t oakley_group2)
{
    struct pluto_crypto_req r;

    continuation = cn;
    pcr_init(&r, pcr_compute_dh, importance);
  return STF_SUSPEND;
}

#endif /* __seam_ikev1_crypto_c__ */
