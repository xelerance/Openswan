void delete_cryptographic_continuation(struct state *st) {}

#include "pluto_crypt.h"
struct pluto_crypto_req_cont *continuation = NULL;


struct pluto_crypto_req rd;
struct pluto_crypto_req *crypto_req = &rd;

stf_status build_ke(struct pluto_crypto_req_cont *cn
		    , struct state *st
		    , const struct oakley_group_desc *group
		    , enum crypto_importance importance)
{
	continuation = cn;
	memset(&rd, 0, sizeof(rd));

	crypto_req->pcr_len  = sizeof(struct pluto_crypto_req);
	crypto_req->pcr_type = pcr_build_kenonce;
	crypto_req->pcr_pcim = importance;

	pcr_init(crypto_req, pcr_build_kenonce, importance);
	crypto_req->pcr_d.kn.oakley_group   = group->group;

	return STF_SUSPEND;
}

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


void run_one_continuation(struct pluto_crypto_req *r)
{
  struct pluto_crypto_req_cont *cn = continuation;
  continuation = NULL;

  if(cn) {
    (*cn->pcrc_func)(cn, r, NULL);
  } else {
    fprintf(stderr, "should have found a continuation, but none was found\n");
  }
}

void run_continuation(struct pluto_crypto_req *r)
{
  while(continuation != NULL) {
    run_one_continuation(r);
  }
}

bool ikev2_calculate_psk_auth(struct state *st
                              , enum phase1_role role
                              , unsigned char *idhash
                              , pb_stream *a_pbs)
{
	out_zero(20, a_pbs, "fake psk auth");
	return TRUE;
}

stf_status
ikev2_verify_psk_auth(struct state *st
		      , enum phase1_role role
		      , unsigned char *idhash
		      , pb_stream *sig_pbs)
{
	return STF_OK;
}

