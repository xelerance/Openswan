stf_status build_nonce(struct pluto_crypto_req_cont *cn
		       , struct state *st
		       , enum crypto_importance importance)
{
	continuation = cn;
	memset(&rd, 0, sizeof(rd));

        cn->pcrc_serialno    = st->st_serialno;
	crypto_req->pcr_len  = sizeof(struct pluto_crypto_req);
	crypto_req->pcr_type = pcr_build_nonce;
	crypto_req->pcr_pcim = importance;

	pcr_init(crypto_req, pcr_build_nonce, importance);

	return STF_SUSPEND;
}

