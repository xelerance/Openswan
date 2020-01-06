#ifndef __seam_rsa_check_c__
#define __seam_rsa_check_c__
stf_status
check_signature_gen(struct connection *d
                    , struct state *st
			, const u_char hash_val[MAX_DIGEST_LEN]
			, size_t hash_len
			, const pb_stream *sig_pbs
#ifdef USE_KEYRR
			, const struct pubkey_list *keys_from_dns
#endif /* USE_KEYRR */
			, const struct gw_info *gateways_from_dns
			, err_t (*try_RSA_signature)(const u_char hash_val[MAX_DIGEST_LEN]
						     , size_t hash_len
						     , const pb_stream *sig_pbs
						     , struct pubkey *kr
						     , struct state *st))
{
  return STF_OK;
}

#endif
