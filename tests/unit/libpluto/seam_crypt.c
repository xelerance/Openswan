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

bool ikev2_calculate_rsa_sha1(struct state *st
			      , enum phase1_role role
			      , unsigned char *idhash
			      , pb_stream *a_pbs)
{
  static int fakesig = 1;

	out_zero(192, a_pbs, "fake rsa sig");
        snprintf(st->st_our_keyid, sizeof(st->st_our_keyid), "fakesig%u", fakesig++);
	return TRUE;
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

stf_status
ikev2_verify_rsa_sha1(struct state *st
		      , enum phase1_role role
			    , unsigned char *idhash
			    , const struct pubkey_list *keys_from_dns
			    , const struct gw_info *gateways_from_dns
			    , pb_stream *sig_pbs)
{
  static int fakecheck = 1;
  struct pubkey_list *p, **pp;
  struct connection *c = st->st_connection;
  int pathlen;

  pp = &pluto_pubkeys;

  snprintf(st->st_their_keyid, sizeof(st->st_their_keyid), "fakecheck%u", fakecheck++);

  {

    DBG(DBG_CONTROL,
        char buf[IDTOA_BUF];
        dntoa_or_null(buf, IDTOA_BUF, c->spd.that.ca, "%any");
        DBG_log("ikev2 verify required CA is '%s'", buf));
  }

  {
    time_t n;
    n = 1438262454;   /* Thu Jul 30 09:21:01 EDT 2015 in seconds */
    list_certs(n);
  }

  for (p = pluto_pubkeys; p != NULL; p = *pp)
    {
      char keyname[IDTOA_BUF];
      struct pubkey *key = p->key;
      pp = &p->next;

      idtoa(&key->id, keyname, IDTOA_BUF);
      DBG_log("checking alg=%d == %d, keyid=%s same_id=%u\n"
              , key->alg, PUBKEY_ALG_RSA
              , keyname
              , same_id(&st->ikev2.st_peer_id, &key->id));
      if (key->alg == PUBKEY_ALG_RSA
          && same_id(&st->ikev2.st_peer_id, &key->id)
          && (key->dns_auth_level > DAL_UNSIGNED || trusted_ca(key->issuer, c->spd.that.ca, &pathlen)))
        {
          time_t tnow;

          DBG(DBG_CONTROL,
              char buf[IDTOA_BUF];
              dntoa_or_null(buf, IDTOA_BUF, key->issuer, "%any");
              DBG_log("key issuer CA is '%s'", buf));

          /* check if found public key has expired */
          time(&tnow);
          if (key->until_time != UNDEFINED_TIME && key->until_time < tnow)
            {
              loglog(RC_LOG_SERIOUS,
                     "cached RSA public key has expired and has been deleted");
              *pp = free_public_keyentry(p);
              continue; /* continue with next public key */
            }

          return STF_OK;
        }
    }

  list_public_keys(TRUE, FALSE);
  return STF_FAIL + INVALID_KEY_INFORMATION;
}

