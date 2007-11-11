void delete_cryptographic_continuation(struct state *st) {}

#include "pluto_crypt.h"
struct pluto_crypto_req_cont *continuation;


struct pluto_crypto_req rd;
struct pluto_crypto_req *r = &rd;

stf_status build_ke(struct pluto_crypto_req_cont *cn
		    , struct state *st 
		    , const struct oakley_group_desc *group
		    , enum crypto_importance importance)
{
	continuation = cn;
	err_t e;
	bool toomuch = FALSE;
	
	memset(&rd, 0, sizeof(rd));
	
	r->pcr_len  = sizeof(struct pluto_crypto_req);
	r->pcr_type = pcr_build_kenonce;
	r->pcr_pcim = importance;
	
	pcr_init(r);
	r->pcr_d.kn.oakley_group   = group->group;

	return STF_SUSPEND;
}

void run_continuation(struct pluto_crypto_req *r)
{
	while(continuation != NULL) {
		struct pluto_crypto_req_cont *cn = continuation;
		continuation = NULL;
		(*cn->pcrc_func)(cn, r, NULL);
	}
}


