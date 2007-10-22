void delete_cryptographic_continuation(struct state *st) {}

#include "pluto_crypt.h"
struct pluto_crypto_req_cont *continuation;


stf_status build_ke(struct pluto_crypto_req_cont *cn
		    , struct state *st 
		    , const struct oakley_group_desc *group
		    , enum crypto_importance importance)
{
	continuation = cn;

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


