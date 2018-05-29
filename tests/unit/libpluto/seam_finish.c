#ifndef __seam_finish_c__
#define __seam_finish_c__
struct pluto_crypto_req;
void finish_dh_v2(struct state *st,
		  struct pluto_crypto_req *r)
{
	//struct pcr_skeycalc_v2 *dhv2 = &r->pcr_d.dhv2;

#define CLONEIT(X) \
    clonetochunk(st->st_##X \
		 , SS(X.ptr) \
		 , SS(X.len) \
		 ,   "calculated " #X "shared secret");

    CLONEIT(shared);
    CLONEIT(skey_d);
    CLONEIT(skey_ai);
    CLONEIT(skey_ar);
    CLONEIT(skey_ei);
    CLONEIT(skey_er);
    CLONEIT(skey_pi);
    CLONEIT(skey_pr);
#undef CLONEIT

    ikev2_validate_key_lengths(st);

    st->hidden_variables.st_skeyid_calculated = TRUE;
}
#endif
