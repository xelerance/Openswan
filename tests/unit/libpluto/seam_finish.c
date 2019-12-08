#ifndef __seam_finish_c__
#define __seam_finish_c__

#define CLONETO(X,Y,Z)  \
    clonetochunk(st->st_##X \
		 , Y, Z                              \
		 ,   "calculated " #X "shared secret");

#define CLONEIT(X) CLONETO(X, SS(X.ptr), SS(X.len))



struct pluto_crypto_req;
void finish_dh_v2(struct state *st,
		  struct pluto_crypto_req *r)
{
	//struct pcr_skeycalc_v2 *dhv2 = &r->pcr_d.dhv2;

    CLONEIT(shared);
    CLONEIT(skey_d);
    CLONEIT(skey_ai);
    CLONEIT(skey_ar);
    CLONEIT(skey_ei);
    CLONEIT(skey_er);
    CLONEIT(skey_pi);
    CLONEIT(skey_pr);

    ikev2_validate_key_lengths(st);

    st->hidden_variables.st_skeyid_calculated = TRUE;
}

void finish_dh_secretiv(struct state *st,
			struct pluto_crypto_req *r)
{
    CLONEIT(shared);
    CLONEIT(skey_d);
    CLONEIT(skey_ai);
    CLONEIT(skey_ar);
    CLONEIT(skey_ei);
    CLONEIT(skey_er);
    CLONEIT(skey_pi);
    CLONEIT(skey_pr);

#if 0
    memcpy(st->st_new_iv, SS(new_iv.ptr), SS(new_iv.len));
    st->st_new_iv_len = SS(new_iv.len);
#endif

    ikev2_validate_key_lengths(st);

    st->hidden_variables.st_skeyid_calculated = TRUE;
    r->pcr_success = TRUE;
}

void finish_dh_secret(struct state *st,
		      struct pluto_crypto_req *r)
{
    struct pcr_skeyid_r *dhr = &r->pcr_d.dhr;

    CLONEIT(shared);
    CLONETO(gr, SS(gr.ptr), SS(gr.len));
    r->pcr_success = TRUE;
}



#endif


