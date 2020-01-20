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

    __validate_key_lengths(st, "seam", __func__, __LINE__);

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
    CLONEIT(enc_key);

    memcpy(st->st_new_iv, SS(new_iv.ptr), SS(new_iv.len));
    st->st_new_iv_len = SS(new_iv.len);

    //fprintf(stderr, "seam %s %u %u\n",  SS(secrets_name), SS(new_iv.len), st->st_new_iv_len);
    __validate_key_lengths(st, "seam", __func__, __LINE__);

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


