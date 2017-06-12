struct state *sendI1_short(struct connection *c1, int debugging)
{
	struct state *st;
	struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;  /* r is a global in the seams */

	c1->extra_debugging = DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;
	ipsecdoi_initiate(/* whack-sock=stdout */1
                          , NULL, NULL
			  , c1
			  , c1->policy
			  , 0
			  , FALSE
			  , pcim_demand_crypto, USER_SEC_CTX_NULL);

	/* find st involved */
	st = state_with_serialno(1);

	cur_debugging = debugging;
	c1->extra_debugging = debugging;

	/* now fill in the KE values from a constant.. not calculated */
	clonetowirechunk(&kn->thespace, kn->space, &kn->secret, tc3_secret,tc3_secret_len);
	clonetowirechunk(&kn->thespace, kn->space, &kn->n,   tc3_ni, tc3_ni_len);
	clonetowirechunk(&kn->thespace, kn->space, &kn->gi,  tc3_gi, tc3_gi_len);

	run_continuation(crypto_req);

	return st;
}

void sendI1b(struct connection *c1, int debugging, int calculate)
{
	struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;  /* r is a global in the seams */

	cur_debugging = debugging;
	c1->extra_debugging = debugging;

        if(continuation) {
          if(calculate) {
            calc_ke(crypto_req);
            calc_nonce(crypto_req);
          } else {
            passert(kn->oakley_group == tc14_oakleygroup);
            /* now fill in the KE values from a constant.. not calculated */
            clonetowirechunk(&kn->thespace, kn->space, &kn->secret, tc14_secret,tc14_secret_len);
            clonetowirechunk(&kn->thespace, kn->space, &kn->n,   tc14_ni, tc14_ni_len);
            clonetowirechunk(&kn->thespace, kn->space, &kn->gi,  tc14_gi, tc14_gi_len);
          }
        }

	run_continuation(crypto_req);
}

struct state *sendI1(struct connection *c1, int debugging, int calculate)
{
	struct state *st;
	so_serial_t newone;

	c1->extra_debugging = DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;
	newone = ipsecdoi_initiate(/* whack-sock=stdout */1
                                   , NULL, NULL
                                   , c1
                                   , c1->policy
                                   , 0 /* try */
                                   , FALSE /* replacing */
                                   , pcim_demand_crypto, USER_SEC_CTX_NULL);

	/* find st involved */
	st = state_with_serialno(newone);

        if(st == NULL) return NULL;

        sendI1b(c1, debugging, calculate);

        return st;
}

