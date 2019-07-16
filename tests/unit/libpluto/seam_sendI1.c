#include "seam_gi_sha1.c"

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
            /* now fill in the KE values from a constant.. not calculated */
            clonetowirechunk(&kn->thespace, kn->space, &kn->secret, SS(secret.ptr), SS(secret.len));
            clonetowirechunk(&kn->thespace, kn->space, &kn->n,      SS(ni.ptr), SS(ni.len));
            clonetowirechunk(&kn->thespace, kn->space, &kn->gi,     SS(gi.ptr), SS(gi.len));
          }
        }

	run_continuation(crypto_req);
        reset_globals();
}

struct state *sendI1(struct connection *c1, int debugging, int calculate)
{
	struct state *st;
	so_serial_t newone;

        passert(GLOBALS_ARE_RESET());
	c1->extra_debugging = DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;
	newone = ipsecdoi_initiate(/* whack-sock=stdout */1
                                   , NULL, NULL
                                   , c1
                                   , c1->policy
                                   , 0 /* try */
                                   , FALSE /* replacing */
                                   , pcim_demand_crypto, USER_SEC_CTX_NULL);

        passert(GLOBALS_ARE_RESET());
	/* find st involved */
	st = state_with_serialno(newone);

        if(st == NULL) return NULL;

        sendI1b(c1, debugging, calculate);

        return st;
}

