stf_status
aggr_outI1(int whack_sock,
	   struct connection *c,
	   struct state *predecessor,
	   lset_t policy,
	   unsigned long try
	   , enum crypto_importance importance)
{
	abort();
}

stf_status
main_outI1(int whack_sock
	   , struct connection *c
	   , struct state *predecessor
	   , lset_t policy
	   , unsigned long try
	   , enum crypto_importance importance)
{
	abort();
}

stf_status
quick_outI1(int whack_sock
	    , struct state *isakmp_sa
	    , struct connection *c
	    , lset_t policy
	    , unsigned long try
	    , so_serial_t replacing)
{
	abort();
}

void
ikev1_delete_out(struct state *st)
{
	printf("deleted state #%lu\n", st->st_serialno);
}
