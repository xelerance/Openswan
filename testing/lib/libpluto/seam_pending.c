void flush_pending_by_state(struct state *st) {}
void show_pending_phase2(const struct connection *c, const struct state *st) {}

void
add_pending(int whack_sock
	    , struct state *isakmp_sa
	    , struct connection *c
	    , lset_t policy
	    , unsigned long try
	    , so_serial_t replacing)
{
}

void
update_pending(struct state *os, struct state *ns)
{
	/* nothing */
}



