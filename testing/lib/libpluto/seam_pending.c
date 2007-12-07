void flush_pending_by_state(struct state *st) {}
void show_pending_phase2(const struct connection *c, const struct state *st) {}

static struct connection *pending_c;
static lset_t pending_policy;

void
add_pending(int whack_sock
	    , struct state *isakmp_sa
	    , struct connection *c
	    , lset_t policy
	    , unsigned long try
	    , so_serial_t replacing)
{
	pending_c = c;
	pending_policy = policy;
}

void
update_pending(struct state *os, struct state *ns)
{
	/* nothing */
}

struct connection *first_pending(struct state *st, lset_t *policy)
{

	*policy = pending_policy;
	return pending_c;
}


