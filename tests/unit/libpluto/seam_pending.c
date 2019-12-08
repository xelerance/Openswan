#ifndef __seam_pending_c__
#ifndef OMIT_ADD_PENDING
#define __seam_pending_c__
struct state;
void flush_pending_by_state(struct state *st) {}
void show_pending_phase2(const struct connection *c, const struct state *st) {}
void release_pending_whacks(struct state *st, err_t story) {}
void flush_pending_by_connection(struct connection *c) {}


static struct connection *pending_c;
static int pending_whack_sock;
static lset_t pending_policy;

int
add_pending(int whack_sock
	    , struct state *isakmp_sa
	    , struct connection *c
	    , lset_t policy
	    , unsigned long try
	    , so_serial_t replacing
            , struct xfrm_user_sec_ctx_ike * uctx)

{
	pending_c = c;
	pending_policy = policy;
	pending_whack_sock = whack_sock;

	return 0;
}

int
update_pending(struct state *os, struct state *ns)
{
	return 0;
}

struct connection *first_pending(struct state *st, lset_t *policy, int *p_whack_sock)
{

	*policy = pending_policy;
	*p_whack_sock = pending_whack_sock;
	return pending_c;
}


#endif /* OMIT_ADD_PENDING */
#endif
