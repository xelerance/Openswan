#ifndef INCLUDE_IKEV1_PROCESSING
stf_status
main_outI1(int whack_sock
	   , struct connection *c
	   , struct state *predecessor
	   , lset_t policy
	   , unsigned long try
	   , enum crypto_importance importance)
{
	DBG_log("MAIN OUTi1()\n");
}

void
send_notification_from_state(struct state *st, enum state_kind state,
    u_int16_t type)
{
}

void
send_notification_from_md(struct msg_digest *md, u_int16_t type)
{
}

void
ikev1_delete_out(struct state *st)
{
	printf("deleted state #%lu\n", st->st_serialno);
}
#endif
