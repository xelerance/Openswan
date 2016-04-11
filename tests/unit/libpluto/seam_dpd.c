#include "pluto/dpd.h"

stf_status dpd_init(struct state *st) { return STF_OK; }

void dpd_event(struct state *st) {}

void p1_dpd_outI1(struct state *p1st) {};
void p2_dpd_outI1(struct state *p2st) {};
stf_status dpd_inI_outR(struct state *st
			       , struct isakmp_notification *const n
			       , pb_stream *pbs) {
	return STF_OK;
}

stf_status dpd_inR(struct state *st
			  , struct isakmp_notification *const n
			  , pb_stream *pbs) {
	return STF_OK;
}

void dpd_timeout(struct state *st)  {
}


