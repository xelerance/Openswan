#include "pluto/nat_traversal.h"
#include "pluto/vendor.h"

/*
 * Unit test cases actually SHOULD have this really done.
 * this is NOT DRY... XXX fix.
 */
bool nat_traversal_insert_vid(u_int8_t np, pb_stream *outs, struct state *st)
{
	bool r = TRUE;
	DBG(DBG_NATT
	    , DBG_log("nat add vid. port: %d nonike: %d"
		      , nat_traversal_support_port_floating
		      , nat_traversal_support_non_ike));

	if (nat_traversal_support_port_floating) {
	    if (st->st_connection->remotepeertype == CISCO) {
	    if (r) r = out_vid(np, outs, VID_NATT_RFC);
	    } else {
	    if (r) r = out_vid(ISAKMP_NEXT_VID, outs, VID_NATT_RFC);
	    if (r) r = out_vid(ISAKMP_NEXT_VID, outs, VID_NATT_IETF_03);
	    if (r) r = out_vid(ISAKMP_NEXT_VID, outs, VID_NATT_IETF_02_N);
	    if (r)
		r = out_vid(nat_traversal_support_non_ike ? ISAKMP_NEXT_VID : np,
			outs, VID_NATT_IETF_02);
	    }
	}
	if (nat_traversal_support_non_ike && st->st_connection->remotepeertype != CISCO) {
	    if (r) r = out_vid(np, outs, VID_NATT_IETF_00);
	}
	return r;
}


