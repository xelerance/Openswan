#if !defined(__seam_natt_c__) && (!defined(NAPT_ENABLED) || NAPT_ENABLED!=1)
#define __seam_natt_c__
#include "pluto/nat_traversal.h"
#include "pluto/vendor.h"
bool nat_traversal_support_non_ike = FALSE;
bool nat_traversal_support_port_floating = FALSE;
bool nat_traversal_enabled = FALSE;
bool nat_traversal_ka_event_called = FALSE;
bool nat_traversal_ka_event_scheduled = FALSE;

void nat_traversal_change_port_lookup(struct msg_digest *md, struct state *st)
{
}

void nat_traversal_ka_event (void)
{
    openswan_log("nat_traversal_ka_event_called = TRUE (was %s)",
		 nat_traversal_ka_event_called ? "TRUE" : "FALSE");
    nat_traversal_ka_event_called = TRUE;
}

bool nat_traversal_add_natd(u_int8_t np, pb_stream *outs,
                            struct msg_digest *md)
{
    return TRUE;
}

void nat_traversal_natd_lookup(struct msg_digest *md)
{
}

void nat_traversal_show_result (u_int32_t nt, u_int16_t sport)
{
}

u_int32_t nat_traversal_vid_to_method(unsigned short nat_t_vid)
{
    return LELEM(NAT_TRAVERSAL_RFC);
}

void nat_traversal_new_ka_event (void)
{
    openswan_log("nat_traversal_ka_event_scheduled = TRUE (was %s)",
		 nat_traversal_ka_event_scheduled ? "TRUE" : "FALSE");
    nat_traversal_ka_event_scheduled = TRUE;
}

#endif
