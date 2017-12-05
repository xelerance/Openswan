#include "kernel.h"

bool can_do_IPcomp = TRUE;  /* can system actually perform IPCOMP? */

void delete_ipsec_sa(struct state *st USED_BY_KLIPS, bool inbound_only USED_BY_KLIPS) {}

bool install_inbound_ipsec_sa(struct state *parent_st, struct state *st) { return TRUE; }
bool install_ipsec_sa(struct state *parent_st, struct state *st, bool inbound UNUSED) { return TRUE; }

ipsec_spi_t spis[4]={ 0x12345678,
		      0x34567812,
		      0x56781234,
		      0x78123456};
static int spinext=0;
bool get_ipsec_spi(struct ipsec_proto_info *pi
			  , int proto UNUSED, struct state *st UNUSED
			  , bool tunnel UNUSED)
{
	if(spinext == 4) spinext=0;
        pi->our_spi = htonl(spis[spinext++]);
        return TRUE;
}

ipsec_spi_t get_my_cpi(struct state *st, bool tunnel)
{
	if(spinext == 4) spinext=0;
	return htonl(spis[spinext++]);
}

const char *kernel_if_name(void);
const char *kernel_if_name()
{
    return "kernel_seam";
}

void scan_proc_shunts(void) {}

bool kernel_overlap_supported()
{
	return 1;
}

bool get_sa_info(struct state *st, bool inbound, time_t *ago)
{
	return FALSE;
}

bool
unit_do_command(struct connection *c, const struct spd_route *sr
                  , const char *verb, const char *verb_suffix
                  , struct state *st)
{
  DBG_log("executing %s", verb);
  return TRUE;
}


/* empty structure */
struct kernel_ops unit_kernel_ops = {
    kern_name: "netkeyunit",
    type: USE_NETKEY,
    inbound_eroute:  TRUE,
    policy_lifetime: TRUE,
    async_fdp: -1,
    replay_window: 32,

    init: init_netlink,
    pfkey_register: NULL,
    pfkey_register_response: NULL,
    process_msg: netlink_process_msg,
    raw_eroute: netlink_raw_eroute,
    add_sa: netlink_add_sa,
    del_sa: netlink_del_sa,
    get_sa: netlink_get_sa,
    process_queue: NULL,
    grp_sa: NULL,
    get_spi: netlink_get_spi,
    exceptsocket: NULL,
    docommand: unit_do_command,
    process_ifaces: netlink_process_raw_ifaces,
    shunt_eroute: netlink_shunt_eroute,
    sag_eroute: netlink_sag_eroute,
    eroute_idle: netlink_eroute_idle,
    set_debug: NULL,
    remove_orphaned_holds: NULL,
    overlap_supported: FALSE,
    sha2_truncbug_support: FALSE,
};
const struct kernel_ops *kernel_ops = &unit_kernel_ops;

bool route_and_eroute(struct connection *c USED_BY_KLIPS
                      , const struct spd_route *sr USED_BY_KLIPS
                      , struct spd_route *orig_sr USED_BY_KLIPS
                      , struct state *st USED_BY_KLIPS) { return TRUE; }

bool replace_bare_shunt(const ip_address *src, const ip_address *dst
                        , policy_prio_t policy_prio
                        , ipsec_spi_t shunt_spi      /* in host order! */
                        , bool repl  /* if TRUE, replace; if FALSE, delete */
                        , int transport_proto
                        , const char *why) { return TRUE; }

ipsec_spi_t shunt_policy_spi(struct connection *c, bool prospective) { return 1; }

bool assign_hold(struct connection *c USED_BY_DEBUG
                 , struct spd_route *sr
                 , int transport_proto
                 , const ip_address *src, const ip_address *dst) { return TRUE; }

bool has_bare_hold(const ip_address *src, const ip_address *dst, int transport_proto) { return FALSE;}

