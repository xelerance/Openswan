#include "kernel.h"
void delete_ipsec_sa(struct state *st USED_BY_KLIPS, bool inbound_only USED_BY_KLIPS) {}

bool install_inbound_ipsec_sa(struct state *parent_st, struct state *st) { return TRUE; }
bool install_ipsec_sa(struct state *parent_st, struct state *st, bool inbound UNUSED) { return TRUE; }

ipsec_spi_t spis[4]={ 0x12345678,
		      0x34567812,
		      0x56781234,
		      0x78123456};
static int spinext=0;
ipsec_spi_t get_ipsec_spi(ipsec_spi_t avoid UNUSED
			  , int proto UNUSED, struct spd_route *sr UNUSED
			  , bool tunnel UNUSED)
{
	if(spinext == 4) spinext=0;
	return htonl(spis[spinext++]);
}

ipsec_spi_t
get_my_cpi(struct spd_route *sr, bool tunnel)
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

/* empty structure */
static struct kernel_ops unit_kernel_ops;
const struct kernel_ops *kernel_ops = &unit_kernel_ops;

bool route_and_eroute(struct connection *c USED_BY_KLIPS
                      , struct spd_route *sr USED_BY_KLIPS
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

