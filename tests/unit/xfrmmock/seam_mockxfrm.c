#define NETKEY_SUPPORT
#include "linux26/xfrm.h"
#include "linux26/rtnetlink.h"
#include "kernel.h"
#include "kernel_forces.h"
#include "kernel_netlink.h"

int netlink_bcast_fd = NULL_FD;
int useful_mastno;
char *pluto_listen = NULL;
struct iface_list interface_dev;
int   create_socket(struct raw_iface *ifp, const char *v_name, int port) {}
int   nat_traversal_espinudp_socket (int sk, const char *fam, u_int32_t type) {}

void init_netlink(void) {}

ipsec_spi_t spis[4]={ 0x12345678,
		      0x34567812,
		      0x56781234,
		      0x78123456};
static int spinext=0;
ipsec_spi_t mock_get_spi(const ip_address *src
                         , const ip_address *dst
                         , int proto
                         , bool tunnel_mode
                         , unsigned reqid
                         , ipsec_spi_t min
                         , ipsec_spi_t max
                         , const char *text_said)
{
	if(spinext == 4) spinext=0;
        return htonl(spis[spinext++]);
}

void scan_proc_shunts(void) {}

bool
unit_do_command(struct connection *c, const struct spd_route *sr
                  , const char *verb, const char *verb_suffix
                  , struct state *st)
{
  DBG_log("executing %s", verb);
  return TRUE;
}

bool netlink_get(void) { return FALSE; }
void netlink_register_proto(unsigned satype, const char *satypename) {}

#include <errno.h>
#include "hexdump.c"

bool send_netlink_msg(struct nlmsghdr *hdr, struct nlmsghdr *rbuf, size_t rbuf_len
                      , const char *description, const char *text_said)
{
  size_t len = hdr->nlmsg_len;

  fprintf(stderr, "writing netlink for %s\n", text_said);
  hexdump(stderr, (char *)hdr, 0, len);
  errno = 0;
  return TRUE;
}

bool netlink_policy(struct nlmsghdr *hdr, bool enoent_ok, const char *text_said)
{
  size_t len = hdr->nlmsg_len;

  fprintf(stderr, "writing netlink policy for %s\n", text_said);
  hexdump(stderr, (char *)hdr, 0, len);
  errno = 0;
  return TRUE;
}


/* empty structure */
struct kernel_ops noklips_kernel_ops;
struct kernel_ops mast_kernel_ops;
struct kernel_ops klips_kernel_ops;
struct kernel_ops unit_kernel_ops = {
    kern_name: "netkeyunit",
    type: USE_NETKEY,
    inbound_eroute:  TRUE,
    policy_lifetime: TRUE,
    async_fdp: NULL,
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
    get_spi: mock_get_spi,
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


