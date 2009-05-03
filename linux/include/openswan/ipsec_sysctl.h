#ifndef OPENSWAN_SYSCTL_H
#define OPENSWAN_SYSCTL_H

extern int debug_ah;
extern int debug_esp;
extern int debug_xform;
extern int debug_eroute;
extern int debug_spi;
extern int debug_netlink;
extern int debug_radij;
extern int debug_rcv;
extern int debug_tunnel;
extern int debug_xmit;
extern int debug_mast;

extern int sysctl_ip_default_ttl;
extern int sysctl_ipsec_inbound_policy_check;
extern int sysctl_ipsec_debug_ipcomp;
extern int sysctl_ipsec_debug_verbose;
#endif
