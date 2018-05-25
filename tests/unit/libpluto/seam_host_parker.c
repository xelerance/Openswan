#ifndef __seam_host_parker_c__
#define __seam_host_parker_c__
#include <arpa/inet.h>
struct iface_dev  parker_ifd1 = {
	.id_count = 1,
	.id_vname = "ipsec0",
	.id_rname = "eth0"
};

struct iface_port parker_if1 = {
	.ip_dev = &parker_ifd1,
	.port   = 500,
        .socktypename = "AF_INET",
	.ip_addr.u.v4.sin_family = AF_INET,
	.ip_addr.u.v4.sin_addr.s_addr = 0xc0a80101, /* 192.168.1.1 -- see htonl() below */
	.fd     = -1,
	.next   = NULL,
	.ike_float = 0,
	.change    = IFN_KEEP
};

struct iface_port parker_if1b = {
	.ip_dev = &parker_ifd1,
	.port   = 4500,
	.ip_addr.u.v4.sin_family = AF_INET,
	.ip_addr.u.v4.sin_addr.s_addr = 0xc0a80101, /* 192.168.1.1 -- see htonl() below */
	.fd     = -1,
	.next   = NULL,
	.ike_float = 1,
	.change    = IFN_KEEP
};

struct iface_port parker_if2 = {
	.ip_dev = &parker_ifd1,
	.port   = 500,
	.ip_addr.u.v6.sin6_family = AF_INET6,
        /* filled in below */
	.fd     = -1,
	.next   = NULL,
	.ike_float = 0,
	.change    = IFN_KEEP
};

void init_parker_interface(bool doipv6)
{
  if(doipv6) {
    inet_pton(AF_INET6, "2606:2800:220:1:248:1893:25c8:1946", &parker_if2.ip_addr.u.v6.sin6_addr);
    init_iface_port(&parker_if2);

    parker_if2.next = interfaces;
    interfaces = &parker_if2;
  }

  parker_if1b.ip_addr.u.v4.sin_addr.s_addr = htonl(parker_if1b.ip_addr.u.v4.sin_addr.s_addr);
  init_iface_port(&parker_if1b);
  parker_if1b.next = interfaces;
  interfaces = &parker_if1b;

  parker_if1.ip_addr.u.v4.sin_addr.s_addr = htonl(parker_if1.ip_addr.u.v4.sin_addr.s_addr);
  init_iface_port(&parker_if1);
  parker_if1.next = interfaces;
  interfaces = &parker_if1;
}
#endif
