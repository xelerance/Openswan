#ifndef __seam_host_dave_c__
#define __seam_host_dave_c__
struct iface_dev  dave_ifd1 = {
	.id_count = 1,
	.id_vname = "ipsec0",
	.id_rname = "eth0"
};

struct iface_port dave_if1 = {
	.ip_dev = &dave_ifd1,
	.port   = 500,
        .socktypename = "AF_INET",
	.ip_addr.u.v4.sin_family = AF_INET,
	.fd     = -1,
	.next   = NULL,
	.ike_float = 0,
	.change    = IFN_KEEP
};

void init_dave_interface(void)
{
  init_iface_port(&dave_if1);
  dave_if1.next = interfaces;
  dave_if1.ip_addr.u.v4.sin_addr.s_addr=htonl(0x5db8d823); /* 93.184.216.35 example.com */
  interfaces = &dave_if1;
}
#endif
