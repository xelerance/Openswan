struct iface_dev  moon_ifd1 = {
	.id_count = 1,
	.id_vname = "ipsec0",
	.id_rname = "eth0"
};

struct iface_port moon_if1 = {
	.ip_dev = &moon_ifd1,
	.port   = 500,
        .socktypename = "AF_INET",
	.ip_addr.u.v4.sin_family = AF_INET,
	.fd     = -1,
	.next   = NULL,
	.ike_float = 0,
	.change    = IFN_KEEP
};

void init_moon_interface(bool doipv6 UNUSED)
{
  init_iface_port(&moon_if1);
  moon_if1.next = interfaces;
  inet_pton(AF_INET, "192.168.0.1", &moon_if1.ip_addr.u.v4.sin_addr);
  interfaces = &moon_if1;
}
