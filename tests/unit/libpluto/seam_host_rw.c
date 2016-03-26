struct iface_dev  rw_ifd1 = {
	.id_count = 1,
	.id_vname = "ipsec0",
	.id_rname = "eth0"
};

struct iface_port rw_if1 = {
	.ip_dev = &rw_ifd1,
	.port   = 500,
        .socktypename = "AF_INET",
	.ip_addr.u.v4.sin_family = AF_INET,
	.fd     = -1,
	.next   = NULL,
	.ike_float = 0,
	.change    = IFN_KEEP
};

void init_rw_interface(void)
{
  rw_if1.ip_addr.u.v4.sin_addr.s_addr=htonl(0x5db8d822); /* 93.184.216.34 example.com */
  init_iface_port(&rw_if1);

  rw_if1.next = interfaces;
  interfaces = &rw_if1;
}
