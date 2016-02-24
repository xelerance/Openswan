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

void init_parker_interface(void)
{
  parker_if1.ip_addr.u.v4.sin_addr.s_addr = htonl(parker_if1.ip_addr.u.v4.sin_addr.s_addr);
  parker_if1.next = interfaces;
  interfaces = &parker_if1;
}
