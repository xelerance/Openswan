struct iface_dev  jj_ifd1 = {
	.id_count = 1,
	.id_vname = "ipsec0",
	.id_rname = "eth0"
};

struct iface_port jj_if1 = {
	.ip_dev = &jj_ifd1,
	.port   = 500,
        .socktypename = "AF_INET",
	.ip_addr.u.v4.sin_family = AF_INET,
	.ip_addr.u.v4.sin_addr.s_addr = 0x84D5EE07,  /* 132.213.238.7 */
	.fd     = -1,
	.next   = NULL,
	.ike_float = 0,
	.change    = IFN_KEEP
};

void init_jamesjohnson_interface(void)
{
  inet_pton(AF_INET, "132.213.238.7", &jj_if1.ip_addr.u.v4.sin_addr);
  init_iface_port(&jj_if1);
  jj_if1.next = interfaces;
  interfaces = &jj_if1;
}
