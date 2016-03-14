struct iface_dev  bob_ifd1 = {
	.id_count = 1,
	.id_vname = "ipsec0",
	.id_rname = "eth0"
};

struct iface_port bob_if1 = {
	.ip_dev = &bob_ifd1,
	.port   = 500,
        .socktypename = "AF_INET",
	.ip_addr.u.v4.sin_family = AF_INET,
	.fd     = -1,
	.next   = NULL,
	.ike_float = 0,
	.change    = IFN_KEEP
};

void init_bob_interface(bool doipv6)
{
  inet_pton(AF_INET, "10.2.0.10", &bob_if1.ip_addr.u.v4.sin_addr);
  init_iface_port(&bob_if1);
  bob_if1.next = interfaces;
  interfaces = &bob_if1;
}
