void add_if_to_list(int  family,
                    char *ifaddr,
                    unsigned int  port,
                    bool ike_float,
                    char *devname)
{
  static unsigned int virtnum = 0;
  char buf1[256];

  struct iface_dev *dev = alloc_thing(*dev, "device name");
  struct iface_port *ifport = alloc_thing(*ifport, "device port");
  snprintf(buf1, sizeof(buf1), "ipsec%u", ++virtnum);
  dev->id_vname = clone_str(buf1, "vname");
  dev->id_rname = clone_str(devname, "rname");

  ifport->ip_dev = dev;
  ifport->port   = port;
  ifport->socktypename = (family == AF_INET6 ? "AF_INET" : "AF_INET6");

  ttoaddr_num(ifaddr, 0, family, &ifport->ip_addr);
  ifport->fd = -1;
  ifport->ike_float = ike_float;
  ifport->change = IFN_KEEP;

  ifport->next = interfaces;
  interfaces = ifport;
}

void init_gatefun_interface(void)
{
  add_if_to_list(AF_INET, "93.184.216.34", 500, FALSE, "eth0");
  add_if_to_list(AF_INET6, "2606:2800:220:1:248:1893:25c8:1946", 500, FALSE, "eth0");

  add_if_to_list(AF_INET, "127.0.0.1", 500, FALSE, "lo");
  add_if_to_list(AF_INET6, "::1", 500, FALSE, "lo");

  add_if_to_list(AF_INET, "132.213.238.7", 500, FALSE, "eth1");
  add_if_to_list(AF_INET6, "fd68:c9f9:4157::1234", 500, FALSE, "eth3");

}



