struct ifmake {
  int  family;
  char *ifaddr;
  unsigned int  port;
  bool ike_float;
  char *devname;
};

void add_if_to_list(struct ifmake *ifm)
{
  static unsigned int virtnum = 0;
  char buf1[256];

  struct iface_dev *dev = alloc_thing(*dev, "device name");
  struct iface_port *ifport = alloc_thing(*ifport, "device port");
  snprintf(buf1, sizeof(buf1), "ipsec%u", ++virtnum);
  dev->id_vname = clone_str(buf1, "vname");
  dev->id_rname = clone_str(ifm->devname, "rname");

  ifport->ip_dev = dev;
  ifport->port   = ifm->port;
  ifport->socktypename = (ifm->family == AF_INET6 ? "AF_INET" : "AF_INET6");

  ttoaddr_num(ifm->ifaddr, 0, ifm->family, &ifport->ip_addr);
  addrtot(&ifport->ip_addr, 0, ifport->addrname, sizeof(ifport->addrname));
  ifport->fd = -1;
  ifport->ike_float = ifm->ike_float;
  ifport->change = IFN_KEEP;

  ifport->next = interfaces;
  interfaces = ifport;
}


struct ifmake if_01 = {AF_INET, "93.184.216.34", 500, FALSE, "eth0"};
struct ifmake if_02 = {AF_INET6, "2606:2800:220:1:248:1893:25c8:1946", 500, FALSE, "eth0"};
struct ifmake if_03 = {AF_INET, "127.0.0.1", 500, FALSE, "lo"};
struct ifmake if_04 = {AF_INET6, "::1", 500, FALSE, "lo"};
struct ifmake if_05 = {AF_INET, "132.213.238.7", 500, FALSE, "eth1"};
struct ifmake if_06 = {AF_INET6, "fd68:c9f9:4157::1234", 500, FALSE, "eth3"};

struct ifmake *ifaces[] = {&if_01, &if_02, &if_03, &if_04, &if_05, &if_06};
#define IFACES_COUNT 6

void init_gatefun_interface(void)
{
  add_if_to_list(&if_01);
  add_if_to_list(&if_02);
  add_if_to_list(&if_03);
  add_if_to_list(&if_04);
  add_if_to_list(&if_05);
  add_if_to_list(&if_06);
}



