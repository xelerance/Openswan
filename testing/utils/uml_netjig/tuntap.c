#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>

#include "nethub.h"
#include "port.h"

static void send_tap(int fd, void *packet, int len, void *unused)
{
  int n;

  n = write(fd, packet, len);
  if(n != len){
    if(errno != EAGAIN) perror("send_tap");
  }
}

int open_tap(struct netjig_state *ns,
	     struct nethub *nh,
	     char *dev)
{
  struct ifreq ifr;
  int fd, err;

  if((fd = open("/dev/net/tun", O_RDWR)) < 0){
    perror("Failed to open /dev/net/tun");
    return(-1);
  }
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name) - 1);
  if(ioctl(fd, TUNSETIFF, (void *) &ifr) < 0){
    perror("TUNSETIFF failed");
    close(fd);
    return(-1);
  }

  err = setup_sock_tap(ns, nh, fd, send_tap);
  if(err) return(err);

  add_fd(ns, fd);

  return(fd);
}

