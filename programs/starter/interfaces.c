/* FreeS/WAN interfaces management (interfaces.c)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * RCSID $Id: interfaces.c,v 1.4 2004/04/10 16:37:37 ken Exp $
 */

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <openswan.h>

#include "openswan/ipsec_tunnel.h"

#include "interfaces.h"
#include "exec.h"
#include "files.h"
#include "starterlog.h"

#define MIN(a,b) ( ((a)>(b)) ? (b) : (a) )

#define N_IPSEC_IF      4

struct st_ipsec_if {
	char name[IFNAMSIZ+1];
	char phys[IFNAMSIZ+1];
	int up;
};
static struct st_ipsec_if _ipsec_if[N_IPSEC_IF];

static char *_find_physical_iface(int sock, char *iface)
{
	static char _if[IFNAMSIZ+1];
	char *b;
	struct ifreq req;
	FILE *f;
	char line[256];

	strncpy(req.ifr_name, iface, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFFLAGS, &req)==0) {
		if (req.ifr_flags & IFF_UP) {
			strncpy(_if, iface, IFNAMSIZ);
			return _if;
		}
	}
	else {
		/**
		 * If there is a file named /var/run/dynip/<iface>, look if we
		 * can get interface name from there (IP_PHYS)
		 */
		b = (char *)malloc(strlen(DYNIP_DIR)+strlen(iface)+10);
		if (b) {
			sprintf(b, "%s/%s", DYNIP_DIR, iface);
			f = fopen(b, "r");
			free(b);
			if (f) {
				memset(_if, 0, sizeof(_if));
				memset(line, 0, sizeof(line));
				while (fgets(line, sizeof(line)-1, f)!=0) {
					if ((strncmp(line,"IP_PHYS=\"", 9)==0) &&
						(line[strlen(line)-2]=='"') &&
						(line[strlen(line)-1]=='\n')) {
						strncpy(_if, line+9, MIN(strlen(line)-11,IFNAMSIZ));
						break;
					}
					else if ((strncmp(line,"IP_PHYS=", 8)==0) &&
						(line[8]!='"') &&
						(line[strlen(line)-1]=='\n')) {
						strncpy(_if, line+8, MIN(strlen(line)-9,IFNAMSIZ));
						break;
					}
				}
				fclose(f);
				if (*_if) {
					strncpy(req.ifr_name, _if, IFNAMSIZ);
					if (ioctl(sock, SIOCGIFFLAGS, &req)==0) {
						if (req.ifr_flags & IFF_UP) {
							return _if;
						}
					}
				}
			}
		}
	}
	return NULL;
}

int starter_iface_find(char *iface, int af, ip_address *dst, ip_address *nh)
{
	char *phys;
	struct ifreq req;
	struct sockaddr_in *sa = (struct sockaddr_in *)(&req.ifr_addr);
	int sock;

	if (!iface) return -1;

	sock = socket(af, SOCK_DGRAM, 0);
	if (sock < 0) return -1;

	phys = _find_physical_iface(sock, iface);
	if (!phys) goto failed;

	strncpy(req.ifr_name, phys, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFFLAGS, &req)!=0) goto failed;
	if (!(req.ifr_flags & IFF_UP)) goto failed;

	if ((req.ifr_flags & IFF_POINTOPOINT) && (nh) &&
		(ioctl(sock, SIOCGIFDSTADDR, &req)==0)) {
		if (sa->sin_family == af) {
			initaddr((const void *)&sa->sin_addr,
				sizeof(struct in_addr), af, nh);
		}
	}
	if ((dst) && (ioctl(sock, SIOCGIFADDR, &req)==0)) {
		if (sa->sin_family == af) {
			initaddr((const void *)&sa->sin_addr,
				sizeof(struct in_addr), af, dst);
		}
	}
	close(sock);
	return 0;

failed:
	close(sock);
	return -1;
}

static int valid_str(char *str, unsigned int *pn, char **pphys)
{
	if (!str) return 0;
	if (strlen(str)<8) return 0;
	if ((str[0]!='i') || (str[1]!='p') || (str[2]!='s') || (str[3]!='e') ||
		(str[4]!='c') || (str[5]<'0') || (str[5]>'9') || (str[6]!='='))
		return 0;
	if (pn) *pn = str[5] - '0';
	if (pphys) *pphys = &(str[7]);
	return 1;
}

static int _iface_up (int sock,  struct st_ipsec_if *iface, char *phys,
	unsigned int mtu, int nat_t)
{
	struct ifreq req;
	struct ipsectunnelconf *shc=(struct ipsectunnelconf *)&req.ifr_data;
	short phys_flags;
	int ret = 0;

	strncpy(req.ifr_name, phys, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFFLAGS, &req)!=0) {
		return ret;
	}
	phys_flags = req.ifr_flags;

	strncpy(req.ifr_name, iface->name, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFFLAGS, &req)!=0) {
		return ret;
	}

	if ((!(req.ifr_flags & IFF_UP)) || (!iface->up)) {
		starter_log(LOG_LEVEL_INFO, "attaching interface %s to %s", iface->name,
			phys);
		ret = 1;
	}

	if ((*iface->phys) && (strcmp(iface->phys, phys)!=0)) {
		/* tncfg --detach if phys has changed */
		strncpy(req.ifr_name, iface->name, IFNAMSIZ);
		ioctl(sock, IPSEC_DEL_DEV, &req);
		ret = 1;
	}

	/* tncfg --attach */
	strncpy(req.ifr_name, iface->name, IFNAMSIZ);
	strncpy(shc->cf_name, phys, sizeof(shc->cf_name));
	ioctl(sock, IPSEC_SET_DEV, &req);

	/* set ipsec addr = phys addr */
	strncpy(req.ifr_name, phys, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFADDR, &req)==0) {
		strncpy(req.ifr_name, iface->name, IFNAMSIZ);
		ioctl(sock, SIOCSIFADDR, &req);
	}

	/* set ipsec mask = phys mask */
	strncpy(req.ifr_name, phys, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFNETMASK, &req)==0) {
		strncpy(req.ifr_name, iface->name, IFNAMSIZ);
		ioctl(sock, SIOCSIFNETMASK, &req);
	}

	/* set other flags & addr */
	strncpy(req.ifr_name, iface->name, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFFLAGS, &req)==0) {
		if (phys_flags & IFF_POINTOPOINT) {
			req.ifr_flags |= IFF_POINTOPOINT;
			req.ifr_flags &= ~IFF_BROADCAST;
			ioctl(sock, SIOCSIFFLAGS, &req);
			strncpy(req.ifr_name, phys, IFNAMSIZ);
			if (ioctl(sock, SIOCGIFDSTADDR, &req)==0) {
				strncpy(req.ifr_name, iface->name, IFNAMSIZ);
				ioctl(sock, SIOCSIFDSTADDR, &req);
			}
		}
		else if (phys_flags & IFF_BROADCAST) {
			req.ifr_flags &= ~IFF_POINTOPOINT;
			req.ifr_flags |= IFF_BROADCAST;
			ioctl(sock, SIOCSIFFLAGS, &req);
			strncpy(req.ifr_name, phys, IFNAMSIZ);
			if (ioctl(sock, SIOCGIFBRDADDR, &req)==0) {
				strncpy(req.ifr_name, iface->name, IFNAMSIZ);
				ioctl(sock, SIOCSIFBRDADDR, &req);
			}
		}
		else {
			req.ifr_flags &= ~IFF_POINTOPOINT;
			req.ifr_flags &= ~IFF_BROADCAST;
			ioctl(sock, SIOCSIFFLAGS, &req);
		}
	}

	/*
	 * guess MTU = phys interface MTU - ESP Overhead
	 *
	 * ESP overhead : 10+16+7+2+12=57 -> 60 by security
	 * NAT-T overhead : 20
	 */
	if (mtu==0) {
		strncpy(req.ifr_name, phys, IFNAMSIZ);
		ioctl(sock, SIOCGIFMTU, &req);
		mtu = req.ifr_mtu - 60;
		if (nat_t) mtu -= 20;
	}
	/* set MTU */
	if (mtu) {
		strncpy(req.ifr_name, iface->name, IFNAMSIZ);
		req.ifr_mtu = mtu;
		ioctl(sock, SIOCSIFMTU, &req);
	}

	/* ipsec interface UP */
	strncpy(req.ifr_name, iface->name, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFFLAGS, &req)==0) {
		req.ifr_flags |= IFF_UP;
		ioctl(sock, SIOCSIFFLAGS, &req);
	}

	iface->up = 1;
	strncpy(iface->phys, phys, IFNAMSIZ);
	return ret;
}

static int _iface_down (int sock, struct st_ipsec_if *iface)
{
	struct ifreq req;
	int ret = 0;

	iface->up = 0;

	strncpy(req.ifr_name, iface->name, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFFLAGS, &req)!=0) {
		return ret;
	}

	if (req.ifr_flags & IFF_UP) {
		starter_log(LOG_LEVEL_INFO, "shutting down interface %s/%s",
			iface->name, iface->phys);
		req.ifr_flags &= ~IFF_UP;
		ioctl(sock, SIOCSIFFLAGS, &req);
		ret = 1;
	}

	/* unset addr */
	memset(&req.ifr_addr, 0, sizeof(req.ifr_addr));
	req.ifr_addr.sa_family = AF_INET;
	ioctl(sock, SIOCSIFADDR, &req);

	/* tncfg --detach */
	ioctl(sock, IPSEC_DEL_DEV, &req);

	memset(iface->phys, 0, sizeof(iface->phys));

	return ret;
}

void starter_ifaces_init (void)
{
	int i;

	memset(_ipsec_if, 0, sizeof(_ipsec_if));
	for (i=0; i<N_IPSEC_IF; i++) {
		snprintf(_ipsec_if[i].name, IFNAMSIZ, "ipsec%d", i);
	}
}

void starter_ifaces_clear (void)
{
	int sock;
	unsigned int i;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) return;

	for (i=0; i<N_IPSEC_IF; i++) {
		_iface_down (sock, &(_ipsec_if[i]));
	}
}

int starter_ifaces_load (char **ifaces, unsigned int omtu, int nat_t)
{
	char *tmp_phys, *phys;
	int n;
	char **i;
	int sock;
	int j, found;
	int ret = 0;

	starter_log(LOG_LEVEL_DEBUG, "starter_ifaces_load()");

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) return -1;

	for (j=0; j<N_IPSEC_IF; j++) {
		found = 0;
		for (i=ifaces; i && *i; i++) {
			if ((valid_str(*i, &n, &tmp_phys)) && (tmp_phys) &&
			(n>=0) && (n<N_IPSEC_IF)) {
				if (n==j) {
					if (found) {
						starter_log(LOG_LEVEL_ERR,
							"ignoring duplicate entry for interface ipsec%d",
							j);
					}
					else {
						found++;
						phys = _find_physical_iface(sock, tmp_phys);
						if (phys) {
							ret += _iface_up (sock, &(_ipsec_if[n]), phys,
								omtu, nat_t);
						}
						else {
							ret += _iface_down (sock, &(_ipsec_if[n]));
						}
					}
				}
			}
			else if (j==0) {
				/**
				 * Only log in the first loop
				 */
				starter_log(LOG_LEVEL_ERR, "ignoring invalid interface '%s'",
					*i);
			}
		}
		if (!found)
			ret += _iface_down (sock, &(_ipsec_if[j]));
	}

	close(sock);
	return ret; /* = number of changes - 'whack --listen' if > 0 */
}

