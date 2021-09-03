/* interfaces management (interfaces.c)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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
 */

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <openswan.h>

#include "sysdep.h"
#include "socketwrapper.h"
#include "openswan/ipsec_tunnel.h"

#include "ipsecconf/interfaces.h"
#include "ipsecconf/exec.h"
#include "ipsecconf/files.h"
#include "ipsecconf/starterlog.h"

#define MIN(a,b) ( ((a)>(b)) ? (b) : (a) )

#define N_IPSEC_IF      4

struct st_ipsec_if {
	char name[IFNAMSIZ];
	char phys[IFNAMSIZ];
	int up;
};
static struct st_ipsec_if _ipsec_if[N_IPSEC_IF];

extern char *starter_find_physical_iface(int sock, char *iface);


static int valid_str(const char * const str, unsigned int * const pn, char ** const pphys)
{
	char *pequal = NULL;
	char *pnum_start = NULL;
	char numeric[5] = {'\0'};
	char ch = '\0';
	unsigned int i = 0;
	if (!str) return 0;
	if (strlen(str)<8) return 0;

	/* Check if the string has an = sign */
	pequal = strchr(str,'=');
	if (!pequal) return 0;

	/* Where does the device number start ? */
	pnum_start = strstr(str,"ipsec");
	if (!pnum_start) {
		pnum_start = strstr(str,"mast");
		if (!pnum_start) return 0;
		else pnum_start += (sizeof("mast") - 1);
	}
	else pnum_start += (sizeof("ipsec") - 1);

	/* Is there a device number ? */
	if (pequal == pnum_start) return 0;

	/* Is there enough room to store the device number ? */
	if ((pequal - pnum_start) >= sizeof(numeric)) return 0;

	/* Copy only digit characters */
	while ( '=' != (ch = pnum_start[i]) ) {
		if (ch < '0' || ch > '9') return 0;
		numeric[i++] = ch;
	}

	if (pn) *pn = atoi(numeric);
	if (pphys) *pphys = pequal + 1;
	return 1;
}

static int _iface_up (int sock,  struct st_ipsec_if *iface, char *phys,
	unsigned int mtu, int nat_t)
{
	struct ifreq req;
	struct ipsectunnelconf *shc=(struct ipsectunnelconf *)&req.ifr_data;
	short phys_flags;
	int ret = 0;

	strncpy(req.ifr_name, phys, IFNAMSIZ-1);
	if (ioctl(sock, SIOCGIFFLAGS, &req)!=0) {
		return ret;
	}
	phys_flags = req.ifr_flags;

	strncpy(req.ifr_name, iface->name, IFNAMSIZ-1);
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
		strncpy(req.ifr_name, iface->name, IFNAMSIZ-1);
		ioctl(sock, IPSEC_DEL_DEV, &req);
		ret = 1;
	}

	/* tncfg --attach */
	strncpy(req.ifr_name, iface->name, IFNAMSIZ-1);
	strncpy(shc->cf_name, phys, sizeof(shc->cf_name));
	ioctl(sock, IPSEC_SET_DEV, &req);

	/* set ipsec addr = phys addr */
	strncpy(req.ifr_name, phys, IFNAMSIZ-1);
	if (ioctl(sock, SIOCGIFADDR, &req)==0) {
		strncpy(req.ifr_name, iface->name, IFNAMSIZ-1);
		ioctl(sock, SIOCSIFADDR, &req);
	}

	/* set ipsec mask = phys mask */
	strncpy(req.ifr_name, phys, IFNAMSIZ-1);
	if (ioctl(sock, SIOCGIFNETMASK, &req)==0) {
		strncpy(req.ifr_name, iface->name, IFNAMSIZ-1);
		ioctl(sock, SIOCSIFNETMASK, &req);
	}

	/* set other flags & addr */
	strncpy(req.ifr_name, iface->name, IFNAMSIZ-1);
	if (ioctl(sock, SIOCGIFFLAGS, &req)==0) {
		if (phys_flags & IFF_POINTOPOINT) {
			req.ifr_flags |= IFF_POINTOPOINT;
			req.ifr_flags &= ~IFF_BROADCAST;
			ioctl(sock, SIOCSIFFLAGS, &req);
			strncpy(req.ifr_name, phys, IFNAMSIZ-1);
			if (ioctl(sock, SIOCGIFDSTADDR, &req)==0) {
				strncpy(req.ifr_name, iface->name, IFNAMSIZ-1);
				ioctl(sock, SIOCSIFDSTADDR, &req);
			}
		}
		else if (phys_flags & IFF_BROADCAST) {
			req.ifr_flags &= ~IFF_POINTOPOINT;
			req.ifr_flags |= IFF_BROADCAST;
			ioctl(sock, SIOCSIFFLAGS, &req);
			strncpy(req.ifr_name, phys, IFNAMSIZ-1);
			if (ioctl(sock, SIOCGIFBRDADDR, &req)==0) {
				strncpy(req.ifr_name, iface->name, IFNAMSIZ-1);
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
		strncpy(req.ifr_name, phys, IFNAMSIZ-1);
		ioctl(sock, SIOCGIFMTU, &req);
		mtu = req.ifr_mtu - 60;
		if (nat_t) mtu -= 20;
	}
	/* set MTU */
	if (mtu) {
		strncpy(req.ifr_name, iface->name, IFNAMSIZ-1);
		req.ifr_mtu = mtu;
		ioctl(sock, SIOCSIFMTU, &req);
	}

	/* ipsec interface UP */
	strncpy(req.ifr_name, iface->name, IFNAMSIZ-1);
	if (ioctl(sock, SIOCGIFFLAGS, &req)==0) {
		req.ifr_flags |= IFF_UP;
		ioctl(sock, SIOCSIFFLAGS, &req);
	}

	iface->up = 1;
	strncpy(iface->phys, phys, IFNAMSIZ-1);
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
		snprintf(_ipsec_if[i].name, IFNAMSIZ-1, "ipsec%d", i);
	}
}

void starter_ifaces_clear (void)
{
	int sock;
	unsigned int i;

	sock = safe_socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) return;

	for (i=0; i<N_IPSEC_IF; i++) {
		_iface_down (sock, &(_ipsec_if[i]));
	}
	if(close(sock)){
		starter_log(LOG_LEVEL_ERR,"starter_ifaces_clear socket close() failed: %s", strerror(errno));
	}
}

int starter_ifaces_load (char **ifaces, unsigned int omtu, int nat_t)
{
	char *tmp_phys, *phys;
	unsigned int n;
	char **i;
	int sock;
	int j, found;
	int ret = 0;

	starter_log(LOG_LEVEL_DEBUG, "starter_ifaces_load()");

	sock = safe_socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) return -1;

	for (j=0; j<N_IPSEC_IF; j++) {
		found = 0;
		for (i=ifaces; i && *i; i++) {
			if ((valid_str(*i, &n, &tmp_phys)) && (tmp_phys)
			&& (n<N_IPSEC_IF)) {
				if (n==j) {
					if (found) {
						starter_log(LOG_LEVEL_ERR,
							"ignoring duplicate entry for interface ipsec%d",
							j);
					}
					else {
						found++;
						phys = starter_find_physical_iface(sock, tmp_phys);
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

