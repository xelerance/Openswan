/* pfkey interface to the kernel's IPsec mechanism
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003 Herbert Xu.
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
 * RCSID $Id: kernel_pfkey.c,v 1.25 2005/08/24 22:50:50 mcr Exp $
 */

#ifdef KLIPS

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <openswan.h>
#include <pfkeyv2.h>
#include <pfkey.h>

#include "sysdep.h"
#include "constants.h"
#include "oswlog.h"

#include "defs.h"
#include "id.h"
#include "connections.h"
#include "state.h"
#include "kernel.h"
#include "kernel_pfkey.h"
#include "timer.h"
#include "log.h"
#include "whack.h"	/* for RC_LOG_SERIOUS */
#ifdef NAT_TRAVERSAL
#include "packet.h"  /* for pb_stream in nat_traversal.h */
#include "nat_traversal.h"
#endif

#include "alg_info.h"
#include "kernel_alg.h"

static int next_free_mast_device=-1;

/* for now, a kludge */
#define MAX_MAST 64
enum mast_stat {
    MAST_INUSE,    /* not available */
    MAST_AVAIL,    /* created, available */
    MAST_OPEN      /* not created */
};
enum mast_stat mastdevice[MAX_MAST];

/*
 * build list of available mast devices.
 */

static void
find_next_free_mast(void)
{
    int mastno;
    
    for(mastno=0; mastno<MAX_MAST; mastno++) {
	if(mastdevice[mastno]==MAST_AVAIL) {
	    next_free_mast_device=mastno;
	    break;
	}
    }
    if(next_free_mast_device==-1) {
	for(mastno=0; mastno<MAX_MAST; mastno++) {
	    if(mastdevice[mastno]==MAST_OPEN) {
		next_free_mast_device=mastno;
		break;
	    }
	}
    }
}

static void
recalculate_mast_device_list(struct raw_iface *rifaces)
{
    struct raw_iface *ifp;
    int mastno;

    /* mark them all as available */
    next_free_mast_device=-1;
    for(mastno=0; mastno<MAX_MAST; mastno++) {
	mastdevice[mastno]=MAST_OPEN;
    }
    
    for(ifp=rifaces; ifp!=NULL; ifp=ifp->next) {
	/* look for virtual (mast*) interface */
	if (strncmp(ifp->name, MASTDEVPREFIX, sizeof(MASTDEVPREFIX)-1))
	    continue;
	
	if(sscanf(ifp->name, "mast%d", &mastno)==1) {
	    openswan_log("found %s device already present", ifp->name);
	    mastdevice[mastno]=MAST_AVAIL;
	    if(!isunspecaddr(&ifp->addr)) {
		openswan_log("device %s already in use", ifp->name);
		/* mark it as existing, and in use */
		mastdevice[mastno]=MAST_INUSE;
	    }
	}
    }

    find_next_free_mast();
}

static int
allocate_mast_device(void)
{
    int next;
    if(next_free_mast_device == -1) {
	find_next_free_mast();
    }
	
    if(next_free_mast_device != -1) {
	next = next_free_mast_device;
	next_free_mast_device = -1;
	return next;
    }
    return -1;
}


static void
mast_process_raw_ifaces(struct raw_iface *rifaces)
{
    struct raw_iface *ifp;
    int mastno;

    recalculate_mast_device_list(rifaces);

    /* 
     * For each real interface...
     */
    for (ifp = rifaces; ifp != NULL; ifp = ifp->next)
    {
	/* ignore if virtual (ipsec*) interface */
	if (strncmp(ifp->name, IPSECDEVPREFIX, sizeof(IPSECDEVPREFIX)-1) == 0)
	    continue;

	/* ignore if virtual (mast*) interface */
	if (strncmp(ifp->name, MASTDEVPREFIX, sizeof(MASTDEVPREFIX)-1) == 0)
	    continue;

	/* ignore if loopback interface */
	if (strncmp(ifp->name, "lo", 2) == 0)
	    continue;

	/*
	 * see if this is a new thing: search old interfaces list.
	 */
	do {
	    struct iface_dev *id = NULL;
	    struct iface_port *q = interfaces;

	    while(q != NULL)
	    {
		/* search over if matching old entry found */
		if (streq(q->ip_dev->id_rname, ifp->name)
		    && sameaddr(&q->ip_addr, &ifp->addr))
		{
		    /* matches -- rejuvinate old entry */
		    q->change = IFN_KEEP;
#ifdef NAT_TRAVERSAL
		    /* look for other interfaces to keep (due to NAT-T) */
		    for (q = q->next ; q ; q = q->next) {
			if (streq(q->ip_dev->id_rname, ifp->name)
			    && sameaddr(&q->ip_addr, &ifp->addr)) {
			    q->change = IFN_KEEP;
			}
		    }
#endif
		    break;
		}
		
		/* try again */
		q = q->next;
	    } 

	    /* search is over if at end of list */
	    if (q == NULL)
	    {
		/* matches nothing -- create a new entry */
		int fd;
		
		q = alloc_thing(struct iface_port, "struct iface_port");
		id = alloc_thing(struct iface_dev, "struct iface_dev");
		
		LIST_INSERT_HEAD(&interface_dev, id, id_entry);
		
		q->ip_dev = id;
		id->id_rname = clone_str(ifp->name, "real device name");
		id->id_vname = clone_str("mastXXXXXXXX", "virtual device name");
		id->id_count++;
		
		q->ip_addr = ifp->addr;
		q->change = IFN_ADD;
		q->port = pluto_port;
		q->ike_float = FALSE;
		
		/*
		 * now, create a mastXXX interface to match, and then configure
		 * it with the same IP.
		 */
		mastno = allocate_mast_device();
		passert(mastno != -1);
		sprintf(q->ip_dev->id_vname, "mast%d", mastno);
		if(mastdevice[mastno]==MAST_OPEN) {
		    mastdevice[mastno]=MAST_INUSE;
		    pfkey_plumb_mast_device(mastno);
		}
		
		/* now configure an IP address on the mast number */
		{
		    char cmd[512];
		    
		    snprintf(cmd, sizeof(cmd)
			     , "ifconfig %s inet %s netmask 255.255.255.255"
			     , q->ip_dev->id_vname
			     , ip_str(&q->ip_addr));
		    
		    if(!invoke_command("plumb","", cmd)) {
			break;
		    }
		}
		
		fd = create_socket(ifp, q->ip_dev->id_vname, pluto_port);
		q->fd = fd;
		
		if (fd < 0) 
		    break;
		
#ifdef NAT_TRAVERSAL
		if (nat_traversal_support_non_ike && addrtypeof(&ifp->addr) == AF_INET)
		{
		    nat_traversal_espinudp_socket(fd, "IPv4", ESPINUDP_WITH_NON_IKE);
		}
#endif
		
		/* done with primary interface */
		q->next = interfaces;
		interfaces = q;
		
		openswan_log("adding interface %s/%s %s:%d (fd=%d)"
			     , q->ip_dev->id_vname
			     , q->ip_dev->id_rname
			     , ip_str(&q->ip_addr)
			     , q->port, q->fd);
		
		
#ifdef NAT_TRAVERSAL
		/*
		 * right now, we do not support NAT-T on IPv6, because
		 * the kernel did not support it, and gave an error
		 * it one tried to turn it on.
		 */
		if (nat_traversal_support_port_floating
		    && addrtypeof(&ifp->addr) == AF_INET)
		{
		    fd = create_socket(ifp, q->ip_dev->id_vname, NAT_T_IKE_FLOAT_PORT);
		    if (fd < 0) {
			openswan_log("failed to create socket for NAT-T: %s"
				     , strerror(errno));
			/* go to next if in list */
			break;
		    }
		    nat_traversal_espinudp_socket(fd, "IPv4"
						  , ESPINUDP_WITH_NON_ESP);
		    q = alloc_thing(struct iface_port, "struct iface_port");
		    q->ip_dev = id;
		    id->id_count++;
		    
		    q->ip_addr = ifp->addr;
		    setportof(htons(NAT_T_IKE_FLOAT_PORT), &q->ip_addr);
		    q->port = NAT_T_IKE_FLOAT_PORT;
		    q->fd = fd;
		    q->change = IFN_ADD;
		    q->ike_float = TRUE;
		    
		    q->next = interfaces;
		    interfaces = q;
		    openswan_log("adding interface %s/%s %s:%d (fd=%d)"
				 , q->ip_dev->id_vname, q->ip_dev->id_rname
				 , ip_str(&q->ip_addr)
				 , q->port, q->fd);
		}
#endif
	    }
	} while(0);
    }

    /* delete the raw interfaces list */
    while (rifaces != NULL)
    {
	struct raw_iface *t = rifaces;

	rifaces = t->next;
	pfree(t);
    }
}

const struct kernel_ops mast_kernel_ops = {
    type: USE_MASTKLIPS,
    async_fdp: &pfkeyfd,
    replay_window: 64,
    
    pfkey_register: klips_pfkey_register,
    pfkey_register_response: klips_pfkey_register_response,
    process_queue: pfkey_dequeue,
    process_msg: pfkey_event,
    raw_eroute: pfkey_raw_eroute,
    shunt_eroute: pfkey_shunt_eroute,
    sag_eroute: pfkey_sag_eroute,
    add_sa: pfkey_add_sa,
    grp_sa: pfkey_grp_sa,
    del_sa: pfkey_del_sa,
    get_spi: NULL,
    eroute_idle: pfkey_was_eroute_idle,
    inbound_eroute: FALSE,
    policy_lifetime: FALSE,
    init: init_pfkey,
    docommand: do_command_linux,
    set_debug: pfkey_set_debug,
    remove_orphaned_holds: pfkey_remove_orphaned_holds,
    process_ifaces: mast_process_raw_ifaces,
    kern_name: "mast"
};
#endif /* KLIPS */
