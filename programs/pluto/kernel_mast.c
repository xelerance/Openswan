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
#include <openswan/pfkeyv2.h>
#include <openswan/pfkey.h>

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
int  useful_mastno=-1;

#ifndef DEFAULT_UPDOWN
# define DEFAULT_UPDOWN "ipsec _updown"
#endif

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

static int
recalculate_mast_device_list(struct raw_iface *rifaces)
{
    struct raw_iface *ifp;
    int mastno;
    int firstmastno=-1;

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
		if(firstmastno == -1) {
		    firstmastno = mastno;
		}
	    }
	}
    }

    find_next_free_mast();
    return firstmastno;
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

static int
init_useful_mast(ip_address addr, char *vname)
{
    int mastno;

    /*
     * now, create a mastXXX interface to match, and then configure
     * it with an IP address that leads out.
     */
    mastno = allocate_mast_device();
    passert(mastno != -1);
    sprintf(vname, "mast%d", mastno);
    if(mastdevice[mastno]==MAST_OPEN) {
	mastdevice[mastno]=MAST_INUSE;
	pfkey_plumb_mast_device(mastno);
    }
    
    /* now configure an IP address on the mast number */
    {
	char cmd[512];
	
	/* 1452 gives us enough space for IP + UDP + typical ESP */
	snprintf(cmd, sizeof(cmd)
		 , "ifconfig %s inet %s netmask 255.255.255.255 mtu 1452"
		 , vname
		 , ip_str(&addr));
	
	invoke_command("plumb","", cmd);
    }
    return mastno;
}


static void
mast_process_raw_ifaces(struct raw_iface *rifaces)
{
    struct raw_iface *ifp;
    struct iface_port *firstq=NULL;
    char useful_mast_name[256];
    bool found_mast=FALSE;

    strcpy(useful_mast_name, "useless");
    { int new_useful=recalculate_mast_device_list(rifaces);

	    if(new_useful != -1) {
		    useful_mastno=new_useful;
	    }
    }

    DBG_log("useful mast device %d\n", useful_mastno);
    if(useful_mastno >= 0) {
	sprintf(useful_mast_name, "mast%d", useful_mastno);
    }
	
    /* 
     * For each real interface...
     */
    for (ifp = rifaces; ifp != NULL; ifp = ifp->next)
    {
	/* ignore if virtual (ipsec*) interface */
	if (strncmp(ifp->name, IPSECDEVPREFIX, sizeof(IPSECDEVPREFIX)-1) == 0)
	    continue;

	/* ignore if virtual (mast*) interface */ 
	if (strncmp(ifp->name, MASTDEVPREFIX, sizeof(MASTDEVPREFIX)-1) == 0) {
		found_mast=TRUE;
		continue;
	}

	/* ignore if loopback interface */
	if (strncmp(ifp->name, "lo", 2) == 0)
	    continue;

	/*
	 * see if this is a new thing: search old interfaces list.
	 */
	do {
	    bool newone = TRUE;
	    struct iface_dev *id = NULL;
	    struct iface_port *q = interfaces;

	    while(q != NULL)
	    {
		/* search over if matching old entry found */
		if (streq(q->ip_dev->id_rname, ifp->name)
		    && sameaddr(&q->ip_addr, &ifp->addr))
		{
		    newone = FALSE;

		    /* matches -- rejuvinate old entry */
		    q->change = IFN_KEEP;
#ifdef NAT_TRAVERSAL
		    /* look for other interfaces to keep (due to NAT-T) */
		    for (q = q->next ; q ; q = q->next) {
			if (streq(q->ip_dev->id_rname, ifp->name)
			    && sameaddr(&q->ip_addr, &ifp->addr)) {
			    q->change = IFN_KEEP;
			    if(firstq == NULL) {
				firstq=q;
				if(useful_mastno == -1) {
				    useful_mastno=init_useful_mast(firstq->ip_addr, useful_mast_name);
				}
			    }
			}
		    }
#endif
		    break;
		}
		
		/* try again */
		q = q->next;
	    } 

	    /* search is over if at end of list */
	    if (newone) 
	    {
		/* matches nothing -- create a new entry */
		char *vname;
		int fd;
		
		if(useful_mastno == -1) {
		    useful_mastno=init_useful_mast(ifp->addr, useful_mast_name);
		}

		vname = clone_str(useful_mast_name
				  , "virtual device name");
		fd = create_socket(ifp, vname, pluto_port);
		
		if (fd < 0) 
		    break;
		
		q = alloc_thing(struct iface_port, "struct iface_port");
		id = alloc_thing(struct iface_dev, "struct iface_dev");
		memset(q, 0, sizeof(*q));
		memset(id,0, sizeof(*id));
		if(firstq == NULL) firstq=q;
		
		LIST_INSERT_HEAD(&interface_dev, id, id_entry);
		
		q->fd = fd;
		q->ip_dev = id;
		id->id_rname = clone_str(ifp->name, "real device name");
		id->id_vname = vname;
		id->id_count++;
		
		q->ip_addr = ifp->addr;
		q->change = IFN_ADD;
		q->port = pluto_port;
		q->ike_float = FALSE;
		
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

    /* make one up for later */
    if((!found_mast && firstq!=NULL) && useful_mastno==-1) {
	init_useful_mast(firstq->ip_addr, useful_mast_name);
    }
}

static bool
mast_do_command(struct connection *c, struct spd_route *sr
		, const char *verb, struct state *st)
{
    char cmd[2048];     /* arbitrary limit on shell command length */
    char common_shell_out_str[2048];
    const char *verb_suffix;
    IPsecSAref_t ref,refhim;

    /* figure out which verb suffix applies */
    {
        const char *hs, *cs;

        switch (addrtypeof(&sr->this.host_addr))
        {
            case AF_INET:
                hs = "-host";
                cs = "-client";
                break;
            case AF_INET6:
                hs = "-host-v6";
                cs = "-client-v6";
                break;
            default:
                loglog(RC_LOG_SERIOUS, "unknown address family");
                return FALSE;
        }
        verb_suffix = subnetisaddr(&sr->this.client, &sr->this.host_addr)
            ? hs : cs;
    }

    if(fmt_common_shell_out(common_shell_out_str, sizeof(common_shell_out_str), c, sr, st)==-1) {
	loglog(RC_LOG_SERIOUS, "%s%s command too long!", verb, verb_suffix);
	return FALSE;
    }

    ref = refhim = IPSEC_SAREF_NULL;
    if(st) {
	ref   = st->st_ref;
	refhim= st->st_refhim;
	DBG(DBG_KLIPS, DBG_log("Using saref=%u/%u for verb=%s\n", ref, refhim, verb));
    }

    if (-1 == snprintf(cmd, sizeof(cmd)
		       , "2>&1 "   /* capture stderr along with stdout */
		       "PLUTO_MY_REF=%u "
		       "PLUTO_PEER_REF=%u "
		       "PLUTO_VERB='%s%s' "
		       "%s"        /* other stuff   */
		       "%s"        /* actual script */
		       , ref
		       , refhim
		       , verb, verb_suffix
		       , common_shell_out_str
		       , sr->this.updown == NULL? DEFAULT_UPDOWN : sr->this.updown))
    {
	loglog(RC_LOG_SERIOUS, "%s%s command too long!", verb, verb_suffix);
	return FALSE;
    }

    return invoke_command(verb, verb_suffix, cmd);
}

static bool
mast_raw_eroute(const ip_address *this_host UNUSED
		, const ip_subnet *this_client UNUSED
		, const ip_address *that_host UNUSED
		, const ip_subnet *that_client UNUSED
		, ipsec_spi_t spi UNUSED
		, unsigned int proto UNUSED
		, unsigned int transport_proto UNUSED
		, unsigned int satype UNUSED
		, const struct pfkey_proto_info *proto_info UNUSED
		, time_t use_lifetime UNUSED
		, enum pluto_sadb_operations op UNUSED
		, const char *text_said UNUSED)
{
	
	/* actually, we did all the work with iptables in _updown */
	return TRUE;
}

/* Add/replace/delete a shunt eroute.
 * Such an eroute determines the fate of packets without the use
 * of any SAs.  These are defaults, in effect.
 * If a negotiation has not been attempted, use %trap.
 * If negotiation has failed, the choice between %trap/%pass/%drop/%reject
 * is specified in the policy of connection c.
 */
static bool
mast_shunt_eroute(struct connection *c UNUSED
		   , struct spd_route *sr UNUSED
		   , enum routing_t rt_kind UNUSED
		   , enum pluto_sadb_operations op UNUSED
		  , const char *opname UNUSED)
{
    DBG_log("mast_shunt_eroute called");
    return TRUE;
}

/* install or remove eroute for SA Group */
static bool
mast_sag_eroute(struct state *st, struct spd_route *sr
		, enum pluto_sadb_operations op, const char *opname UNUSED)
{
    switch(op)
    {
    case ERO_ADD:
	return mast_do_command(st->st_connection, sr, "spdadd", st);
	
    case ERO_DELETE:
	return mast_do_command(st->st_connection, sr, "spddel", st);

    case ERO_REPLACE:
	(void)mast_do_command(st->st_connection, sr, "spddel", st);
	return mast_do_command(st->st_connection, sr, "spdadd", st);
	
    case ERO_ADD_INBOUND:
    case ERO_REPLACE_INBOUND:
    case ERO_DEL_INBOUND:
	return TRUE;
    }
    return FALSE;
}

const struct kernel_ops mast_kernel_ops = {
    type: USE_MASTKLIPS,
    async_fdp: &pfkeyfd,
    replay_window: 64,
    
    pfkey_register: klips_pfkey_register,
    pfkey_register_response: klips_pfkey_register_response,
    process_queue: pfkey_dequeue,
    process_msg: pfkey_event,
    raw_eroute: mast_raw_eroute,
    shunt_eroute: mast_shunt_eroute,
    sag_eroute: mast_sag_eroute,
    add_sa: pfkey_add_sa,
    grp_sa: pfkey_grp_sa,
    del_sa: pfkey_del_sa,
    get_sa: NULL,
    get_spi: NULL,
    eroute_idle: pfkey_was_eroute_idle,
    inbound_eroute: FALSE,
    policy_lifetime: FALSE,
    init: init_pfkey,
    exceptsocket: NULL,
    docommand: mast_do_command,
    set_debug: pfkey_set_debug,
    remove_orphaned_holds: pfkey_remove_orphaned_holds,
    process_ifaces: mast_process_raw_ifaces,
    kern_name: "mast",
    .overlap_supported = TRUE
};
#endif /* KLIPS */
