/* netlink interface to the kernel's (XFRM/NETKEY) IPsec mechanism
 *
 * Copyright (C) 2003-2008 Herbert Xu
 * Copyright (C) 2006-2019 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2006 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2007-2019 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2007 Ilia Sotnikov
 * Copyright (C) 2009 Carsten Schlote <c.schlote@konzeptpark.de>
 * Copyright (C) 2008 Andreas Steffen
 * Copyright (C) 2008 Neil Horman <nhorman@redhat.com>
 * Copyright (C) 2008-2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2006-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2010 Mika Ilmaranta <ilmis@foobar.fi>
 * Copyright (C) 2010 Roman Hoog Antink <rha@open.ch>
 * Copyright (C) 2010 D. Hugh Redelmeier
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

#if defined(linux) && defined(NETKEY_SUPPORT)

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <linux/pfkeyv2.h>
#include <unistd.h>

#include "kameipsec.h"
#include "linux26/rtnetlink.h"
#include <xfrm.h>

#include <openswan.h>
#include <openswan/pfkeyv2.h>
#include <openswan/pfkey.h>
#include <openswan/ipsec_tunnel.h>

#include "sysdep.h"
#include "socketwrapper.h"
#include "constants.h"
#include "defs.h"
#include "oswtime.h"
#include "oswconf.h"
#include "timer.h"
#include "id.h"
#include "oswtime.h"
#include "timer.h"
#include "pluto/state.h"
#include "pluto/connections.h"
#include "kernel.h"
#include "pluto/server.h"
#include "nat_traversal.h"
#include "state.h"
#include "kernel_forces.h"
#include "kernel_netlink.h"
#include "kernel_pfkey.h"
#include "log.h"
#include "whack.h"	/* for RC_LOG_SERIOUS */
#include "kernel_alg.h"
#include "crypto/aes_cbc.h"
#include "pluto/ike_alg.h"

#include "natt_defines.h"

static int netlinkfd = NULL_FD;
int netlink_bcast_fd = NULL_FD;

/** linux_pfkey_register - Register via PFKEY our capabilities
 *
 */
void
linux_pfkey_register(void)
{
    netlink_register_proto(SADB_SATYPE_AH, "AH");
    netlink_register_proto(SADB_SATYPE_ESP, "ESP");
    netlink_register_proto(SADB_X_SATYPE_IPCOMP, "IPCOMP");
    pfkey_close();
}

/** send_netlink_msg
 *
 * @param hdr - Data to be sent.
 * @param rbuf - Return Buffer - contains data returned from the send.
 * @param rbuf_len - Length of rbuf
 * @param description - String - user friendly description of what is
 *                      being attempted.  Used for diagnostics
 * @param text_said - String
 * @return bool True if the message was succesfully sent.
 */
bool
send_netlink_msg(struct nlmsghdr *hdr, struct nlmsghdr *rbuf, size_t rbuf_len
		 , const char *description, const char *text_said)
{
    const struct osw_conf_options *oco = osw_init_options();
    struct {
	struct nlmsghdr n;
	struct nlmsgerr e;
	char data[1024];
    } rsp;
    size_t len;
    ssize_t r;
    struct sockaddr_nl addr;
    static uint32_t seq;

    if (oco->kern_interface == NO_KERNEL)
    {
	return TRUE;
    }

    hdr->nlmsg_seq = ++seq;
    len = hdr->nlmsg_len;
    do {
	r = write(netlinkfd, hdr, len);
    } while (r < 0 && errno == EINTR);
    if (r < 0)
    {
	log_errno((e
	    , "netlink write() of %s message"
	      " for %s %s failed"
	    , sparse_val_show(xfrm_type_names, hdr->nlmsg_type)
	    , description, text_said));
	return FALSE;
    }
    else if ((size_t)r != len)
    {
	loglog(RC_LOG_SERIOUS
	    , "ERROR: netlink write() of %s message"
	      " for %s %s truncated: %ld instead of %lu"
	    , sparse_val_show(xfrm_type_names, hdr->nlmsg_type)
	    , description, text_said
	    , (long)r, (unsigned long)len);
	return FALSE;
    }

    for (;;) {
	socklen_t alen;

	alen = sizeof(addr);
	r = recvfrom(netlinkfd, &rsp, sizeof(rsp), 0
	    , (struct sockaddr *)&addr, &alen);
	if (r < 0)
	{
	    if (errno == EINTR)
	    {
		continue;
	    }
	    log_errno((e
		, "netlink recvfrom() of response to our %s message"
		  " for %s %s failed"
		, sparse_val_show(xfrm_type_names, hdr->nlmsg_type)
		, description, text_said));
	    return FALSE;
	}
	else if ((size_t) r < sizeof(rsp.n))
	{
	    openswan_log("netlink read truncated message: %ld bytes; ignore message"
		, (long) r);
	    continue;
	}
	else if (addr.nl_pid != 0)
	{
	    /* not for us: ignore */
	    DBG(DBG_NETKEY,
		DBG_log("netlink: ignoring %s message from process %u"
		    , sparse_val_show(xfrm_type_names, rsp.n.nlmsg_type)
		    , addr.nl_pid));
	    continue;
	}
	else if (rsp.n.nlmsg_seq != seq)
	{
	    DBG(DBG_NETKEY,
		DBG_log("netlink: ignoring out of sequence (%u/%u) message %s"
		    , rsp.n.nlmsg_seq, seq
		    , sparse_val_show(xfrm_type_names, rsp.n.nlmsg_type)));
	    continue;
	}
	break;
    }

    if (rsp.n.nlmsg_len > (size_t) r)
    {
	loglog(RC_LOG_SERIOUS
	    , "netlink recvfrom() of response to our %s message"
	      " for %s %s was truncated: %ld instead of %lu"
	    , sparse_val_show(xfrm_type_names, hdr->nlmsg_type)
	    , description, text_said
	    , (long) len, (unsigned long) rsp.n.nlmsg_len);
	return FALSE;
    }
    else if (rsp.n.nlmsg_type != NLMSG_ERROR
    && (rbuf && rsp.n.nlmsg_type != rbuf->nlmsg_type))
    {
	loglog(RC_LOG_SERIOUS
	    , "netlink recvfrom() of response to our %s message"
	      " for %s %s was of wrong type (%s)"
	    , sparse_val_show(xfrm_type_names, hdr->nlmsg_type)
	    , description, text_said
	    , sparse_val_show(xfrm_type_names, rsp.n.nlmsg_type));
	return FALSE;
    }
    else if (rbuf)
    {
	if ((size_t) r > rbuf_len)
	{
	    loglog(RC_LOG_SERIOUS
		, "netlink recvfrom() of response to our %s message"
		  " for %s %s was too long: %ld > %lu"
		, sparse_val_show(xfrm_type_names, hdr->nlmsg_type)
		, description, text_said
		, (long)r, (unsigned long)rbuf_len);
	    return FALSE;
	}
	memcpy(rbuf, &rsp, r);
	return TRUE;
    }
    else if (rsp.n.nlmsg_type == NLMSG_ERROR && rsp.e.error)
    {
	loglog(RC_LOG_SERIOUS
	    , "ERROR: netlink response for %s %s included errno %d: %s"
	    , description, text_said
	    , -rsp.e.error
	    , strerror(-rsp.e.error));
	return FALSE;
    }

    return TRUE;
}

/**
 * netlink_policy - send a message into NETLINK, and look for an errno-based return
 *
 * @param hdr - Data to check
 * @param enoent_ok - Boolean - OK or not OK.
 * @param text_said - String
 * @return boolean
 */
bool
netlink_policy(struct nlmsghdr *hdr, bool enoent_ok, const char *text_said)
{
    struct {
	struct nlmsghdr n;
	struct nlmsgerr e;
	char data[1024];
    } rsp;
    int error;

    rsp.n.nlmsg_type = NLMSG_ERROR;
    if (!send_netlink_msg(hdr, &rsp.n, sizeof(rsp), "policy", text_said))
    {
	return FALSE;
    }

    error = -rsp.e.error;
    if (!error)
    {
	return TRUE;
    }

    if (error == ENOENT && enoent_ok)
    {
	return TRUE;
    }

    loglog(RC_LOG_SERIOUS
	, "ERROR: netlink %s response for flow %s included errno %d: %s"
	, sparse_val_show(xfrm_type_names, hdr->nlmsg_type)
	, text_said
	, error
	, strerror(error));
    return FALSE;
}

bool
netlink_get(void)
{
    struct {
	struct nlmsghdr n;
	char data[1024];
    } rsp;
    ssize_t r;
    struct sockaddr_nl addr;
    socklen_t alen;

    alen = sizeof(addr);
    r = recvfrom(netlink_bcast_fd, &rsp, sizeof(rsp), 0
	, (struct sockaddr *)&addr, &alen);
    if (r < 0)
    {
	if (errno == EAGAIN)
	    return FALSE;
	if (errno != EINTR)
	    log_errno((e, "recvfrom() failed in netlink_get"));
	return TRUE;
    }
    else if ((size_t) r < sizeof(rsp.n))
    {
	openswan_log("netlink_get read truncated message: %ld bytes; ignore message"
	    , (long) r);
	return TRUE;
    }
    else if (addr.nl_pid != 0)
    {
	/* not for us: ignore */
	DBG(DBG_NETKEY,
	    DBG_log("netlink_get: ignoring %s message from process %u"
		, sparse_val_show(xfrm_type_names, rsp.n.nlmsg_type)
		, addr.nl_pid));
	return TRUE;
    }
    else if ((size_t) r != rsp.n.nlmsg_len)
    {
	openswan_log("netlink_get read message with length %ld that doesn't equal nlmsg_len %lu bytes; ignore message"
	    , (long) r
	    , (unsigned long) rsp.n.nlmsg_len);
	return TRUE;
    }

    DBG(DBG_NETKEY,
	DBG_log("netlink_get: %s message"
		, sparse_val_show(xfrm_type_names, rsp.n.nlmsg_type)));

    switch (rsp.n.nlmsg_type)
    {
    case XFRM_MSG_ACQUIRE:
	netlink_acquire(&rsp.n);
	break;
    case XFRM_MSG_POLEXPIRE:
	netlink_policy_expire(&rsp.n);
	break;
    default:
	/* ignored */
	break;
    }

    return TRUE;
}

bool
netkey_do_command(struct connection *c, const struct spd_route *sr
                  , const char *verb, const char *verb_suffix
                  , struct state *st)
{
    char cmd[2048];     /* arbitrary limit on shell command length */
    char common_shell_out_str[2048];

    if(fmt_common_shell_out(common_shell_out_str, sizeof(common_shell_out_str), c, sr, st)==-1) {
	loglog(RC_LOG_SERIOUS, "%s%s command too long!", verb, verb_suffix);
	return FALSE;
	}

    if (-1 == snprintf(cmd, sizeof(cmd)
		       , "2>&1 "   /* capture stderr along with stdout */
		       "PLUTO_VERB='%s%s' "
		       "%s"        /* other stuff   */
		       "%s"        /* actual script */
		       , verb, verb_suffix
		       , common_shell_out_str
		       , sr->this.updown == NULL? DEFAULT_UPDOWN : sr->this.updown))
    {
	loglog(RC_LOG_SERIOUS, "%s%s command too long!", verb, verb_suffix);
	return FALSE;
    }

    return invoke_command(verb, verb_suffix, cmd);
}

int nat_traversal_espinudp_socket (int sk, const char *fam, u_int32_t type)
{
    const struct osw_conf_options *oco = osw_init_options();
    int r = -1;
    struct ifreq ifr;
    int *fdp = (int *) &ifr.ifr_data;

    DBG(DBG_NATT, DBG_log("NAT-Traversal: Trying new style NAT-T"));
    memset(&ifr, 0, sizeof(ifr));
    switch(oco->kern_interface) {
    case USE_MASTKLIPS:
        strcpy(ifr.ifr_name, "ipsec0"); /* using mast0 will break it! */
        break;
    case USE_KLIPS:
        strcpy(ifr.ifr_name, "ipsec0");
        break;

    case USE_NETKEY:
        /* Let's hope we have at least one ethernet device */
        strcpy(ifr.ifr_name, "eth0");
        break;

    case USE_BSDKAME:
        /* Let's hope we have at least one ethernet device */
        strcpy(ifr.ifr_name, "en0");
        break;

    default:
        /* We have nothing , really prob just abort and return -1 */
        strcpy(ifr.ifr_name, "eth0");
        break;
    }
    fdp[0] = sk;
    fdp[1] = type;
    r = setsockopt(sk, SOL_UDP, UDP_ESPINUDP, &type, sizeof(type));
    if (r == -1) {
        DBG(DBG_NATT, DBG_log("NAT-Traversal: ESPINUDP(%d) setup failed for "
                              "new style NAT-T family %s (errno=%d)"
                              , type, fam, errno));
    } else {
        DBG(DBG_NATT, DBG_log("NAT-Traversal: ESPINUDP(%d) setup succeeded for "
                              "new style NAT-T family %s" , type, fam));
        return r;
    }

#if defined(KLIPS)
    DBG(DBG_NATT, DBG_log("NAT-Traversal: Trying old style NAT-T"));
    r = ioctl(sk, IPSEC_UDP_ENCAP_CONVERT, &ifr);
    if (r == -1) {
        DBG(DBG_NATT, DBG_log("NAT-Traversal: ESPINUDP(%d) setup failed for "
                              "old style NAT-T family %s (errno=%d)"
                              , type, fam, errno));
    } else {
        DBG(DBG_NATT, DBG_log("NAT-Traversal: ESPINUDP(%d) setup succeeded for "
                              "old style NAT-T family %s" , type, fam));
        return r;
    }
# else
    DBG(DBG_NATT, DBG_log("NAT-Traversal: ESPINUDP() setup for old style NAT-T family not available - KLIPS support not compiled in"));
# endif

    loglog(RC_LOG_SERIOUS,
           "NAT-Traversal: ESPINUDP(%d) not supported by kernel for family %s"
           , type, fam);
    disable_nat_traversal(type);
    return -1;
}


/** init_netlink - Initialize the netlink inferface.  Opens the sockets and
 * then binds to the broadcast socket.
 */
void init_netlink(void)
{
    struct sockaddr_nl addr;

    netlinkfd = safe_socket(AF_NETLINK, SOCK_DGRAM, NETLINK_XFRM);

    if (netlinkfd < 0)
	exit_log_errno((e, "socket() in init_netlink()"));

    if (fcntl(netlinkfd, F_SETFD, FD_CLOEXEC) != 0)
	exit_log_errno((e, "fcntl(FD_CLOEXEC) in init_netlink()"));

    netlink_bcast_fd = safe_socket(AF_NETLINK, SOCK_DGRAM, NETLINK_XFRM);

    if (netlink_bcast_fd < 0)
	exit_log_errno((e, "socket() for bcast in init_netlink()"));

    if (fcntl(netlink_bcast_fd, F_SETFD, FD_CLOEXEC) != 0)
	exit_log_errno((e, "fcntl(FD_CLOEXEC) for bcast in init_netlink()"));

    if (fcntl(netlink_bcast_fd, F_SETFL, O_NONBLOCK) != 0)
	exit_log_errno((e, "fcntl(O_NONBLOCK) for bcast in init_netlink()"));

    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = XFRMGRP_ACQUIRE | XFRMGRP_EXPIRE;
    if (bind(netlink_bcast_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
	exit_log_errno((e, "Failed to bind bcast socket in init_netlink() - Perhaps kernel was not compiled with CONFIG_XFRM"));

    /*
     * also open the pfkey socket, since we need it to get a list of
     * algorithms.
     * There is currently no netlink way to do this: (XXX - probably no longer
     * true in 2015).
     */
    init_pfkey();

    xfrm_init_base_algorithms();
}

/* called periodically to cleanup expired bare shunts, like what
 * pfkey_scan_proc_shunts() does for KLIPS shunts */
void
netlink_scan_bare_shunts(void)
{
    struct bare_shunt **bspp;
    time_t nw = now();

    event_schedule(EVENT_SHUNT_SCAN, SHUNT_SCAN_INTERVAL, NULL);

    DBG(DBG_CONTROL, DBG_log("scanning for expired bare shunts"));

    for(bspp = &bare_shunts;;) {
        struct bare_shunt *bsp;
        time_t age;
	bool success;

        bsp = READ_ONCE(*bspp);

        if (!bsp)
            break;

        age = nw - bsp->last_activity;

        if (age <= SHUNT_PATIENCE) {
            DBG_bare_shunt_log("keeping recent", bsp);
            bspp = &bsp->next;
            continue;
        }
        /* need to expire this entry */
        DBG_bare_shunt_log("removing expired", bsp);

	success = delete_bare_shunt_ptr(bspp, "delete expired bare shunts");

	if (success) {
		/* shunt was removed, and the bspp should now point
		 * to the next entry */
		passert(bsp != READ_ONCE(*bspp));
	} else {
		/* if we failed to remove this shunt, we have to skip
		 * to the next entry to avoid getting stuck on this entry */
		if (bsp == READ_ONCE(*bspp))
			bspp = &bsp->next;
	}
    }
}

const struct kernel_ops netkey_kernel_ops = {
    kern_name: "netkey",
    type: USE_NETKEY,
    inbound_eroute:  TRUE,
    policy_lifetime: TRUE,
    async_fdp: &netlink_bcast_fd,
    replay_window: 32,

    init: init_netlink,
    pfkey_register: linux_pfkey_register,
    pfkey_register_response: linux_pfkey_register_response,
    process_msg: netlink_process_msg,
    raw_eroute: netlink_raw_eroute,
    add_sa: netlink_add_sa,
    del_sa: netlink_del_sa,
    get_sa: netlink_get_sa,
    process_queue: NULL,
    grp_sa: NULL,
    get_spi: netlink_get_spi,
    exceptsocket: NULL,
    docommand: netkey_do_command,
    process_ifaces: netlink_process_raw_ifaces,
    shunt_eroute: netlink_shunt_eroute,
    sag_eroute: netlink_sag_eroute,
    eroute_idle: netlink_eroute_idle,
    set_debug: NULL,    /* pfkey_set_debug, */
    /* We should implement netlink_remove_orphaned_holds
     * if netlink  specific changes are needed.
     */
    remove_orphaned_holds: pfkey_remove_orphaned_holds,
    overlap_supported: FALSE,
    sha2_truncbug_support: TRUE,
    scan_shunts: netlink_scan_bare_shunts,
};
#endif /* linux && NETKEY_SUPPORT */

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
