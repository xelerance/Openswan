/* demultiplex incoming IKE messages
 * 
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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
 * (all the code that used to be here is now in ikev1.c)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>	/* only used for belt-and-suspenders select call */
#include <sys/poll.h>	/* only used for forensic poll call */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
#  include <asm/types.h>	/* for __u8, __u32 */
#  include <linux/errqueue.h>
#  include <sys/uio.h>	/* struct iovec */
#endif

#include <openswan.h>

#include "sysdep.h"
#include "constants.h"
#include "oswlog.h"

#include "defs.h"
#include "cookie.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "smartcard.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "connections.h"	/* needs id.h */
#include "state.h"
#include "packet.h"
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "ike_alg.h"
#include "log.h"
#include "demux.h"	/* needs packet.h */
#include "ikev1.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "timer.h"
#if 0
#include "whack.h"	/* requires connections.h */
#include "server.h"
#ifdef XAUTH
#include "xauth.h"
#endif
#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif
#include "vendor.h"
#include "dpd.h"
#endif
#include "udpfromto.h"
#include "tpm/tpm.h"

/* This file does basic header checking and demux of
 * incoming packets.
 */

/* forward declarations */
static bool read_packet(struct msg_digest *md);

/* Reply messages are built in this buffer.
 * Only one state transition function can be using it at a time
 * so suspended STFs must save and restore it.
 * It could be an auto variable of complete_state_transition except for the fact
 * that when a suspended STF resumes, its reply message buffer
 * must be at the same location -- there are pointers into it.
 */
u_int8_t reply_buffer[MAX_OUTPUT_UDP_SIZE];

/* Process any message on the MSG_ERRQUEUE
 *
 * This information is generated because of the IP_RECVERR socket option.
 * The API is sparsely documented, and may be LINUX-only, and only on
 * fairly recent versions at that (hence the conditional compilation).
 *
 * - ip(7) describes IP_RECVERR
 * - recvmsg(2) describes MSG_ERRQUEUE
 * - readv(2) describes iovec
 * - cmsg(3) describes how to process auxilliary messages
 *
 * ??? we should link this message with one we've sent
 * so that the diagnostic can refer to that negotiation.
 *
 * ??? how long can the messge be?
 *
 * ??? poll(2) has a very incomplete description of the POLL* events.
 * We assume that POLLIN, POLLOUT, and POLLERR are all we need to deal with
 * and that POLLERR will be on iff there is a MSG_ERRQUEUE message.
 *
 * We have to code around a couple of surprises:
 *
 * - Select can say that a socket is ready to read from, and
 *   yet a read will hang.  It turns out that a message available on the
 *   MSG_ERRQUEUE will cause select to say something is pending, but
 *   a normal read will hang.  poll(2) can tell when a MSG_ERRQUEUE
 *   message is pending.
 *
 *   This is dealt with by calling check_msg_errqueue after select
 *   has indicated that there is something to read, but before the
 *   read is performed.  check_msg_errqueue will return TRUE if there
 *   is something left to read.
 *
 * - A write to a socket may fail because there is a pending MSG_ERRQUEUE
 *   message, without there being anything wrong with the write.  This
 *   makes for confusing diagnostics.
 *
 *   To avoid this, we call check_msg_errqueue before a write.  True,
 *   there is a race condition (a MSG_ERRQUEUE message might arrive
 *   between the check and the write), but we should eliminate many
 *   of the problematic events.  To narrow the window, the poll(2)
 *   will await until an event happens (in the case or a write,
 *   POLLOUT; this should be benign for POLLIN).
 */

#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
static bool
check_msg_errqueue(const struct iface_port *ifp, short interest)
{
    struct pollfd pfd;

    pfd.fd = ifp->fd;
    pfd.events = interest | POLLPRI | POLLOUT;

    while (pfd.revents = 0
    , poll(&pfd, 1, -1) > 0 && (pfd.revents & POLLERR))
    {
	u_int8_t buffer[3000];	/* hope that this is big enough */
	union
	{
	    struct sockaddr sa;
	    struct sockaddr_in sa_in4;
	    struct sockaddr_in6 sa_in6;
	} from;

	int from_len = sizeof(from);

	int packet_len;

	struct msghdr emh;
	struct iovec eiov;
	union {
	    /* force alignment (not documented as necessary) */
	    struct cmsghdr ecms;

	    /* how much space is enough? */
	    unsigned char space[256];
	} ecms_buf;

	struct cmsghdr *cm;
	char fromstr[sizeof(" for message to  port 65536") + INET6_ADDRSTRLEN];
	struct state *sender = NULL;

	zero(&from.sa);
	from_len = sizeof(from);

	emh.msg_name = &from.sa;	/* ??? filled in? */
	emh.msg_namelen = sizeof(from);
	emh.msg_iov = &eiov;
	emh.msg_iovlen = 1;
	emh.msg_control = &ecms_buf;
	emh.msg_controllen = sizeof(ecms_buf);
	emh.msg_flags = 0;

	eiov.iov_base = buffer;	/* see readv(2) */
	eiov.iov_len = sizeof(buffer);

	packet_len = recvmsg(ifp->fd, &emh, MSG_ERRQUEUE);

	if (packet_len == -1)
	{
	    log_errno((e, "recvmsg(,, MSG_ERRQUEUE) on %s failed in comm_handle"
		, ifp->ip_dev->id_rname));
	    break;
	}
	else if (packet_len == sizeof(buffer))
	{
	    openswan_log("MSG_ERRQUEUE message longer than %lu bytes; truncated"
		, (unsigned long) sizeof(buffer));
	}
	else
	{
	    sender = find_sender((size_t) packet_len, buffer);
	}

	DBG_cond_dump(DBG_ALL, "rejected packet:\n", buffer, packet_len);
	DBG_cond_dump(DBG_ALL, "control:\n", emh.msg_control, emh.msg_controllen);
	/* ??? Andi Kleen <ak@suse.de> and misc documentation
	 * suggests that name will have the original destination
	 * of the packet.  We seem to see msg_namelen == 0.
	 * Andi says that this is a kernel bug and has fixed it.
	 * Perhaps in 2.2.18/2.4.0.
	 */
	passert(emh.msg_name == &from.sa);
	DBG_cond_dump(DBG_ALL, "name:\n", emh.msg_name
	    , emh.msg_namelen);

	fromstr[0] = '\0';	/* usual case :-( */
	switch (from.sa.sa_family)
	{
	char as[INET6_ADDRSTRLEN];

	case AF_INET:
	    if (emh.msg_namelen == sizeof(struct sockaddr_in))
		snprintf(fromstr, sizeof(fromstr)
		, " for message to %s port %u"
		    , inet_ntop(from.sa.sa_family
		    , &from.sa_in4.sin_addr, as, sizeof(as))
		    , ntohs(from.sa_in4.sin_port));
	    break;
	case AF_INET6:
	    if (emh.msg_namelen == sizeof(struct sockaddr_in6))
		snprintf(fromstr, sizeof(fromstr)
		    , " for message to %s port %u"
		    , inet_ntop(from.sa.sa_family
		    , &from.sa_in6.sin6_addr, as, sizeof(as))
		    , ntohs(from.sa_in6.sin6_port));
	    break;
	}

	for (cm = CMSG_FIRSTHDR(&emh)
		 ; cm != NULL
		 ; cm = CMSG_NXTHDR(&emh,cm))
	{
	    if (cm->cmsg_level == SOL_IP
		&& cm->cmsg_type == IP_RECVERR)	{
		/* ip(7) and recvmsg(2) specify:
		 * ee_origin is SO_EE_ORIGIN_ICMP for ICMP
		 *  or SO_EE_ORIGIN_LOCAL for locally generated errors.
		 * ee_type and ee_code are from the ICMP header.
		 * ee_info is the discovered MTU for EMSGSIZE errors
		 * ee_data is not used.
		 *
		 * ??? recvmsg(2) says "SOCK_EE_OFFENDER" but
		 * means "SO_EE_OFFENDER".  The OFFENDER is really
		 * the router that complained.  As such, the port
		 * is meaningless.
		 */

		/* ??? cmsg(3) claims that CMSG_DATA returns
		 * void *, but RFC 2292 and /usr/include/bits/socket.h
		 * say unsigned char *.  The manual is being fixed.
		 */
		struct sock_extended_err *ee = (void *)CMSG_DATA(cm);
		const char *offstr = "unspecified";
		char offstrspace[INET6_ADDRSTRLEN];
		char orname[50];

		if (cm->cmsg_len > CMSG_LEN(sizeof(struct sock_extended_err)))
		{
		    const struct sockaddr *offender = SO_EE_OFFENDER(ee);

		    switch (offender->sa_family)
		    {
		    case AF_INET:
			offstr = inet_ntop(offender->sa_family
			    , &((const struct sockaddr_in *)offender)->sin_addr
			    , offstrspace, sizeof(offstrspace));
			break;
		    case AF_INET6:
			offstr = inet_ntop(offender->sa_family
			    , &((const struct sockaddr_in6 *)offender)->sin6_addr
			    , offstrspace, sizeof(offstrspace));
			break;
		    default:
			offstr = "unknown";
			break;
		    }
		}

		switch (ee->ee_origin)
		{
		case SO_EE_ORIGIN_NONE:
		    snprintf(orname, sizeof(orname), "none");
		    break;
		case SO_EE_ORIGIN_LOCAL:
		    snprintf(orname, sizeof(orname), "local");
		    break;
		case SO_EE_ORIGIN_ICMP:
		    snprintf(orname, sizeof(orname)
			, "ICMP type %d code %d (not authenticated)"
			, ee->ee_type, ee->ee_code
			);
		    break;
		case SO_EE_ORIGIN_ICMP6:
		    snprintf(orname, sizeof(orname)
			, "ICMP6 type %d code %d (not authenticated)"
			, ee->ee_type, ee->ee_code
			);
		    break;
		default:
		    snprintf(orname, sizeof(orname), "invalid origin %lu"
			, (unsigned long) ee->ee_origin);
		    break;
		}

		{
		    struct state *old_state = cur_state;

		    cur_state = sender;

		    /* note dirty trick to suppress ~ at start of format
		     * if we know what state to blame.
		     */
#ifdef NAT_TRAVERSAL
		    if ((packet_len == 1) && (buffer[0] = 0xff)
#ifdef DEBUG
			&& ((cur_debugging & DBG_NATT) == 0)
#endif
			) {
			    /* don't log NAT-T keepalive related errors unless NATT debug is
			     * enabled
			     */
		    }
		    else
#endif
		    openswan_log((sender != NULL) + "~"
			"ERROR: asynchronous network error report on %s (sport=%d)"
			"%s"
			", complainant %s"
			": %s"
			" [errno %lu, origin %s"
			/* ", pad %d, info %ld" */
			/* ", data %ld" */
			"]"
			, ifp->ip_dev->id_rname
				 , ifp->port
			, fromstr
			, offstr
			, strerror(ee->ee_errno)
			, (unsigned long) ee->ee_errno
			, orname
			/* , ee->ee_pad, (unsigned long)ee->ee_info */
			/* , (unsigned long)ee->ee_data */
			);
		    cur_state = old_state;
		}
	    }
	    else if (cm->cmsg_level == SOL_IP
		     && cm->cmsg_type == IP_PKTINFO) {
	    }
	    else
	    {
		/* .cmsg_len is a kernel_size_t(!), but the value
		 * certainly ought to fit in an unsigned long.
		 */
		openswan_log("unknown cmsg: level %d, type %d, len %lu"
		    , cm->cmsg_level, cm->cmsg_type
		    , (unsigned long) cm->cmsg_len);
	    }
	}
    }
    return (pfd.revents & interest) != 0;
}
#endif /* defined(IP_RECVERR) && defined(MSG_ERRQUEUE) */

bool
send_packet(struct state *st, const char *where, bool verbose)
{
    bool err;
    u_int8_t ike_pkt[MAX_OUTPUT_UDP_SIZE];
    u_int8_t *ptr;
    unsigned long len;
    ssize_t wlen;

    if ((st->st_interface->ike_float == TRUE) && (st->st_tpacket.len != 1)) {
	if ((unsigned long) st->st_tpacket.len >
	    (MAX_OUTPUT_UDP_SIZE-sizeof(u_int32_t))) {
	    DBG_log("send_packet(): really too big");
	    return FALSE;
	}
	ptr = ike_pkt;
	/** Add Non-ESP marker **/
	memset(ike_pkt, 0, sizeof(u_int32_t));
	memcpy(ike_pkt + sizeof(u_int32_t), st->st_tpacket.ptr,
	       (unsigned long)st->st_tpacket.len);
	len = (unsigned long) st->st_tpacket.len + sizeof(u_int32_t);
    }
    else {
	ptr = st->st_tpacket.ptr;
	len = (unsigned long) st->st_tpacket.len;
    }

    DBG(DBG_CONTROL|DBG_RAW
	, DBG_log("sending %lu bytes for %s through %s:%d to %s:%u (using #%lu)"
		  , (unsigned long) st->st_tpacket.len
		  , where
		  , st->st_interface->ip_dev->id_rname
		  , st->st_interface->port
		  , ip_str(&st->st_remoteaddr)
		  , st->st_remoteport
		  , st->st_serialno));
    DBG(DBG_RAW
	, DBG_dump(NULL, ptr, len));

    setportof(htons(st->st_remoteport), &st->st_remoteaddr);

#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
    (void) check_msg_errqueue(st->st_interface, POLLOUT);
#endif /* defined(IP_RECVERR) && defined(MSG_ERRQUEUE) */

#if 0
    wlen = sendfromto(st->st_interface->fd
		      , ptr
		      , len, 0
		      , sockaddrof(&st->st_remoteaddr)
		      , sockaddrlenof(&st->st_remoteaddr)
		      , sockaddrof(&st->st_localaddr)
		      , sockaddrlenof(&st->st_localaddr));
#else
    wlen = sendto(st->st_interface->fd
		  , ptr
		  , len, 0
		  , sockaddrof(&st->st_remoteaddr)
		  , sockaddrlenof(&st->st_remoteaddr));

#ifdef DEBUG
    if(DBGP(IMPAIR_JACOB_TWO_TWO)) {
	/* sleep for half a second, and second another packet */
	usleep(500000);

	DBG_log("JACOB 2-2: resending %lu bytes for %s through %s:%d to %s:%u:"
		, (unsigned long) st->st_tpacket.len
		, where
		, st->st_interface->ip_dev->id_rname
		, st->st_interface->port
		, ip_str(&st->st_remoteaddr)
		, st->st_remoteport);
#endif

	wlen = sendto(st->st_interface->fd
		      , ptr
		      , len, 0
		      , sockaddrof(&st->st_remoteaddr)
		      , sockaddrlenof(&st->st_remoteaddr));
    }

	
#endif
    err = (wlen != (ssize_t)len);

    if (err)
    {
        /* do not log NAT-T Keep Alive packets */
        if (!verbose)
	    return FALSE; 
	log_errno((e, "sendto on %s to %s:%u failed in %s"
		   , st->st_interface->ip_dev->id_rname
		   , ip_str(&st->st_remoteaddr)
		   , st->st_remoteport
		   , where));
	return FALSE;
    }
    else
    {
	return TRUE;
    }
}

/* process an input packet, possibly generating a reply.
 *
 * If all goes well, this routine eventually calls a state-specific
 * transition function.
 */
void
process_packet(struct msg_digest **mdp)
{
    struct msg_digest *md = *mdp;
    struct state *st = NULL;
    int maj, min;
    enum state_kind from_state = STATE_UNDEFINED;	/* state we started in */
    struct isakmp_hdr *hdr;

#define SEND_NOTIFICATION(t) { \
    if (st) send_notification_from_state(st, from_state, t); \
    else send_notification_from_md(md, t); }

    if (!in_struct(&md->hdr, &isakmp_hdr_desc, &md->packet_pbs, &md->message_pbs))
    {
	/* Identify specific failures:
	 * - bad ISAKMP major/minor version numbers
	 */
	if (md->packet_pbs.roof - md->packet_pbs.cur >= (ptrdiff_t)isakmp_hdr_desc.size)
	{
	    hdr = (struct isakmp_hdr *)md->packet_pbs.cur;
	    maj = (hdr->isa_version >> ISA_MAJ_SHIFT);
	    min = (hdr->isa_version & ISA_MIN_MASK);

	    if ( maj != ISAKMP_MAJOR_VERSION
		 && maj != IKEv2_MAJOR_VERSION)
	    {
		SEND_NOTIFICATION(INVALID_MAJOR_VERSION);
		return;
	    }
	    else if (maj == ISAKMP_MAJOR_VERSION && min != ISAKMP_MINOR_VERSION)
	    {
		/* all IKEv2 minor version are acceptable */
		SEND_NOTIFICATION(INVALID_MINOR_VERSION);
		return;
	    }
	}
	SEND_NOTIFICATION(PAYLOAD_MALFORMED);
	return;
    }

    if (md->packet_pbs.roof != md->message_pbs.roof)
    {
	openswan_log("size (%u) differs from size specified in ISAKMP HDR (%u)"
	    , (unsigned) pbs_room(&md->packet_pbs), md->hdr.isa_length);
	return;
    }

    maj = (md->hdr.isa_version >> ISA_MAJ_SHIFT);
    min = (md->hdr.isa_version & ISA_MIN_MASK);

    DBG(DBG_CONTROL
	, DBG_log(" processing version=%u.%u packet with exchange type=%s (%d)"
		  , maj, min
		  , enum_name(&exchange_names, md->hdr.isa_xchg)
		  , md->hdr.isa_xchg));

    TCLCALLOUT("processRawPacket", NULL, NULL, md);

    switch(maj) {
    case ISAKMP_MAJOR_VERSION:
	process_v1_packet(mdp);
	break;

    case IKEv2_MAJOR_VERSION:
	process_v2_packet(mdp);
	break;

    default:
	bad_case(maj);
    }
}

/* wrapper for read_packet and process_packet
 *
 * The main purpose of this wrapper is to factor out teardown code
 * from the many return points in process_packet.  This amounts to
 * releasing the msg_digest and resetting global variables.
 *
 * When processing of a packet is suspended (STF_SUSPEND),
 * process_packet sets md to NULL to prevent the msg_digest being freed.
 * Someone else must ensure that msg_digest is freed eventually.
 *
 * read_packet is broken out to minimize the lifetime of the
 * enormous input packet buffer, an auto.
 */
void
comm_handle(const struct iface_port *ifp)
{
    static struct msg_digest *md;

#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
    /* Even though select(2) says that there is a message,
     * it might only be a MSG_ERRQUEUE message.  At least
     * sometimes that leads to a hanging recvfrom.  To avoid
     * what appears to be a kernel bug, check_msg_errqueue
     * uses poll(2) and tells us if there is anything for us
     * to read.
     *
     * This is early enough that teardown isn't required:
     * just return on failure.
     */
    if (!check_msg_errqueue(ifp, POLLIN))
	return;	/* no normal message to read */
#endif /* defined(IP_RECVERR) && defined(MSG_ERRQUEUE) */

    md = alloc_md();
    md->iface = ifp;

    if (read_packet(md))
	process_packet(&md);

    if (md != NULL)
	release_md(md);

    cur_state = NULL;
    reset_cur_connection();
    cur_from = NULL;
}

/* read the message.
 * Since we don't know its size, we read it into
 * an overly large buffer and then copy it to a
 * new, properly sized buffer.
 */
static bool
read_packet(struct msg_digest *md)
{
    const struct iface_port *ifp = md->iface;
    int packet_len;
    /* ??? this buffer seems *way* too big */
    u_int8_t bigbuffer[MAX_INPUT_UDP_SIZE];
#ifdef NAT_TRAVERSAL
    u_int8_t *_buffer = bigbuffer;
#endif
    union
    {
	struct sockaddr sa;
	struct sockaddr_in sa_in4;
	struct sockaddr_in6 sa_in6;
    } from
#if defined(HAVE_UDPFROMTO)
	  ,to
#endif
	  ;
    socklen_t from_len = sizeof(from);
#if defined(HAVE_UDPFROMTO)
    socklen_t to_len   = sizeof(to);
#endif
    err_t from_ugh = NULL;
    static const char undisclosed[] = "unknown source";

    happy(anyaddr(addrtypeof(&ifp->ip_addr), &md->sender));
    zero(&from.sa);

#if defined(HAVE_UDPFROMTO)
    packet_len = recvfromto(ifp->fd, bigbuffer
			    , sizeof(bigbuffer), /*flags*/0
			    , &from.sa, &from_len
			    , &to.sa, &to_len);
#else
    packet_len = recvfrom(ifp->fd, bigbuffer
			  , sizeof(bigbuffer), /*flags*/0
			  , &from.sa, &from_len);
#endif    

    /* we do not do anything with *to* addresses yet... we will */

    /* First: digest the from address.
     * We presume that nothing here disturbs errno.
     */
    if (packet_len == -1
    && from_len == sizeof(from)
    && all_zero((const void *)&from.sa, sizeof(from)))
    {
	/* "from" is untouched -- not set by recvfrom */
	from_ugh = undisclosed;
    }
    else if (from_len
    < (int) (offsetof(struct sockaddr, sa_family) + sizeof(from.sa.sa_family)))
    {
	from_ugh = "truncated";
    }
    else
    {
	const struct af_info *afi = aftoinfo(from.sa.sa_family);

	if (afi == NULL)
	{
	    from_ugh = "unexpected Address Family";
	}
	else if (from_len != afi->sa_sz)
	{
	    from_ugh = "wrong length";
	}
	else
	{
	    switch (from.sa.sa_family)
	    {
	    case AF_INET:
		from_ugh = initaddr((void *) &from.sa_in4.sin_addr
				    , sizeof(from.sa_in4.sin_addr)
				    , AF_INET, &md->sender);
		setportof(from.sa_in4.sin_port, &md->sender);
		md->sender_port = ntohs(from.sa_in4.sin_port);
		break;
	    case AF_INET6:
		from_ugh = initaddr((void *) &from.sa_in6.sin6_addr
				    , sizeof(from.sa_in6.sin6_addr)
				    , AF_INET6, &md->sender);
		setportof(from.sa_in6.sin6_port, &md->sender);
		md->sender_port = ntohs(from.sa_in6.sin6_port);
		break;
	    }
	}
    }

    /* now we report any actual I/O error */
    if (packet_len == -1)
    {
	if (from_ugh == undisclosed
	&& errno == ECONNREFUSED)
	{
	    /* Tone down scary message for vague event:
	     * We get "connection refused" in response to some
	     * datagram we sent, but we cannot tell which one.
	     */
	    openswan_log("some IKE message we sent has been rejected with ECONNREFUSED (kernel supplied no details)");
	}
	else if (from_ugh != NULL)
	{
	    log_errno((e, "recvfrom on %s failed; Pluto cannot decode source sockaddr in rejection: %s"
		, ifp->ip_dev->id_rname, from_ugh));
	}
	else
	{
	    log_errno((e, "recvfrom on %s from %s:%u failed"
		, ifp->ip_dev->id_rname
		, ip_str(&md->sender), (unsigned)md->sender_port));
	}

	return FALSE;
    }
    else if (from_ugh != NULL)
    {
	openswan_log("recvfrom on %s returned misformed source sockaddr: %s"
	    , ifp->ip_dev->id_rname, from_ugh);
	return FALSE;
    }
    cur_from = &md->sender;
    cur_from_port = md->sender_port;

#ifdef NAT_TRAVERSAL
    if (ifp->ike_float == TRUE) {
	u_int32_t non_esp;
	if (packet_len < (int)sizeof(u_int32_t)) {
	    openswan_log("recvfrom %s:%u too small packet (%d)"
		, ip_str(cur_from), (unsigned) cur_from_port, packet_len);
	    return FALSE;
	}
	memcpy(&non_esp, _buffer, sizeof(u_int32_t));
	if (non_esp != 0) {
	    openswan_log("recvfrom %s:%u has no Non-ESP marker"
		, ip_str(cur_from), (unsigned) cur_from_port);
	    return FALSE;
	}
	_buffer += sizeof(u_int32_t);
	packet_len -= sizeof(u_int32_t);
    }
#endif

    /* Clone actual message contents
     * and set up md->packet_pbs to describe it.
     */
    init_pbs(&md->packet_pbs
#ifdef NAT_TRAVERSAL
	, clone_bytes(_buffer, packet_len, "message buffer in comm_handle()")
#else
	, clone_bytes(bigbuffer, packet_len, "message buffer in comm_handle()")
#endif
	, packet_len, "packet");

    DBG(DBG_RAW | DBG_CRYPT | DBG_PARSING | DBG_CONTROL,
	{
	    DBG_log("*received %d bytes from %s:%u on %s (port=%d)"
		    , (int) pbs_room(&md->packet_pbs)
		    , ip_str(cur_from), (unsigned) cur_from_port
		    , ifp->ip_dev->id_rname
		    , ifp->port);
	});

    DBG(DBG_RAW,
	DBG_dump("", md->packet_pbs.start, pbs_room(&md->packet_pbs)));

#ifdef NAT_TRAVERSAL
	if ((pbs_room(&md->packet_pbs)==1) && (md->packet_pbs.start[0]==0xff)) {
		/**
		 * NAT-T Keep-alive packets should be discared by kernel ESPinUDP
		 * layer. But boggus keep-alive packets (sent with a non-esp marker)
		 * can reach this point. Complain and discard them.
		 */
		DBG(DBG_NATT,
			DBG_log("NAT-T keep-alive (boggus ?) should not reach this point. "
				"Ignored. Sender: %s:%u", ip_str(cur_from),
				(unsigned) cur_from_port);
			);
		return FALSE;
	}
#endif

    return TRUE;
}

void fmt_ipsec_sa_established(struct state *st, char *sadetails, int sad_len)
{
    char *b = sadetails;
    const char *ini = " {";
    const char *fin = "";
    
    strcpy(sadetails,
	   (st->st_connection->policy & POLICY_TUNNEL ?
	    " tunnel mode" : " transport mode"));
    b += strlen(sadetails);
    
    /* -1 is to leave space for "fin" */
    
    if(st->st_esp.present)
    {
	const char *natinfo="";
	
	if((st->st_connection->spd.that.host_port != IKE_UDP_PORT
	    && st->st_connection->spd.that.host_port != 0)
	   || st->st_connection->forceencaps) {
	    natinfo="/NAT";
	}
	snprintf(b, sad_len-(b-sadetails)-1
		 , "%sESP%s=>0x%08lx <0x%08lx xfrm=%s_%d-%s"
		 , ini
		 , natinfo
		 , (unsigned long)ntohl(st->st_esp.attrs.spi)
		 , (unsigned long)ntohl(st->st_esp.our_spi)
		 , enum_show(&esp_transformid_names, st->st_esp.attrs.transid)+strlen("ESP_")
		 , st->st_esp.attrs.key_len
		 , enum_show(&auth_alg_names, st->st_esp.attrs.auth)+strlen("AUTH_ALGORITHM_"));
	ini = " ";
	fin = "}";
    }
    /* advance b to end of string */
    b = b + strlen(b);
    
    if(st->st_ah.present)
    {
	snprintf(b, sad_len-(b-sadetails)-1
		 , "%sAH=>0x%08lx <0x%08lx"
		 , ini
		 , (unsigned long)ntohl(st->st_ah.attrs.spi)
		 , (unsigned long)ntohl(st->st_ah.our_spi));
	ini = " ";
	fin = "}";
    }
    /* advance b to end of string */
    b = b + strlen(b);
    
    if(st->st_ipcomp.present)
    {
	snprintf(b, sad_len-(b-sadetails)-1
		 , "%sIPCOMP=>0x%08lx <0x%08lx"
		 , ini
		 , (unsigned long)ntohl(st->st_ipcomp.attrs.spi)
		 , (unsigned long)ntohl(st->st_ipcomp.our_spi));
	ini = " ";
	fin = "}";
    }
    
    /* advance b to end of string */
    b = b + strlen(b);
#ifdef NAT_TRAVERSAL		    
    {
	char oa[ADDRTOT_BUF];
	
	strcpy(oa, "none");
	if(!isanyaddr(&st->hidden_variables.st_nat_oa)) {
	    addrtot(&st->hidden_variables.st_nat_oa, 0
		    , oa, sizeof(oa));
	}
	snprintf(b, sad_len-(b-sadetails)-1
		 , "%sNATOA=%s"
		 , ini, oa);
	ini = " ";
	fin = "}";
    }
    
    {
	char oa[ADDRTOT_BUF+sizeof(":00000")];
	
	strcpy(oa, "none");
	if(!isanyaddr(&st->hidden_variables.st_natd)) {
	    char oa2[ADDRTOT_BUF];
	    addrtot(&st->hidden_variables.st_natd, 0
		    , oa2, sizeof(oa2));
	    snprintf(oa, sizeof(oa)
		     , "%s:%d", oa2, st->st_remoteport);
	}
	snprintf(b, sad_len-(b-sadetails)-1
		 , "%sNATD=%s"
		 , ini, oa);
	ini = " ";
	fin = "}";
    }
#endif
    
    /* advance b to end of string */
    b = b + strlen(b);
    
    snprintf(b, sad_len-(b-sadetails)-1
	     , "%sDPD=%s"
	     , ini
	     , st->hidden_variables.st_dpd_local ?
	     "enabled" : "none");
    
    ini = " ";
    fin = "}";
    
    strcat(b, fin);
}

void fmt_isakmp_sa_established(struct state *st, char *sadetails, int sad_len)
{

    /* document ISAKMP SA details for admin's pleasure */
    char *b = sadetails;
    
    passert(st->st_oakley.encrypter != NULL);
    passert(st->st_oakley.hasher != NULL);
    passert(st->st_oakley.group != NULL);
    
    snprintf(b, sad_len-(b-sadetails)-1
	     , " {auth=%s cipher=%s_%d prf=%s group=modp%d}"
	     , enum_show(&oakley_auth_names, st->st_oakley.auth)
	     , st->st_oakley.encrypter->common.name
	     , st->st_oakley.enckeylen
	     , st->st_oakley.hasher->common.name
	     , (int)st->st_oakley.group->bytes*8);
    st->hidden_variables.st_logged_p1algos = TRUE;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
