/* Find public key in DNS
 * Copyright (C) 2000-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2008 Paul Wouters <paul@xelerance.com>
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

#define _GNU_SOURCE
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>	/* ??? for h_errno */
#include <resolv.h>
#include <arpa/inet.h>  /* for inet_ntop */

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "sysdep.h"
#include "constants.h"
#include "adns.h"	/* needs <resolv.h> */
#include "defs.h"
#include "id.h"
#include "log.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "pluto/connections.h"	/* needs id.h */
#include "keys.h"	    /* needs connections.h */
#include "dnskey.h"
#include "packet.h"
#include "state.h"
#include "timer.h"
#include "pluto/server.h"

/* somebody has to decide */
#define MAX_TXT_RDATA	((MAX_KEY_BYTES * 8 / 6) + 40)	/* somewhat arbitrary overkill */

/* ADNS stuff */

unsigned int sort_dns_answers = 0;

int adns_qfd = NULL_FD,	/* file descriptor for sending queries to adns (O_NONBLOCK) */
    adns_afd = NULL_FD;	/* file descriptor for receiving answers from adns */
static pid_t adns_pid = 0;
const char *pluto_adns_option = NULL;	/* path from --pluto_adns */

static int adns_in_flight = 0;	/* queries outstanding */
int adns_restart_count;
#define ADNS_RESTART_MAX 20

static void release_all_continuations(void);

bool adns_reapchild(pid_t pid, int status UNUSED)
{
  if(pid == adns_pid) {
    close_any(adns_qfd);
    adns_qfd = NULL_FD;
    close_any(adns_afd);
    adns_afd = NULL_FD;

    adns_pid = 0;

    if(adns_in_flight > 0) {
	release_all_continuations();
    }
    pexpect(adns_in_flight == 0);

    return TRUE;
  }
  return FALSE;
}


void
init_adns(void)
{
    int qfds[2];
    int afds[2];

    if (pipe(qfds) != 0 || pipe(afds) != 0)
	exit_log_errno((e, "pipe(2) failed in init_adns()"));

#ifdef HAVE_NO_FORK
    adns_pid = vfork(); /* for better, for worse, in sickness and health..... */
#else
    adns_pid = fork();
#endif
    switch (adns_pid)
    {
    case -1:
	exit_log_errno((e, "fork() failed in init_adns()"));

    case 0:
	/* child */
	{
	    /* Make stdin and stdout our pipes.
	     * Take care to handle case where pipes already use these fds.
	     */
	    if (afds[1] == 0)
		afds[1] = dup(afds[1]);	/* avoid being overwritten */
	    if (qfds[0] != 0)
	    {
		dup2(qfds[0], 0);
		close(qfds[0]);
	    }
	    if (afds[1] != 1)
	    {
		dup2(afds[1], 1);
		close(qfds[1]);
	    }
	    if (afds[0] > 1)
		close(afds[0]);
	    if (afds[1] > 1)
		close(afds[1]);

            adns_main(TRUE);
            exit(0);
	}

    default:
	/* parent */
	close(qfds[0]);
	adns_qfd = qfds[1];
	adns_afd = afds[0];
	close(afds[1]);
	fcntl(adns_qfd, F_SETFD, FD_CLOEXEC);
	fcntl(adns_afd, F_SETFD, FD_CLOEXEC);
	fcntl(adns_qfd, F_SETFL, O_NONBLOCK);
	break;
    }
}

void
stop_adns(void)
{
    close_any(adns_qfd);
    adns_qfd = NULL_FD;
    close_any(adns_afd);
    adns_afd = NULL_FD;

    if (adns_pid != 0)
    {
	int status;
	pid_t p;

	sleep(1);
	p = waitpid(adns_pid, &status, WNOHANG);

	if (p == -1)
	{
	    log_errno((e, "waitpid for ADNS process failed"));

	    /* get rid of, it might be stuck */
	    kill(adns_pid, 15);
	}
	else if (WIFEXITED(status))
	{
	    if (WEXITSTATUS(status) != 0)
		openswan_log("ADNS process exited with status %d"
		    , (int) WEXITSTATUS(status));
	    adns_pid = 0;
	}
	else if (WIFSIGNALED(status))
	{
	    openswan_log("ADNS process terminated by signal %d", (int)WTERMSIG(status));
	    adns_pid = 0;
	}
	else
	{
	    openswan_log("wait for end of ADNS process returned odd status 0x%x\n"
		, status);
	    adns_pid = 0;
	}
    }
}



/* tricky macro to pass any hot potato */
#define TRY(x)	{ err_t ugh = x; if (ugh != NULL) return ugh; }


/* Process TXT X-IPsec-Server record, accumulating relevant ones
 * in cr->gateways_from_dns, a list sorted by "preference".
 *
 * Format of TXT record body: X-IPsec-Server ( nnn ) = iii kkk
 *  nnn is a 16-bit unsigned integer preference
 *  iii is @FQDN or dotted-decimal IPv4 address or colon-hex IPv6 address
 *  kkk is an optional RSA public signing key in base 64.
 *
 * NOTE: we've got to be very wary of anything we find -- bad guys
 * might have prepared it.
 */

#define our_TXT_attr_string "X-IPsec-Server"
static const char our_TXT_attr[] = our_TXT_attr_string;

static err_t
decode_iii(char **pp, struct id *gw_id)
{
    char *p = *pp + strspn(*pp, " \t");
    char *e = p + strcspn(p, " \t");
    char under = *e;

    if (p == e)
	return "TXT " our_TXT_attr_string " badly formed (no gateway specified)";

    *e = '\0';
    if (*p == '@')
    {
	/* gateway specification in this record is @FQDN */
	err_t ugh = atoid(p, gw_id, FALSE);

	if (ugh != NULL)
	    return builddiag("malformed FQDN in TXT " our_TXT_attr_string ": %s"
			     , ugh);
    }
    else
    {
	/* gateway specification is numeric */
	ip_address ip;
	err_t ugh = tnatoaddr(p, e-p
	    , strchr(p, ':') == NULL? AF_INET : AF_INET6
	    , &ip);

	if (ugh != NULL)
	    return builddiag("malformed IP address in TXT " our_TXT_attr_string ": %s"
		, ugh);

	if (isanyaddr(&ip))
	    return "gateway address must not be 0.0.0.0 or 0::0";

	iptoid(&ip, gw_id);
    }

    *e = under;
    *pp = e + strspn(e, " \t");

    return NULL;
}

static err_t
process_txt_rr_body(char *str
		    , bool doit	/* should we capture information? */
		    , enum dns_auth_level dns_auth_level
		    , struct adns_continuation *const cr)
{
    const struct id *client_id = &cr->id;	/* subject of query */
    char *p = str;
    unsigned long pref = 0;
    struct gw_info gi;

    p += strspn(p, " \t");	/* ignore leading whitespace */

    /* is this for us? */
    if (strncasecmp(p, our_TXT_attr, sizeof(our_TXT_attr)-1) != 0)
	return NULL;	/* neither interesting nor bad */

    p += sizeof(our_TXT_attr) - 1;	/* ignore our attribute name */
    p += strspn(p, " \t");	/* ignore leading whitespace */

    /* decode '(' nnn ')' */
    if (*p != '(')
	return "X-IPsec-Server missing '('";

    {
	char *e;

	p++;
	pref = strtoul(p, &e, 0);
	if (e == p)
	    return "malformed X-IPsec-Server priority";

	p = e + strspn(e, " \t");

	if (*p != ')')
	    return "X-IPsec-Server priority missing ')'";

	p++;
	p += strspn(p, " \t");

	if (pref > 0xFFFF)
	    return "X-IPsec-Server priority larger than 0xFFFF";
    }

    /* time for '=' */

    if (*p != '=')
	return "X-IPsec-Server priority missing '='";

    p++;
    p += strspn(p, " \t");

    /* Decode iii (Security Gateway ID). */

    zero(&gi);	/* before first use */

    TRY(decode_iii(&p, &gi.gw_id));	/* will need to unshare_id_content */

    if (!cr->sgw_specified)
    {
	/* we don't know the peer's ID (because we are initiating
	 * and we don't know who to initiate with.
	 * So we're looking for gateway specs with an IP address
	 */
	if (!id_is_ipaddr(&gi.gw_id))
	{
	    DBG(DBG_DNS,
		{
		    char cidb[IDTOA_BUF];
		    char gwidb[IDTOA_BUF];

		    idtoa(client_id, cidb, sizeof(cidb));
		    idtoa(&gi.gw_id, gwidb, sizeof(gwidb));
		    DBG_log("TXT %s record for %s: security gateway %s;"
			" ignored because gateway's IP is unspecified"
			, our_TXT_attr, cidb, gwidb);
		});
	    return NULL;	/* we cannot use this record, but it isn't wrong */
	}
    }
    else
    {
	/* We do know the peer's ID (because we are responding)
	 * So we're looking for gateway specs specifying this known ID.
	 */
	const struct id *peer_id = &cr->sgw_id;

	if (!same_id(peer_id, &gi.gw_id))
	{
	    DBG(DBG_DNS,
		{
		    char cidb[IDTOA_BUF];
		    char gwidb[IDTOA_BUF];
		    char pidb[IDTOA_BUF];

		    idtoa(client_id, cidb, sizeof(cidb));
		    idtoa(&gi.gw_id, gwidb, sizeof(gwidb));
		    idtoa(peer_id, pidb, sizeof(pidb));
		    DBG_log("TXT %s record for %s: security gateway %s;"
			" ignored -- looking to confirm %s as gateway"
			, our_TXT_attr, cidb, gwidb, pidb);
		});
	    return NULL;	/* we cannot use this record, but it isn't wrong */
	}
    }

    if (doit)
    {
	/* really accept gateway */
	struct gw_info **gwip;	/* gateway insertion point */

	gi.client_id = *client_id;	/* will need to unshare_id_content */

	/* decode optional kkk: base 64 encoding of key */

	gi.gw_key_present = *p != '\0';
	if (gi.gw_key_present)
	{
	    /* Decode base 64 encoding of key.
	     * Similar code is in process_lwdnsq_key.
	     */
	    u_char kb[RSA_MAX_ENCODING_BYTES];	/* plenty of space for binary form of public key */
	    chunk_t kbc;
	    struct RSA_public_key r;

	    err_t ugh = ttodatav(p, 0, 64, (char *)kb, sizeof(kb), &kbc.len
		, diag_space, sizeof(diag_space), TTODATAV_SPACECOUNTS);

	    if (ugh != NULL)
		return builddiag("malformed key data: %s", ugh);

	    if (kbc.len > sizeof(kb))
		return builddiag("key data larger than %lu bytes"
		    , (unsigned long) sizeof(kb));

	    kbc.ptr = kb;
	    ugh = unpack_RSA_public_key(&r, &kbc);
	    if (ugh != NULL)
		return builddiag("invalid key data: %s", ugh);

	    /* now find a key entry to put it in */
	    gi.key = public_key_from_rsa(&r);

	    free_RSA_public_content(&r);

	    unreference_key(&cr->last_info);
	    cr->last_info = reference_key(gi.key);
	}

	/* we're home free!  Allocate everything and add to gateways list. */
	gi.refcnt = 1;
	gi.pref = pref;
	gi.key->dns_auth_level = dns_auth_level;
	gi.key->last_tried_time = gi.key->last_worked_time = NO_TIME;

	/* find insertion point */
	for (gwip = &cr->gateways_from_dns; *gwip != NULL && (*gwip)->pref < pref; gwip = &(*gwip)->next)
	    ;

	DBG(DBG_DNS,
	    {
		char cidb[IDTOA_BUF];
		char gwidb[IDTOA_BUF];

		idtoa(client_id, cidb, sizeof(cidb));
		idtoa(&gi.gw_id, gwidb, sizeof(gwidb));
		if (gi.gw_key_present)
		{
		    DBG_log("gateway for %s is %s with key %s"
			, cidb, gwidb, gi.key->u.rsa.keyid);
		}
		else
		{
		    DBG_log("gateway for %s is %s; no key specified"
			, cidb, gwidb);
		}
	    });

	gi.next = *gwip;
	*gwip = clone_thing(gi, "gateway info");
	unshare_id_content(&(*gwip)->gw_id);
	unshare_id_content(&(*gwip)->client_id);
    }

    return NULL;
}

static const char *
rr_typename(int type)
{
    switch (type)
    {
    case ns_t_txt:
	return "TXT";
    case ns_t_key:
	return "KEY";
    case ns_t_a:
	return "A";
    case ns_t_aaaa:
	return "AAAA";
    default:
	return "???";
    }
}



/* structure of Query Reply (RFC 1035 4.1.1):
 *
 *  +---------------------+
 *  |        Header       |
 *  +---------------------+
 *  |       Question      | the question for the name server
 *  +---------------------+
 *  |        Answer       | RRs answering the question
 *  +---------------------+
 *  |      Authority      | RRs pointing toward an authority
 *  +---------------------+
 *  |      Additional     | RRs holding additional information
 *  +---------------------+
 */

/* Header section format (as modified by RFC 2535 6.1):
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                      ID                       |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    QDCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    ANCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    NSCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    ARCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
struct qr_header {
    u_int16_t	id;	/* 16-bit identifier to match query */

    u_int16_t	stuff;	/* packed crud: */

#define QRS_QR	0x8000	/* QR: on if this is a response */

#define QRS_OPCODE_SHIFT	11  /* OPCODE field */
#define QRS_OPCODE_MASK	0xF
#define QRSO_QUERY	0   /* standard query */
#define QRSO_IQUERY	1   /* inverse query */
#define QRSO_STATUS	2   /* server status request query */

#define QRS_AA 0x0400	/* AA: on if Authoritative Answer */
#define QRS_TC 0x0200	/* TC: on if truncation happened */
#define QRS_RD 0x0100	/* RD: on if recursion desired */
#define QRS_RA 0x0080	/* RA: on if recursion available */
#define QRS_Z  0x0040	/* Z: reserved; must be zero */
#define QRS_AD 0x0020	/* AD: on if authentic data (RFC 2535) */
#define QRS_CD 0x0010	/* AD: on if checking disabled (RFC 2535) */

#define QRS_RCODE_SHIFT	0 /* RCODE field: response code */
#define QRS_RCODE_MASK	0xF
#define QRSR_OK	    0


    u_int16_t qdcount;	    /* number of entries in question section */
    u_int16_t ancount;	    /* number of resource records in answer section */
    u_int16_t nscount;	    /* number of name server resource records in authority section */
    u_int16_t arcount;	    /* number of resource records in additional records section */
};

static field_desc qr_header_fields[] = {
    { ft_nat, BYTES_FOR_BITS(16), "ID", NULL },
    { ft_nat, BYTES_FOR_BITS(16), "stuff", NULL },
    { ft_nat, BYTES_FOR_BITS(16), "QD Count", NULL },
    { ft_nat, BYTES_FOR_BITS(16), "Answer Count", NULL },
    { ft_nat, BYTES_FOR_BITS(16), "Authority Count", NULL },
    { ft_nat, BYTES_FOR_BITS(16), "Additional Count", NULL },
    { ft_end, 0, NULL, NULL }
};

static struct_desc qr_header_desc = {
    "Query Response Header",
    qr_header_fields,
    sizeof(struct qr_header)
};

/* Messages for codes in RCODE (see RFC 1035 4.1.1) */
static const err_t rcode_text[QRS_RCODE_MASK + 1] = {
    NULL,   /* not an error */
    "Format error - The name server was unable to interpret the query",
    "Server failure - The name server was unable to process this query"
	" due to a problem with the name server",
    "Name Error - Meaningful only for responses from an authoritative name"
	" server, this code signifies that the domain name referenced in"
	" the query does not exist",
    "Not Implemented - The name server does not support the requested"
	" kind of query",
    "Refused - The name server refuses to perform the specified operation"
	" for policy reasons",
    /* the rest are reserved for future use */
    };

/* throw away a possibly compressed domain name */

static err_t
eat_name(pb_stream *pbs)
{
    char name_buf[NS_MAXDNAME + 2];
    u_char *ip = pbs->cur;
    unsigned oi = 0;
    unsigned jump_count = 0;

    for (;;)
    {
	u_int8_t b;

	if (ip >= pbs->roof)
	    return "ran out of message while skipping domain name";

	b = *ip++;
	if (jump_count == 0)
	    pbs->cur = ip;

	if (b == 0)
	    break;

	switch (b & 0xC0)
	{
	    case 0x00:
		/* we grab the next b characters */
		if (oi + b > NS_MAXDNAME)
		    return "domain name too long";

		if (pbs->roof - ip <= b)
		    return "domain name falls off end of message";

		if (oi != 0)
		    name_buf[oi++] = '.';

		memcpy(name_buf + oi, ip, b);
		oi += b;
		ip += b;
		if (jump_count == 0)
		    pbs->cur = ip;
		break;

	    case 0xC0:
		{
		    unsigned ix;

		    if (ip >= pbs->roof)
			return "ran out of message in middle of compressed domain name";

		    ix = ((b & ~0xC0u) << 8) | *ip++;
		    if (jump_count == 0)
			pbs->cur = ip;

		    if (ix >= pbs_room(pbs))
			return "impossible compressed domain name";

		    /* Avoid infinite loop.
		     * There can be no more jumps than there are bytes
		     * in the packet.  Not a tight limit, but good enough.
		     */
		    jump_count++;
		    if (jump_count > pbs_room(pbs))
			return "loop in compressed domain name";

		    ip = pbs->start + ix;
		}
		break;

	    default:
		return "invalid code in label";
	}
    }

    name_buf[oi++] = '\0';

    DBG(DBG_DNS, DBG_log("skipping name %s", name_buf));

    return NULL;
}

static err_t
eat_name_helpfully(pb_stream *pbs, const char *context)
{
    err_t ugh = eat_name(pbs);

    return ugh == NULL? ugh
	: builddiag("malformed name within DNS record of %s: %s", context, ugh);
}

/* non-variable part of 4.1.2 Question Section entry:
 *                                 1  1  1  1  1  1
 *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                                               |
 * /                     QNAME                     /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     QTYPE                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     QCLASS                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */

struct qs_fixed {
    u_int16_t qtype;
    u_int16_t qclass;
};

static field_desc qs_fixed_fields[] = {
    { ft_loose_enum, BYTES_FOR_BITS(16), "QTYPE", &rr_qtype_names },
    { ft_loose_enum, BYTES_FOR_BITS(16), "QCLASS", &rr_class_names },
    { ft_end, 0, NULL, NULL }
};

static struct_desc qs_fixed_desc = {
    "Question Section entry fixed part",
    qs_fixed_fields,
    sizeof(struct qs_fixed)
};

/* 4.1.3. Resource record format:
 *                                 1  1  1  1  1  1
 *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                                               |
 * /                                               /
 * /                      NAME                     /
 * |                                               |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      TYPE                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     CLASS                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      TTL                      |
 * |                                               |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                   RDLENGTH                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
 * /                     RDATA                     /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */

struct rr_fixed {
    u_int16_t type;
    u_int16_t class;
    u_int32_t ttl;	/* actually signed */
    u_int16_t rdlength;
};


static field_desc rr_fixed_fields[] = {
    { ft_loose_enum, BYTES_FOR_BITS(16), "type", &rr_type_names },
    { ft_loose_enum, BYTES_FOR_BITS(16), "class", &rr_class_names },
    { ft_nat, BYTES_FOR_BITS(32), "TTL", NULL },
    { ft_nat, BYTES_FOR_BITS(16), "RD length", NULL },
    { ft_end, 0, NULL, NULL }
};

static struct_desc rr_fixed_desc = {
    "Resource Record fixed part",
    rr_fixed_fields,
    /* note: following is tricky: avoids padding problems */
    offsetof(struct rr_fixed, rdlength) + sizeof(u_int16_t)
};

/* RFC 1035 3.3.14: TXT RRs have text in the RDATA field.
 * It is in the form of a sequence of <character-string>s as described in 3.3.
 * unpack_txt_rdata() deals with this peculiar representation.
 */

/* RFC 2535 3.1 KEY RDATA format:
 *
 *                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             flags             |    protocol   |   algorithm   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               /
 * /                          public key                           /
 * /                                                               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
 */

struct key_rdata {
    u_int16_t flags;
    u_int8_t protocol;
    u_int8_t algorithm;
};

static field_desc key_rdata_fields[] = {
    { ft_nat, BYTES_FOR_BITS(16), "flags", NULL },
    { ft_nat, BYTES_FOR_BITS(8), "protocol", NULL },
    { ft_nat, BYTES_FOR_BITS(8), "algorithm", NULL },
    { ft_end, 0, NULL, NULL }
};

static struct_desc key_rdata_desc = {
    "KEY RR RData fixed part",
    key_rdata_fields,
    sizeof(struct key_rdata)
};

/* RFC 2535 4.1 SIG RDATA format:
 *
 *                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        type covered           |  algorithm    |     labels    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         original TTL                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      signature expiration                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      signature inception                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            key  tag           |                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         signer's name         +
 * |                                                               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-/
 * /                                                               /
 * /                            signature                          /
 * /                                                               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct sig_rdata {
    u_int16_t type_covered;
    u_int8_t algorithm;
    u_int8_t labels;
    u_int32_t original_ttl;
    u_int32_t sig_expiration;
    u_int32_t sig_inception;
    u_int16_t key_tag;
};

static field_desc sig_rdata_fields[] = {
    { ft_nat, BYTES_FOR_BITS(16), "type_covered", NULL},
    { ft_nat, BYTES_FOR_BITS(8), "algorithm", NULL},
    { ft_nat, BYTES_FOR_BITS(8), "labels", NULL},
    { ft_nat, BYTES_FOR_BITS(32), "original ttl", NULL},
    { ft_nat, BYTES_FOR_BITS(32), "sig expiration", NULL},
    { ft_nat, BYTES_FOR_BITS(32), "sig inception", NULL},
    { ft_nat, BYTES_FOR_BITS(16), "key tag", NULL},
    { ft_end, 0, NULL, NULL }
};

static struct_desc sig_rdata_desc = {
    "SIG RR RData fixed part",
    sig_rdata_fields,
    sizeof(struct sig_rdata)
};

/* handle a KEY Resource Record. */

#ifdef USE_KEYRR
static err_t
process_key_rr(u_char *ptr, size_t len
, bool doit	/* should we capture information? */
, enum dns_auth_level dns_auth_level
, struct adns_continuation *const cr)
{
    pb_stream pbs;
    struct key_rdata kr;

    if (len < sizeof(struct key_rdata))
	return "KEY Resource Record's RD Length is too small";

    init_pbs(&pbs, ptr, len, "KEY RR");

    if (!in_struct(&kr, &key_rdata_desc, &pbs, NULL))
	return "failed to get fixed part of KEY Resource Record RDATA";

    if (kr.protocol == 4	/* IPSEC (RFC 2535 3.1.3) */
    && kr.algorithm == 1	/* RSA/MD5 (RFC 2535 3.2) */
    && (kr.flags & 0x8000) == 0	/* use for authentication (3.1.2) */
    && (kr.flags & 0x2CF0) == 0)	/* must be zero */
    {
	/* we have what seems to be a tasty key */

	if (doit)
	{
	    chunk_t k;

	    setchunk(k, pbs.cur, pbs_left(&pbs));
	    TRY(add_public_key(&cr->id, dns_auth_level, PUBKEY_ALG_RSA, &k
		, &cr->keys_from_dns));
	}
    }
    return NULL;
}
#endif /* USE_KEYRR */


/* unpack TXT rr RDATA into C string.
 * A sequence of <character-string>s as described in RFC 1035 3.3.
 * We concatenate them.
 */
static err_t
unpack_txt_rdata(char *d, size_t dlen, const u_char *s, size_t slen)
{
    size_t i = 0
	, o = 0;

    while (i < slen)
    {
	size_t cl = s[i++];

	if (i + cl > slen)
	    return "TXT rr RDATA representation malformed";

	if (o + cl >= dlen)
	    return "TXT rr RDATA too large";

	memcpy(d + o, s + i, cl);
	i += cl;
	o += cl;
    }
    d[o] = '\0';
    if (strlen((const char *)d) != o)
	return "TXT rr RDATA contains a NUL";

    return NULL;
}

static err_t
process_txt_rr(u_char *rdata, size_t rdlen
, bool doit	/* should we capture information? */
, enum dns_auth_level dns_auth_level
, struct adns_continuation *const cr)
{
    char str[RSA_MAX_ENCODING_BYTES * 8 / 6 + 200];	/* space for unpacked RDATA */

    TRY(unpack_txt_rdata(str, sizeof(str), rdata, rdlen));
    return process_txt_rr_body(str, doit, dns_auth_level, cr);
}

static err_t
process_answer_section(pb_stream *pbs
, bool doit	/* should we capture information? */
, enum dns_auth_level *dns_auth_level
, u_int16_t ancount	/* number of RRs in the answer section */
, struct adns_continuation *const cr)
{
    const int type = cr->query.type;	/* type of RR of interest */
    unsigned c;

    DBG(DBG_DNS, DBG_log("*Answer Section:"));

    for (c = 0; c != ancount; c++)
    {
	struct rr_fixed rrf;
	size_t tail;

	/* ??? do we need to match the name? */

	TRY(eat_name_helpfully(pbs, "Answer Section"));

	if (!in_struct(&rrf, &rr_fixed_desc, pbs, NULL))
	    return "failed to get fixed part of Answer Section Resource Record";

	if (rrf.rdlength > pbs_left(pbs))
	    return "RD Length extends beyond end of message";

	/* ??? should we care about ttl? */

	tail = rrf.rdlength;

	if (rrf.type == type && rrf.class == ns_c_in)
	{
	    err_t ugh = NULL;

	    switch (type)
	    {
#ifdef USE_KEYRR
	    case ns_t_key:
		ugh = process_key_rr(pbs->cur, tail, doit, *dns_auth_level, cr);
		break;
#endif /* USE_KEYRR */
	    case ns_t_txt:
		ugh = process_txt_rr(pbs->cur, tail, doit, *dns_auth_level, cr);
		break;
	    case ns_t_sig:
		/* Check if SIG RR authenticates what we are learning.
		 * The RRset covered by a SIG must have the same owner,
		 * class, and type.
		 * For us, the class is always C_IN, so that matches.
		 * We decode the SIG RR's fixed part to check
		 * that the type_covered field matches our query type
		 * (this may be redundant).
		 * We don't check the owner (apparently this is the
		 * name on the record) -- we assume that it matches
		 * or we would not have been given this SIG in the
		 * Answer Section.
		 *
		 * We only look on first pass, and only if we've something
		 * to learn.  This cuts down on useless decoding.
		 */
		if (!doit && *dns_auth_level == DAL_UNSIGNED)
		{
		    struct sig_rdata sr;

		    if (!in_struct(&sr, &sig_rdata_desc, pbs, NULL))
			ugh = "failed to get fixed part of SIG Resource Record RDATA";
		    else if (sr.type_covered == type)
			*dns_auth_level = DAL_SIGNED;
		}
		break;
	    default:
		ugh = builddiag("unexpected RR type %d", type);
		break;
	    }
	    if (ugh != NULL)
		return ugh;
	}
	in_raw(NULL, tail, pbs, "RR RDATA");
    }

    return doit
	&& cr->gateways_from_dns == NULL
#ifdef USE_KEYRR
	&& cr->keys_from_dns == NULL
#endif /* USE_KEYRR */
	? builddiag("no suitable %s record found in DNS", rr_typename(type))
	: NULL;
}

/* process DNS answer -- TXT or KEY query */

static err_t
process_dns_rr_answer(struct adns_continuation *const cr
                   , u_char ans[], int anslen)
{
    const int type = cr->query.type;	/* type of record being sought */
    int r;	/* all-purpose return value holder */
    u_int16_t c;	/* number of current RR in current answer section */
    pb_stream pbs;
    u_int8_t *ans_start;	/* saved position of answer section */
    struct qr_header qr_header;
    enum dns_auth_level dns_auth_level;

    init_pbs(&pbs, ans, anslen, "Query Response Message");

    /* decode and check header */

    if (!in_struct(&qr_header, &qr_header_desc, &pbs, NULL))
	return "malformed header";

    /* ID: nothing to do with us */

    /* stuff -- lots of things */
    if ((qr_header.stuff & QRS_QR) == 0)
	return "not a response?!?";

    if (((qr_header.stuff >> QRS_OPCODE_SHIFT) & QRS_OPCODE_MASK) != QRSO_QUERY)
	return "unexpected opcode";

    /* I don't think we care about AA */

    if (qr_header.stuff & QRS_TC)
	return "response truncated";

    /* I don't think we care about RD, RA, or CD */

    /* AD means "authentic data" */
    dns_auth_level = qr_header.stuff & QRS_AD? DAL_UNSIGNED : DAL_NOTSEC;

    if (qr_header.stuff & QRS_Z)
	return "Z bit is not zero";

    r = (qr_header.stuff >> QRS_RCODE_SHIFT) & QRS_RCODE_MASK;
    if (r != 0)
	return r < (int)elemsof(rcode_text)? rcode_text[r] : "unknown rcode";

    if (qr_header.ancount == 0)
	return builddiag("no %s RR found by DNS", rr_typename(type));

    /* end of header checking */

    /* Question Section processing */

    /* 4.1.2. Question section format:
     *                                 1  1  1  1  1  1
     *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
     * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     * |                                               |
     * /                     QNAME                     /
     * /                                               /
     * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     * |                     QTYPE                     |
     * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     * |                     QCLASS                    |
     * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     */

    DBG(DBG_DNS, DBG_log("*Question Section:"));

    for (c = 0; c != qr_header.qdcount; c++)
    {
	struct qs_fixed qsf;

	TRY(eat_name_helpfully(&pbs, "Question Section"));

	if (!in_struct(&qsf, &qs_fixed_desc, &pbs, NULL))
	    return "failed to get fixed part of Question Section";

	if (qsf.qtype != type)
	    return "unexpected QTYPE in Question Section";

	if (qsf.qclass != ns_c_in)
	    return "unexpected QCLASS in Question Section";
    }

    /* rest of sections are made up of Resource Records */

    /* Answer Section processing -- error checking, noting T_SIG */

    ans_start = pbs.cur;	/* remember start of answer section */

    TRY(process_answer_section(&pbs, FALSE, &dns_auth_level
	, qr_header.ancount, cr));

    /* Authority Section processing (just sanity checking) */

    DBG(DBG_DNS, DBG_log("*Authority Section:"));

    for (c = 0; c != qr_header.nscount; c++)
    {
	struct rr_fixed rrf;
	size_t tail;

	TRY(eat_name_helpfully(&pbs, "Authority Section"));

	if (!in_struct(&rrf, &rr_fixed_desc, &pbs, NULL))
	    return "failed to get fixed part of Authority Section Resource Record";

	if (rrf.rdlength > pbs_left(&pbs))
	    return "RD Length extends beyond end of message";

	/* ??? should we care about ttl? */

	tail = rrf.rdlength;

	in_raw(NULL, tail, &pbs, "RR RDATA");
    }

    /* Additional Section processing (just sanity checking) */

    DBG(DBG_DNS, DBG_log("*Additional Section:"));

    for (c = 0; c != qr_header.arcount; c++)
    {
	struct rr_fixed rrf;
	size_t tail;

	TRY(eat_name_helpfully(&pbs, "Additional Section"));

	if (!in_struct(&rrf, &rr_fixed_desc, &pbs, NULL))
	    return "failed to get fixed part of Additional Section Resource Record";

	if (rrf.rdlength > pbs_left(&pbs))
	    return "RD Length extends beyond end of message";

	/* ??? should we care about ttl? */

	tail = rrf.rdlength;

	in_raw(NULL, tail, &pbs, "RR RDATA");
    }

    /* done all sections */

    /* ??? is padding legal, or can we complain if more left in record? */

    /* process Answer Section again -- accept contents */

    pbs.cur = ans_start;	/* go back to start of answer section */

    return process_answer_section(&pbs, TRUE, &dns_auth_level
	, qr_header.ancount, cr);
}

/*
 * Note: this could be done with getaddrinfo_a(), but before involving
 * pluto main in dns requests, need to change the key/txt(ipseckey)
 * lookups to work with that, and getaddrinfo_a() uses threads!
 */
static err_t
process_dns_sockaddr_answer(struct adns_continuation *const cr
                            , u_char ans[], int anslen)
{
    /* unserialize the results from the ans buffer */
    /* serialize/unserialize routine is at top of adns.c */
    cr->ipanswers = deserialize_addr_info(ans, anslen);
    return NULL;
}

static err_t
process_dns_answer(struct adns_continuation *const cr
                   , u_char ans[], int anslen)
{
    switch(cr->type) {
    case ns_t_txt:
    case ns_t_key:
        /* raw DNS reply */
        return process_dns_rr_answer(cr, ans, anslen);

    case ns_t_a:
        /* cooked getaddrinfo reply, ans contains a bunch of sockaddr */
        return process_dns_sockaddr_answer(cr, ans, anslen);

    default:
        return "not A, TXT or KEY query";
    }
}


/****************************************************************/

static err_t
build_dns_name(char name_buf[NS_MAXDNAME + 2]
	       , unsigned long serial USED_BY_DEBUG
	       , const struct id *id
	       , const char *typename USED_BY_DEBUG
	       , const char *gwname   USED_BY_DEBUG)
{
    /* note: all end in "." to suppress relative searches */
    id = resolve_myid(id);
    switch (id->kind)
    {
    case ID_IPV4_ADDR:
    {
	/* XXX: this is really ugly and only temporary until addrtot can
	 *      generate the correct format
	 */
	unsigned char *b;
	size_t bl USED_BY_DEBUG = addrbytesptr(&id->ip_addr, &b);

	passert(bl == 4);
	snprintf(name_buf, NS_MAXDNAME + 2, "%d.%d.%d.%d.in-addr.arpa."
		 , b[3], b[2], b[1], b[0]);
	break;
    }

    case ID_IPV6_ADDR:
    {
	/* ??? is this correct? */
	unsigned char *b;
	size_t bl;
	char *op = name_buf;
	static const char suffix[] = "IP6.INT.";

	for (bl = addrbytesptr(&id->ip_addr, &b); bl-- != 0; )
	{
	    if (op + 4 + sizeof(suffix) >= name_buf + NS_MAXDNAME + 1)
		return "IPv6 reverse name too long";
	    op += sprintf(op, "%x.%x.", b[bl] & 0xF, b[bl] >> 4);
	}
	strcpy(op, suffix);
	break;
    }

    case ID_FQDN:
	/* strip trailing "." characters, then add one */
	{
	    size_t il = id->name.len;

	    while (il > 0 && id->name.ptr[il - 1] == '.')
		il--;
	    if (il > NS_MAXDNAME)
		return "FQDN too long for domain name";

	    memcpy(name_buf, id->name.ptr, il);
	    strcpy(name_buf + il, ".");
	}
	break;

    default:
	return "can only query DNS for key for ID that is a FQDN, IPV4_ADDR, or IPV6_ADDR";
    }

    DBG(DBG_CONTROL | DBG_DNS, DBG_log("DNS query %lu for %s for %s (gw: %s)"
	, serial, typename, name_buf, gwname));
    return NULL;
}

void
gw_addref(struct gw_info *gw)
{
    if (gw != NULL)
    {
	DBG(DBG_DNS, DBG_log("gw_addref: %p refcnt: %d++", gw, gw->refcnt))
	gw->refcnt++;
    }
}

void
gw_delref(struct gw_info **gwp)
{
    struct gw_info *gw = *gwp;

    if (gw != NULL)
    {
	DBG(DBG_DNS, DBG_log("gw_delref: %p refcnt: %d--", gw, gw->refcnt));

	passert(gw->refcnt != 0);
	gw->refcnt--;
	if (gw->refcnt == 0)
	{
	    free_id_content(&gw->client_id);
	    free_id_content(&gw->gw_id);
	    if (gw->gw_key_present)
		unreference_key(&gw->key);
	    gw_delref(&gw->next);
	    pfree(gw);	/* trickery could make this a tail-call */
	}
	*gwp = NULL;
    }
}

/* Start an asynchronous DNS query.
 *
 * For KEY record, the result will be a list in cr->keys_from_dns.
 * For TXT records, the result will be a list in cr->gateways_from_dns.
 *
 * If sgw_id is null, only consider TXT records that specify an
 * IP address for the gatway: we need this in the initiation case.
 *
 * If sgw_id is non-null, only consider TXT records that specify
 * this id as the security gatway; this is useful to the Responder
 * for confirming claims of gateways.
 *
 * Continuation cr gives information for continuing when the result shows up.
 *
 * Two kinds of errors must be handled: synchronous (immediate)
 * and asynchronous.  Synchronous errors are indicated by the returned
 * value of start_adns_query; in this case, the continuation will
 * have been freed and the continuation routine will not be called.
 * Asynchronous errors are indicated by the ugh parameter passed to the
 * continuation routine.
 *
 * After the continuation routine has completed, handle_adns_answer
 * will free the continuation.  The continuation routine should have
 * freed any axiliary resources.
 *
 * Note: in the synchronous error case, start_adns_query will have
 * freed the continuation; this means that the caller will have to
 * be very careful to release any auxiliary resources that were in
 * the continuation record without using the continuation record.
 *
 * Either there will be an error result passed to the continuation routine,
 * or the results will be in cr->keys_from_dns or cr->gateways_from_dns.
 * The result variables must by left NULL by the continutation routine.
 * The continuation routine is responsible for establishing and
 * disestablishing any logging context (whack_log_fd, cur_*).
 */

static struct adns_continuation *continuations = NULL;	/* newest of queue */
static struct adns_continuation *next_query = NULL;	/* oldest not sent */

static struct adns_continuation *
continuation_for_qtid(unsigned long qtid)
{
    struct adns_continuation *cr = NULL;

    if (qtid != 0)
	for (cr = continuations; cr != NULL && cr->qtid != qtid; cr = cr->previous)
	    ;
    return cr;
}

static void
release_adns_continuation(struct adns_continuation *cr)
{
    gw_delref(&cr->gateways_from_dns);
#ifdef USE_KEYRR
    free_public_keys(&cr->keys_from_dns);
#endif /* USE_KEYRR */
    unreference_key(&cr->last_info);
    unshare_id_content(&cr->id);
    unshare_id_content(&cr->sgw_id);

    /* unlink from doubly-linked list */
    if (cr->next == NULL)
    {
	passert(continuations == cr);
	continuations = cr->previous;
    }
    else
    {
	passert(cr->next->previous == cr);
	cr->next->previous = cr->previous;
    }

    if (cr->previous != NULL)
    {
	passert(cr->previous->next == cr);
	cr->previous->next = cr->next;
    }

    if(cr->ipanswers != NULL) {
        osw_freeaddrinfo(cr->ipanswers);
    }

    pfree(cr);
}

static void
release_all_continuations()
{
    struct adns_continuation *cr = NULL;
    struct adns_continuation *crnext;
    int num_released = 0;

    for(cr = continuations; cr != NULL; cr = crnext) {
	crnext = cr->previous;

	cr->cont_fn(cr, "no results returned by lwdnsq");
	release_adns_continuation(cr);
	num_released++;
    }

    DBG_log("release_all_cnt: released %d, %d in flight => %d\n",
	    num_released, adns_in_flight,  adns_in_flight-num_released);

    adns_in_flight-=num_released;
}

static void init_generic_adns_query(struct adns_continuation *cr)
{
    if(adns_pid == 0
    && adns_restart_count < ADNS_RESTART_MAX)
    {
	openswan_log("ADNS helper was not running. Restarting attempt %d",adns_restart_count);
	init_adns();
    }


    /* Splice this in at head of doubly-linked list of continuations.
     * Note: this must be done before any release_adns_continuation().
     */
    cr->next = NULL;
    cr->previous = continuations;
    if (continuations != NULL)
    {
	passert(continuations->next == NULL);
	continuations->next = cr;
    }
    continuations = cr;
}

/* type: T_TXT or T_KEY, selecting rr type of interest */
static void start_generic_adns_query(int type
                                     , struct adns_continuation *cr
                                     , sa_family_t addr_family)
{
    static unsigned long qtid = 1;	/* query transaction id; NOTE: static */

    cr->query.addr_family = addr_family;
    cr->qtid = qtid++;
    cr->type = type;
    cr->gateways_from_dns = NULL;
#ifdef USE_KEYRR
    cr->keys_from_dns = NULL;
#endif /* USE_KEYRR */

#ifdef DEBUG
    cr->debugging = cur_debugging;
#else
    cr->debugging = LEMPTY;
#endif

    if (next_query == NULL)
	next_query = cr;

    unsent_ADNS_queries = TRUE;
}

err_t
start_adns_query(const struct id *id	/* domain to query */
                 , const struct id *sgw_id	/* if non-null, any accepted gw_info must match */
                 , int type	/* T_TXT or T_KEY, selecting rr type of interest */
                 , cont_fn_t cont_fn
                 , struct adns_continuation *cr)
{
    char gwidb[IDTOA_BUF];
    const char *typename = rr_typename(type);

    /* link it in so it's all sane */
    init_generic_adns_query(cr);

    cr->cont_fn = cont_fn;
    cr->id = *id;
    unshare_id_content(&cr->id);
    cr->sgw_specified = sgw_id != NULL;
    cr->sgw_id = cr->sgw_specified? *sgw_id : empty_id;
    unshare_id_content(&cr->sgw_id);
    idtoa(&cr->sgw_id, gwidb, sizeof(gwidb));

    zero(&cr->query);

    start_generic_adns_query(type, cr, AF_UNSPEC);
    {
	err_t ugh = build_dns_name(cr->query.name_buf, cr->qtid
				   , id, typename, gwidb);

	if (ugh != NULL)
	{
	    release_adns_continuation(cr);
	    return ugh;
	}
    }

    return NULL;
}

err_t
start_adns_hostname(sa_family_t addr_family
                    , const char *hostname
                    , cont_fn_t cont_fn
                    , struct adns_continuation *cr)
{
    /* link it in so it's all sane */
    init_generic_adns_query(cr);

    cr->cont_fn = cont_fn;
    cr->id.kind = ID_FQDN;
    strtochunk(cr->id.name, hostname, "adns hostname");
    zero(&cr->query);

    {
	err_t ugh = build_dns_name(cr->query.name_buf, cr->qtid
				   , &cr->id, "host", "none");

	if (ugh != NULL)
	{
	    release_adns_continuation(cr);
	    return ugh;
	}
    }

    start_generic_adns_query(ns_t_a, cr, addr_family);

    return NULL;
}

/* send remaining ADNS queries (until pipe full or none left)
 *
 * This is a co-routine, so it uses static variables to
 * preserve state across calls.
 */
bool unsent_ADNS_queries = FALSE;

void
send_unsent_ADNS_queries(void)
{
    static const char *buf_end = NULL;	/* NOTE STATIC */
    static const char *buf_cur = NULL;	/* NOTE STATIC */

    if (adns_qfd == NULL_FD)
	return;	/* nothing useful to do */

    for (;;)
    {
	if (buf_cur != buf_end)
	{
	    static int try = 0;	/* NOTE STATIC */
	    size_t n = buf_end - buf_cur;
	    ssize_t r = write(adns_qfd, buf_cur, n);

	    if (r == -1)
	    {
		switch (errno)
		{
		case EINTR:
		    continue;	/* try again now */
		case EAGAIN:
		    DBG(DBG_DNS, DBG_log("EAGAIN writing to ADNS"));
		    break;	/* try again later */
		default:
		    try++;
		    log_errno((e, "error %d writing DNS query", try));
		    break;	/* try again later */
		}
		unsent_ADNS_queries = TRUE;
		break;	/* done! */
	    }
	    else
	    {
		passert(r >= 0);
		try = 0;
		buf_cur += r;
	    }
	}
	else
	{
	    if (next_query == NULL)
	    {
		unsent_ADNS_queries = FALSE;
		break;	/* done! */
	    }

	    next_query->query.debugging = next_query->debugging;
	    next_query->query.serial = next_query->qtid;
	    next_query->query.len = sizeof(next_query->query);
	    next_query->query.qmagic = ADNS_Q_MAGIC;
	    next_query->query.type = next_query->type;
	    buf_cur = (const void *)&next_query->query;
	    buf_end = buf_cur + sizeof(next_query->query);
	    next_query = next_query->next;
	    adns_in_flight++;
	}
    }
}


static void
recover_adns_die(void)
{
    struct adns_continuation *cr = NULL;

    adns_pid = 0;
    if(adns_restart_count < ADNS_RESTART_MAX) {
	adns_restart_count++;

	/* next DNS query will restart it */

	/* we have to walk the list of the outstanding requests,
	 * and redo them!
	 */

	cr = continuations;

	/* find the head of the list */
	if(continuations != NULL) {
	    for (; cr->previous != NULL; cr = cr->previous);
	}

	next_query = cr;

	if(next_query != NULL) {
	    unsent_ADNS_queries = TRUE;
	}
    }
}

void reset_adns_restart_count(void)
{
    adns_restart_count=0;
}

bool adns_any_in_flight(void)
{
    return adns_in_flight > 0;
}

void
handle_adns_answer(void)
{
  /* These are retained across calls to handle_adns_answer. */
    static size_t buflen = 0;	/* bytes in answer buffer */
    static struct adns_answer buf;

    ssize_t n;

    passert(buflen < sizeof(buf));
    n = read(adns_afd, (unsigned char *)&buf + buflen, sizeof(buf) - buflen);

    if (n < 0)
    {
	if (errno != EINTR)
	{
	    log_errno((e, "error reading answer from adns"));
	    /* ??? how can we recover? */
	}
	n = 0;	/* now n reflects amount read */
    }
    else if (n == 0)
    {
	/* EOF */
	if (adns_in_flight != 0)
	{
	    openswan_log("EOF from ADNS with %d queries outstanding (restarts %d)"
		 , adns_in_flight, adns_restart_count);
	    recover_adns_die();
	}
	if (buflen != 0)
	{
	    openswan_log("EOF from ADNS with %lu bytes of a partial answer outstanding"
		 "(restarts %d)"
		 , (unsigned long)buflen
		 ,  adns_restart_count);
	    recover_adns_die();
	}
	stop_adns();
	return;
    }
    else
    {
	passert(adns_in_flight > 0);
    }

    buflen += n;
    while (buflen >= offsetof(struct adns_answer, ans) && buflen >= buf.len)
    {
	/* we've got a tasty answer -- process it */
	err_t ugh;
	struct adns_continuation *cr = continuation_for_qtid(buf.serial);	/* assume it works */
	const char *typename = rr_typename(cr->query.type);
	const char *name_buf = cr->query.name_buf;

#ifdef USE_KEYRR
	passert(cr->keys_from_dns == NULL);
#endif /* USE_KEYRR */
	passert(cr->gateways_from_dns == NULL);
	adns_in_flight--;
	if (buf.result == -1)
	{
	    /* newer resolvers support statp->res_h_errno as well as h_errno.
	     * That might be better, but older resolvers don't.
	     * See resolver(3), if you have it.
	     * The undocumented(!) h_errno values are defined in
	     * /usr/include/netdb.h.
	     */
	    switch (buf.h_errno_val)
	    {
            case EAI_NODATA:
		ugh = builddiag("no %s record for %s", typename, name_buf);
		break;
            case EAI_NONAME:
		ugh = builddiag("no host %s for %s record", name_buf, typename);
		break;
	    default:
		ugh = builddiag("failure querying DNS for %s of %s: %s"
		    , typename, name_buf, gai_strerror(buf.h_errno_val));
		break;
	    }
	}
	else if (buf.result > (int) sizeof(buf.ans))
	{
	    ugh = builddiag("(INTERNAL ERROR) answer too long (%ld) for buffer"
		, (long)buf.result);
	}
	else
	{
	    ugh = process_dns_answer(cr, buf.ans, buf.result);
	    if (ugh != NULL)
		ugh = builddiag("failure processing %s record of DNS answer for %s: %s"
		    , typename, name_buf, ugh);
	}
	DBG(DBG_RAW | DBG_CRYPT | DBG_PARSING | DBG_CONTROL | DBG_DNS,
	    if (ugh == NULL)
		DBG_log("async DNS answer %lu for %s of %s"
		    , cr->query.serial, typename, name_buf);
	    else
		DBG_log("async DNS answer %lu %s", cr->query.serial, ugh);
	    );

	passert(GLOBALS_ARE_RESET());
	cr->cont_fn(cr, ugh);
	reset_globals();
	release_adns_continuation(cr);

	/* shift out answer that we've consumed */
	buflen -= buf.len;
	memmove((unsigned char *)&buf, (unsigned char *)&buf + buf.len, buflen);
    }
}

/*
 * this routing picks a new DNS result, or if there are none, performs
 * a new DNS lookup, in an attempt to find a useable peer address.
 *
 * Ideally, one would try all the addresses for *SELF* and also for *REMOTE*
 * as this gets around BCP38 filtering, and is what RFC3484 says we should do.
 *
 * Return true if there was a change that can be acted on now.
 *
 * Blacklist reserved IPs addresses (including loopback) and multicast addresses.
 * Treat them as if no DNS answer was available.
 *
 */
static bool advance_end_dns_list(struct connection *c
                          , struct end *end)
{
    unsigned int len = sizeof(end->host_addr);
    struct addrinfo *ai = end->host_address_list.next_address;
    char newaddr[ADDRTOT_BUF];
    bool valid = FALSE;

    /* try next address in the list */
    if(ai == NULL) return FALSE;

    /* see if next address is valid */
    switch(ai->ai_family) {
    case AF_INET:
        {
            struct sockaddr_in *ai4 = (struct sockaddr_in *)ai->ai_addr;
            const unsigned char *bytes = (unsigned char *)&ai4->sin_addr.s_addr;
            char addrbuf[ADDRTOT_BUF];
            inet_ntop(AF_INET, bytes, addrbuf, ADDRTOT_BUF);

            if(bytes[0] == 127) {
                /* loopback addresses not allowed */
                openswan_log("DNS lookup for '%s' rejected address %s: loopback address"
                            , end->host_addr_name, addrbuf);
                valid = FALSE;
            } else if(bytes[0] > 224 && bytes[0] <= 239) {
                /* multicast addresses now allowed, but maybe class E permitted */
                openswan_log("DNS lookup for '%s' rejected address %s: multicast address"
                            , end->host_addr_name, addrbuf);
                valid = FALSE;
            } else if(bytes[0] == 255) {
                /* 255/8 is reserved */
                openswan_log("DNS lookup for '%s' rejected rejected address %s: 255/8 is reserved"
                            , end->host_addr_name, addrbuf);
                valid = FALSE;
            } else if(bytes[0] == 0) {
                /* 0/8 is reserved */
                openswan_log("DNS lookup for '%s' rejected address %s: 0/8 is reserved"
                            , end->host_addr_name, addrbuf);
                valid = FALSE;
            } else {
                valid = TRUE;
            }
        }
        break;
    case AF_INET6:
        {
            struct sockaddr_in6 *ai6 = (struct sockaddr_in6 *)ai->ai_addr;
            const unsigned char *bytes = ai6->sin6_addr.s6_addr;
            char addrbuf[ADDRTOT_BUF];
            inet_ntop(AF_INET6, bytes, addrbuf, ADDRTOT_BUF);

            /* see https://tools.ietf.org/html/rfc4291 */
            if(bytes[0] == 0 && bytes[1] == 0 && bytes[2]==0 && bytes[3]==0
               && bytes[4] == 0 && bytes[5] == 0 && bytes[6]==0 && bytes[7]==0
               && bytes[8] == 0 && bytes[9] == 0 && bytes[10]==0 && bytes[11]==0
               && bytes[12]== 0 && bytes[13]== 0 && bytes[14]==0) {

                /* section 2.5.2, and 2.5.3 */
                /* loopback addresses ::1 and unspecified ::, and all of ::/120 */
                openswan_log("DNS lookup for '%s' rejected address %s: loopback address"
                            , end->host_addr_name, addrbuf);
                valid = FALSE;
            } else if(bytes[0] == 0 && bytes[1] == 0 && bytes[2]==0 && bytes[3]==0
                      && bytes[4] == 0 && bytes[5] == 0 && bytes[6]==0 && bytes[7]==0
                      && bytes[8] == 0 && bytes[9] == 0 && bytes[10]==0 && bytes[11]==0) {

                /* section 2.5.5.1: IPv4 compatible IPv6 addresses, e.g.  ::1.2.3.4 */
                openswan_log("DNS lookup for '%s' rejected address %s: IPv4-compatible IPv6 address"
                            , end->host_addr_name, addrbuf);
                valid = FALSE;
            } else if(bytes[0] == 0 && bytes[1] == 0 && bytes[2]==0 && bytes[3]==0
                      && bytes[4] == 0 && bytes[5] == 0 && bytes[6]==0 && bytes[7]==0
                      && bytes[8] == 0 && bytes[9] == 0 && bytes[10]==0xff && bytes[11]==0xff) {

                /* section 2.5.5.6: IPv4-mapped IPv6 addresses, e.g.  ::ffff:1.2.3.4 */
                /* XXX rejected for now: could become IPv4 address */
                openswan_log("DNS lookup for '%s' rejected address %s: IPv4-mapped IPv6 address"
                            , end->host_addr_name, addrbuf);
                valid = FALSE;
            } else if(bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80) {
                /* section 2.5.6: Link-Local addresses 0b1111 1110 10, fe80::/10 */
                /* XXX rejected for now --- attack vector */
                openswan_log("DNS lookup for '%s' rejected address %s: Link Local address returned"
                            , end->host_addr_name, addrbuf);
                valid = FALSE;
            } else if(bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0xc0) {
                /* section 2.5.7: Site-Local addresses 0b1111 1110 11, fec0::/10 */
                /* warned for now -- might be attack vector */
                openswan_log("DNS lookup for '%s' found address %s: Site Local address returned (okay)"
                            , end->host_addr_name, addrbuf);
                valid = FALSE;
            } else if(bytes[0] == 0xff && (bytes[1] & 0xc0) == 0xc0) {
                /* section 2.7: Multicast addresses 0b1111 1111, ff00::/8 */
                /* rejected */
                openswan_log("DNS lookup for '%s' found address %s: multicast address returned"
                            , end->host_addr_name, addrbuf);
                valid = FALSE;
            } else {
                valid = TRUE;
            }
        }
        break;

    default:
        /* protect against future IP protocols...*/
        valid = FALSE;
        break;
    }

    if(valid) {
        /* copy the address into the host_addr structure, and kick this conn */
        /* structures are not identically names, but equivalent; both contain sockaddr */
        if(len > ai->ai_addrlen) len = ai->ai_addrlen;
        memcpy(&end->host_addr, ai->ai_addr, len);
        end->host_address_list.addresses_available = TRUE;

        addrtot(&end->host_addr, 0, newaddr, sizeof(newaddr));
        DBG(DBG_DNS
            , DBG_log("advancing DNS to: %s (next: %s)", newaddr, ai->ai_next ? "more":"last"));
        if(update_host_pairs(c) == FALSE) {
            valid = FALSE;
        }
    }

    /* advance pointer, we consumed something, maybe valid */
    end->host_address_list.next_address = ai->ai_next;

    return valid;
}

static void reset_end_dns_list(struct dns_end_list *del)
{
    del->next_address = del->address_list;
}

void iphostname_continuation(struct adns_continuation *cr, err_t ugh)
{
    struct iphostname_continuation *iph_c = (struct iphostname_continuation *)cr;
    struct addrinfo *ai;

    DBG(DBG_DNS
        , DBG_log("iphostname_continuation: %s %s", iph_c->c->name
                  , ugh ? ugh : "no-error"));
    if(ugh) {
        loglog(RC_NOPEERIP, "iphostname error: %s", ugh);
        /* continuation is freed by dnskey */
        return;
    }
    ai = cr->ipanswers;
    if(sort_dns_answers) {
        ai = sort_addr_info(ai);
    }
    dump_addr_info(ai);

    /* now move results to connection structure */
    iph_c->c->spd.that.host_address_list.address_list = ai;
    reset_end_dns_list(&iph_c->c->spd.that.host_address_list);
    iph_c->ac.ipanswers = NULL;

    kick_adns_connection(iph_c->c, ugh);
}

/*
 * sort addrinfo structures.
 * this is useful when doing regression tests where gai.conf might differ
 * and is otherwise stupid.
 */
static int ai_compare(const void *a, const void *b, void *arg UNUSED)
{
    const struct addrinfo * const *aip;
    const struct addrinfo * const *bip;
    const struct addrinfo *ai,*bi;
    aip = a; ai = *aip;
    bip = b; bi = *bip;
    if(!ai->ai_addr) return -1;
    if(!bi->ai_addr) return -1;
    if(ai->ai_addrlen < bi->ai_addrlen) return -1;
    if(ai->ai_addrlen > bi->ai_addrlen) return 1;
    return memcmp(ai->ai_addr, bi->ai_addr, ai->ai_addrlen);
}

struct addrinfo *sort_addr_info(struct addrinfo *ai)
{
    int ai_count, i;
    struct addrinfo *ai1;
    struct addrinfo **array;

    /* first figure out how many there are */
    for(ai_count=0,ai1 = ai; ai1 != NULL; ai1=ai1->ai_next, ai_count++);

    /* now make an array */
    array = (struct addrinfo **)alloca(sizeof(struct addrinfo *)*ai_count);
    for(i=0,ai1 = ai; ai1 != NULL; ai1=ai1->ai_next, i++) {
        array[i] = ai1;
    }

    /* now sort it */
    qsort_r(array, ai_count, sizeof(struct addrinfo *), ai_compare, NULL);

    /* now put them back into the linked list */
    ai = array[0];
    if(ai_count > 1) {
        for(i=0; i < ai_count-1; i++) {
            array[i]->ai_next = array[i+1];
        }
    }
    array[ai_count-1]->ai_next = NULL;

    return ai;
}

void dump_addr_info(struct addrinfo *ans)
{
    unsigned int ansnum = 0;

    while(ans) {
        char addrbuf[ADDRTOT_BUF];
        DBG_log("ans %03u canonname=%s protocol=%u family=%u len=%u\n"
               , ansnum, ans->ai_canonname, ans->ai_protocol, ans->ai_family, ans->ai_addrlen);
        if(ans->ai_addrlen && ans->ai_addr) {
            sin_addrtot(ans->ai_addr, 0, addrbuf, sizeof(addrbuf));
            DBG_log("        result=%s\n", addrbuf);
        }

        ans = ans->ai_next;
        ansnum++;
    }
}


bool kick_adns_connection_lookup(struct connection *c
                                 , struct end *end
                                 , bool newlookup)
{
    struct iphostname_continuation *iph_c;

    err_t e;
    bool valid = FALSE;

    /* first look for a new IP address to try: see if there a new one. */
    /* if some addresses found, and not at end of list */
    while(valid == FALSE
          && end->host_address_list.address_list != NULL
          && end->host_address_list.next_address != NULL) {

        /*
         * try all the addresses: we may fail on some due to address type,
         * or address family that can not be oriented.
         */
        valid = advance_end_dns_list(c, end);
        if(valid) return TRUE;
    }

    if(!newlookup) {
        return FALSE;
    }

    /*
     * no new address to try, schedule a new DNS lookup.
     * do not initiate the lookup immediately, because it leads to continuous
     * DNS lookup loops.
     * In the meantime, also reset the pointer to beginning, if there are
     * any items to find.
     */
    iph_c = alloc_thing(struct iphostname_continuation, "kick adns");
    iph_c->c = c;
    e = start_adns_hostname(c->addr_family, end->host_addr_name,
                            iphostname_continuation, &iph_c->ac);

    if(e) {
        openswan_log("failed to initiate DNS lookup on %s: %s", end->host_addr_name, e);
        return FALSE;
    }
    reset_end_dns_list(&end->host_address_list);
    return advance_end_dns_list(c, end);
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
