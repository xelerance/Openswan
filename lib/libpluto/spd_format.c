/* information about connections between hosts and clients
 *
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009-2010 Avesh Agarwal <avagarwa@redhat.com>
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
 */

#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <resolv.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>
#include "openswan/pfkeyv2.h"

#include "sysdep.h"
#include "constants.h"
#include "oswalloc.h"
#include "oswtime.h"
#include "oswlog.h"
#include "id.h"
#include "pluto/x509lists.h"
#include "certs.h"
#include "secrets.h"

#include "pluto/defs.h"
#include "ac.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "pluto/connections.h"	/* needs id.h */
#include "pluto/virtual.h"	/* needs id.h */

/* Format the topology of a connection end, leaving out defaults.
 * Largest left end looks like: client === host : port [ host_id ] --- hop
 * Note: if that==NULL, skip nexthop
 * Returns strlen of formated result (length excludes NUL at end).
 */
size_t
format_end(char *buf
	   , size_t buf_len
	   , const struct end *this
	   , const struct end *that
	   , bool is_left
	   , lset_t policy)
{
    char client[SUBNETTOT_BUF];
    const char *client_sep = "";
    char protoport[sizeof(":255/65535")];
    const char *host = NULL;
    char host_space[ADDRTOT_BUF+256]; /* if you change this, see below */
    bool dohost_name = FALSE;
    char host_port[sizeof(":65535")];
    char host_id[IDTOA_BUF + 2];
    char hop[ADDRTOT_BUF];
    char endopts[sizeof("MS+MC+XS+XC+Sxx")+1];
    const char *hop_sep = "";
    const char *open_brackets  = "";
    const char *close_brackets = "";
    const char *id_obrackets = "";
    const char *id_cbrackets = "";
    const char *id_comma = "";

    memset(endopts, 0, sizeof(endopts));

    if (isanyaddr(&this->host_addr))
    {
	if(this->host_type == KH_IPHOSTNAME) {
	    host = strcpy(host_space, "%dns");
	    dohost_name=TRUE;
	} else {
	    switch (policy & (POLICY_GROUP | POLICY_OPPO))
	    {
	    case POLICY_GROUP:
		host = "%group";
		break;
	    case POLICY_OPPO:
		host = "%opportunistic";
		break;
	    case POLICY_GROUP | POLICY_OPPO:
		host = "%opportunisticgroup";
		break;
	    default:
		host = "%any";
		break;
	    }
	}
    }

    client[0] = '\0';

    if (is_virtual_end(this) && isanyaddr(&this->host_addr)) {
	host = "%virtual";
    }

    /* [client===] */
    if (this->has_client)
    {
	ip_address client_net, client_mask;

	networkof(&this->client, &client_net);
	maskof(&this->client, &client_mask);
	client_sep = "===";

 	/* {client_subnet_wildcard} */
 	if (this->has_client_wildcard)
 	{
 	    open_brackets  = "{";
 	    close_brackets = "}";
 	}

	if (isanyaddr(&client_net) && isanyaddr(&client_mask)
	&& (policy & (POLICY_GROUP | POLICY_OPPO)))
	    client_sep = "";	/* boring case */
	else if (subnetisnone(&this->client))
	    strcpy(client, "?");
	else
	    subnettot(&this->client, 0, client, sizeof(client));
    }

    /* host */
    if (host == NULL)
    {
	addrtot(&this->host_addr, 0, host_space, sizeof(host_space));
	host = host_space;
        if(this->host_type != KH_IPADDR) {
            dohost_name=TRUE;
        }
    }

    if(dohost_name) {
    	if(this->host_addr_name) {
		size_t icl = strlen(host_space);
		size_t room = sizeof(host_space) - icl - 1;
		int needed = snprintf(host_space + icl, room, "<%s>", this->host_addr_name);

		if (needed > (signed)room) {
		   loglog(RC_BADID, "format_end: buffer too small for dohost_name - should not happen\n");
		}
	}
    }

    host_port[0] = '\0';
    if (this->host_port_specific)
	snprintf(host_port, sizeof(host_port), ":%u"
	    , this->host_port);

    /* payload portocol and port */
    protoport[0] = '\0';
    if (this->has_port_wildcard)
	snprintf(protoport, sizeof(protoport), ":%u/%%any", this->protocol);
    else if (this->port || this->protocol)
	snprintf(protoport, sizeof(protoport), ":%u/%u", this->protocol
	    , this->port);

    /* id, if different from host */
    host_id[0] = '\0';
    if (this->id.kind == ID_MYID)
    {
	id_obrackets = "[";
	id_cbrackets = "]";
	strcpy(host_id, "%myid");
    }
    else if (!(this->id.kind == ID_NONE
    || (id_is_ipaddr(&this->id) && sameaddr(&this->id.ip_addr, &this->host_addr))))
    {
	id_obrackets = "[";
	id_cbrackets = "]";
	idtoa(&this->id, host_id, sizeof(host_id));
    }

#if defined(XAUTH)
    if(this->modecfg_server || this->modecfg_client
       || this->xauth_server || this->xauth_client
       || this->sendcert != cert_defaultcertpolicy)
    {
	const char *plus = "+";
	endopts[0]='\0';

	if(id_obrackets[0]=='[')
	{
	    id_comma=",";
	} else {
	    id_obrackets = "[";
	    id_cbrackets = "]";
	}

	if(this->modecfg_server) {
	    strncat(endopts, "MS", sizeof(endopts) - strlen(endopts)-1);
	}

	if(this->modecfg_client) {
	    strncat(endopts, plus, sizeof(endopts) - strlen(endopts)-1);
	    strncat(endopts, "MC", sizeof(endopts) - strlen(endopts)-1);
	}

	if(this->xauth_server) {
	    strncat(endopts, plus, sizeof(endopts) - strlen(endopts)-1);
	    strncat(endopts, "XS", sizeof(endopts) - strlen(endopts)-1);
	}

	if(this->xauth_client) {
	    strncat(endopts, plus, sizeof(endopts) - strlen(endopts)-1);
	    strncat(endopts, "XC", sizeof(endopts) - strlen(endopts)-1);
	}

	{
	    const char *send_cert = "";
	    char s[32];

	    send_cert=""; /* Length 3 because cert.type is 1-11 */

	    switch(this->sendcert) {
	    case cert_neversend:
		send_cert="S-C";
		break;
	    case cert_sendifasked:
		send_cert="S?C";
		break;
	    case cert_alwayssend:
		send_cert="S=C";
		break;
	    case cert_forcedtype:
		sprintf(s, "S%d", this->cert.type);
		send_cert=s;
		break;
	    }
	    strncat(endopts, plus, sizeof(endopts) - strlen(endopts)-1);
	    strncat(endopts, send_cert, sizeof(endopts) - strlen(endopts)-1);
	}
    }
#endif

    /* [---hop] */
    hop[0] = '\0';
    hop_sep = "";
    /* do not format if nexthop is invalid.
     * skip if nexhop is actually right=
     */
    if (that != NULL
        && !sameaddr(&this->host_nexthop, &that->host_addr)
        && addrtypeof(&this->host_nexthop)!=0
        && KH_ISKNOWNADDR(this->host_type)
        && addrbytesptr(&this->host_nexthop, NULL)!=0)
    {
	addrtot(&this->host_nexthop, 0, hop, sizeof(hop));
	hop_sep = "---";
    }

    if (is_left)
	snprintf(buf, buf_len, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s"
	    , open_brackets, client, close_brackets
	    , client_sep, host, host_port
		 , id_obrackets, host_id, id_comma, endopts, id_cbrackets
	    , protoport, hop_sep, hop);
    else
	snprintf(buf, buf_len, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s"
	    , hop, hop_sep, host, host_port
		 , id_obrackets, host_id, id_comma, endopts, id_cbrackets
	    , protoport, client_sep
	    , open_brackets, client, close_brackets);
    return strlen(buf);
}

/* format topology of a connection.
 * Two symmetric ends separated by ...
 */
size_t
format_connection(char *buf, size_t buf_len
		  , const struct connection *c
		  , struct spd_route *sr)
{
    size_t w = format_end(buf, buf_len, &sr->this, &sr->that, TRUE, LEMPTY);
    snprintf(buf + w, buf_len - w, "...");
    w += strlen(buf + w);
    return w + format_end(buf + w, buf_len - w, &sr->that, &sr->this, FALSE, c->policy);
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
