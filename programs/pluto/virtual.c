/* Openswan Virtual IP Management
 * Copyright (C) 2002 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2004 Xelerance Corporation
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
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


#include <openswan.h>

#include <stdlib.h>
#include <string.h>

#include "sysdep.h"
#include "constants.h"
#include "oswlog.h"

#include "defs.h"
#include "log.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "connections.h"
#include "whack.h"
#include "virtual.h"

#define F_VIRTUAL_NO          1
#define F_VIRTUAL_DHCP        2
#define F_VIRTUAL_IKE_CONFIG  4
#define F_VIRTUAL_PRIVATE     8
#define F_VIRTUAL_ALL         16
#define F_VIRTUAL_HOST        32

struct virtual_t {
    unsigned short flags;
    unsigned short n_net;
    ip_subnet net[0];
};

static ip_subnet *private_net_ok=NULL, *private_net_ko=NULL;
static unsigned short private_net_ok_len=0, private_net_ko_len=0;

/** Read a subnet (IPv4/IPv6)
 * read %v4:x.x.x.x/y or %v6:xxxxxxxxx/yy
 * or %v4:!x.x.x.x/y if dstko not NULL
 *
 * @param src String in format (see above)
 * @param len Length of src string
 * @param dst IP Subnet Destination
 * @param dstko IP Subnet
 * @param isok Boolean
 * @return bool If the format string is valid.
 */
static bool
_read_subnet(const char *src, size_t len, ip_subnet *dst, ip_subnet *dstko,
    bool *isok)
{
    bool ok;
    int af;
    /* workaround for typo "%4:" instead of "%v4:" introduced in old openswan release*/
    int offset=0;

    if ((len > 4) && (strncmp(src, "%v4:", 4)==0)) {
	af = AF_INET;
    }
    else if ((len > 4) && (strncmp(src, "%v6:", 4)==0)) {
	af = AF_INET6;
    }
    else if ((len > 4) && (strncmp(src, "%4:", 3)==0)) {
	af = AF_INET;
	offset=-1;
	loglog(RC_LOG_SERIOUS, "fixup for bad virtual_private entry '%s', please fix your virtual_private line!",src);
    }
    else {
	return FALSE;
    }

    ok = (src[4+offset] == '!') ? FALSE : TRUE;
    src += ok ? (4+offset) : (5+offset);
    len -= ok ? (4+offset) : (5+offset);

    if (!len) return FALSE;
    if ((!ok) && (!dstko)) return FALSE;

    passert ( ((ok)?(dst):(dstko))!=NULL );

    if (ttosubnet(src, len, af, ((ok)?(dst):(dstko)))) {
	loglog(RC_LOG_SERIOUS,"fail in ttosubnet ?");
	return FALSE;
    }
    if (isok) *isok = ok;
    return TRUE;
}

/** Initialize Virtual IP Support
 *
 * @param private_list String (contents of virtual_private= from ipsec.conf)
 */
void
init_virtual_ip(const char *private_list)
{
    const char *next, *str=private_list;
    unsigned short ign = 0, i_ok, i_ko;
    ip_subnet sub;
    bool ok;

    /** Count **/
    private_net_ok_len=0;
    private_net_ko_len=0;
    while (str) {
	next = strchr(str,',');
	if (!next) next = str + strlen(str);
	if (_read_subnet(str, next-str, &sub, &sub, &ok)) {
	    if (ok)
		private_net_ok_len++;
	    else
		private_net_ko_len++;
	}
	else {
	    ign++;
	}
	str = *next ? next+1 : NULL;
    }

    if (!ign) {
	/** Allocate **/
	if (private_net_ok_len) {
	    private_net_ok = (ip_subnet *)alloc_bytes(
		(private_net_ok_len*sizeof(ip_subnet)),
		"private_net_ok subnets");
	}
	if (private_net_ko_len) {
	    private_net_ko = (ip_subnet *)alloc_bytes(
		(private_net_ko_len*sizeof(ip_subnet)),
		"private_net_ko subnets");
	}
	if ((private_net_ok_len && !private_net_ok) ||
	    (private_net_ko_len && !private_net_ko)) {
	    loglog(RC_LOG_SERIOUS,
		"can't alloc in init_virtual_ip");
	    pfreeany(private_net_ok);
	    private_net_ok = NULL;
	    pfreeany(private_net_ko);
	    private_net_ko = NULL;
	}
	else {
	    /** Fill **/
	    str = private_list;
	    i_ok = 0;
	    i_ko = 0;
	    while (str) {
		next = strchr(str,',');
		if (!next) next = str + strlen(str);
		if (_read_subnet(str, next-str,
		   &(private_net_ok[i_ok]), &(private_net_ko[i_ko]), &ok)) {
		    if (ok)
			i_ok++;
		    else
			i_ko++;
		}
		str = *next ? next+1 : NULL;
	    }
	}
    }
    else {
	loglog(RC_LOG_SERIOUS,
	    "%d bad entries in virtual_private - none loaded", ign);
    }
}

/**
 * virtual string must be :
 * {vhost,vnet}:[%method]*
 *
 * vhost = accept only a host (/32)
 * vnet  = accept any network
 *
 * %no   = no virtual IP (accept public IP)
 * %dhcp = accept DHCP SA (0.0.0.0/0) of affected IP  [not implemented]
 * %ike  = accept affected IKE Config Mode IP         [not implemented]
 * %priv = accept system-wide private net list
 * %v4:x = accept ipv4 in list 'x'
 * %v6:x = accept ipv6 in list 'x'
 * %all  = accept all ips                             [only for testing]
 *
 * ex: vhost:%no,%dhcp,%priv,%v4:192.168.1.0/24
 *
 * @param c Connection Struct
 * @param string (virtual_private= from ipsec.conf)
 * @return virtual_t
 */
struct virtual_t
*create_virtual(const struct connection *c, const char *string)
{
    unsigned short flags=0, n_net=0, i;
    const char *str = string, *next, *first_net=NULL;
    ip_subnet sub;
    struct virtual_t *v;

    if ((!string) || (string[0]=='\0')) return NULL;

    if ((strlen(string)>=6) && (strncmp(string,"vhost:",6)==0)) {
	flags |= F_VIRTUAL_HOST;
	str += 6;
    }
    else if ((strlen(string)>=5) && (strncmp(string,"vnet:",5)==0)) {
	str += 5;
    }
    else {
	goto fail;
    }

    /**
     * Parse string : fill flags & count subnets
     */
    while ((str) && (*str)) {
	next = strchr(str,',');
	if (!next) next = str + strlen(str);
	if ((next-str == 3) && (strncmp(str, "%no", 3)==0)) {
	    flags |= F_VIRTUAL_NO;
	}
#if 0
	else if ((next-str == 4) && (strncmp(str, "%ike", 4)==0)) {
	    flags |= F_VIRTUAL_IKE_CONFIG;
	}
	else if ((next-str == 5) && (strncmp(str, "%dhcp", 5)==0)) {
	    flags |= F_VIRTUAL_DHCP;
	}
#endif
	else if ((next-str == 5) && (strncmp(str, "%priv", 5)==0)) {
	    flags |= F_VIRTUAL_PRIVATE;
	}
	else if ((next-str == 4) && (strncmp(str, "%all", 4)==0)) {
	    flags |= F_VIRTUAL_ALL;
	}
	else if (_read_subnet(str, next-str, &sub, NULL, NULL)) {
	    n_net++;
	    if (!first_net) first_net = str;
	}
	else {
	    goto fail;
	}
	str = *next ? next+1 : NULL;
    }

    v = (struct virtual_t *)alloc_bytes(
	sizeof(struct virtual_t) + (n_net*sizeof(ip_subnet)),
	"virtual description");
    if (!v) goto fail;

    v->flags = flags;
    v->n_net = n_net;
    if (n_net && first_net) {
	/**
	 * Save subnets in newly allocated struct
	 */
	for (str=first_net, i=0; (str) && (*str); ) {
	    next = strchr(str,',');
	    if (!next) next = str + strlen(str);
	    if (_read_subnet(str, next-str, &(v->net[i]), NULL, NULL))
		i++;
	    str = *next ? next+1 : NULL;
	}
    }

    return v;

fail:
    openswan_log("invalid virtual string [%s] - "
	"virtual selection disabled for connection '%s'", string, c->name);
    return NULL;
}

/** is_virtual_end - Do we have a virtual IP on the other end?
 *
 * @param that end structure
 * @return bool True if we do
 */
bool
is_virtual_end(const struct end *that)
{
    return ((that->virt)?TRUE:FALSE);
}

/** Does this connection have a virtual IP ?
 *
 * @param c Active Connection struct
 * @return bool True if we do
 */
bool
is_virtual_connection(const struct connection *c)
{
    const struct spd_route *sr;
    for (sr = &c->spd; sr != NULL; sr = sr->next)
    {
	if(sr->that.virt) return TRUE;
    }
    return FALSE;
}

/** Does this spd have a virtual IP ?
 *
 * @param c Active Connection struct
 * @return bool True if we do
 */
bool
is_virtual_sr(const struct spd_route *sr)
{
    return ((sr->that.virt)?TRUE:FALSE);
}

/** net_in_list - Check if a subnet is in a list
 *
 * @param peer_net IP Subnet to check
 * @param list IP Subnet list to search within
 * @param len # of subnets in list
 * @return bool True if peer_net is in list
 */
static bool
net_in_list(const ip_subnet *peer_net, const ip_subnet *list,
    unsigned short len)
{
    unsigned short i;
    if (!list || !len) return FALSE;
    for (i=0; i<len; i++) {
	if (subnetinsubnet(peer_net, &(list[i])))
	    return TRUE;
    }
    return FALSE;
}

/** is_virtual_net_allowed -
 * Check if the virtual network the client proposes is acceptable to us
 *
 * @param c Connection structure (active)
 * @param peer_net IP Subnet the peer proposes
 * @param his_addr Peers IP Address
 * @return bool True if allowed
 */
err_t
is_virtual_net_allowed(const struct connection *c, const ip_subnet *peer_net,
	const ip_address *his_addr)
{
    err_t why = NULL;

    if (!c->spd.that.virt) return NULL;

    if (c->spd.that.virt->flags & F_VIRTUAL_HOST) {
	if (!subnetishost(peer_net)) {
	    why = "only virtual host IPs are allowed";
	    return why;
	}
    }

    if (c->spd.that.virt->flags & F_VIRTUAL_NO) {
	if (subnetishost(peer_net) &&
	    addrinsubnet(his_addr, peer_net))
	    return NULL;
    }

    if (c->spd.that.virt->flags & F_VIRTUAL_PRIVATE) {
	if (net_in_list(peer_net, private_net_ok, private_net_ok_len) &&
	    !net_in_list(peer_net, private_net_ko, private_net_ko_len))
	    return NULL;
	why = "a private network virtual IP was required, but the proposed IP did not match our list (virtual_private=)";
    }

    if (c->spd.that.virt->n_net) {
	if (net_in_list(peer_net, c->spd.that.virt->net, c->spd.that.virt->n_net))
	    return NULL;
	why = "a specific network IP was required, but the proposed IP did not match our list (subnet=vhost:list)";
    }

    if (c->spd.that.virt->flags & F_VIRTUAL_ALL) {
	/* %all must only be used for testing - log it */
	loglog(RC_LOG_SERIOUS, "Warning - "
	    "v%s:%%all must only be used for testing",
	    (c->spd.that.virt->flags & F_VIRTUAL_HOST) ? "host" : "net");
	return NULL;
    }

    return why;
}

void
show_virtual_private()
{
    char allowed[SUBNETTOT_BUF];
    char disallowed[SUBNETTOT_BUF];
    char all_ok[256] = ""; /* arbitrary limit */
    char all_ko[256] = ""; /* arbitrary limit */
    int i,truncok=0,truncko=0;

    if (private_net_ok!=NULL) {
	for (i=0;i<private_net_ok_len;i++) {
	    subnettot(&private_net_ok[i], 0, allowed, sizeof(allowed));
	    if(i!=0)
		strcat(all_ok, ", ");
	    if( (strlen(all_ok) + strlen(allowed)) <= 255)
		strcat(all_ok, allowed);
	    else {
		truncok = 1;
		i = private_net_ok_len;
	    }
	};
    } else all_ok[0] = '\0';

    if (private_net_ko!=NULL) {
	for (i=0;i<private_net_ko_len;i++) {
	    subnettot(&private_net_ko[i], 0, disallowed, sizeof(disallowed));
	    if(i!=0)
		strcat(all_ko, ", ");
	    if( (strlen(all_ko) + strlen(disallowed)) <= 255)
		strcat(all_ko, disallowed);
	    else {
		truncko = 1;
		i = private_net_ko_len;
	    };
	};
    } else all_ko[0] = '\0';

    whack_log(RC_COMMENT, "virtual_private (%%priv):");
    whack_log(RC_COMMENT, "- allowed %d subnet%s: %s",
	      private_net_ok_len,
	      (private_net_ok_len == 1) ? "" : "s", all_ok );

    whack_log(RC_COMMENT, "- disallowed %d subnet%s: %s",
	      private_net_ko_len,
	      (private_net_ko_len == 1) ? "" : "s", all_ko );
    if (truncok || truncko)
	whack_log(RC_COMMENT, "WARNING: some virtual_private entries were not shown, do you really need that many?");
    if (!truncok && !truncko && !strlen(all_ok)) {
	whack_log(RC_COMMENT, "WARNING: Either virtual_private= is not specified, or there is a syntax\n");
	whack_log(RC_COMMENT, "         error in that line. 'left/rightsubnet=vhost:%%priv' will not work!");
    }
    if (!truncok && !truncko && !strlen(all_ko)) {
	whack_log(RC_COMMENT, "WARNING: Disallowed subnets in virtual_private= is empty. If you have\n");
	whack_log(RC_COMMENT, "         private address space in internal use, it should be excluded!");
    }
}
