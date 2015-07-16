/* how to arrange connections: which end am I?
 * Copyright (C) 2015 Michael Richardson <mcr@xelerance.com>
 *
 * based upon ../../programs/pluto/initiate.c
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
#include <netinet/in.h>
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
#include "pluto/keys.h"

#include "pluto/server.h"
#include "pluto/connections.h"	/* needs id.h */

size_t
endclienttot(const struct end *end, char *dst, size_t dstlen)
{
    char typebuf[KEYWORD_NAME_BUFLEN];
    int  len, rest;
    char *p;
    if(end->has_client) {
        len = subnettot(&end->client,  0, dst, dstlen);
    } else {
        switch(end->host_type) {
        case KH_ANY:
            len = snprintf(dst, dstlen, "%%self/32");
            break;
        default:
            len = snprintf(dst, dstlen, "<type:%s>", keyword_name(&kw_host_list, end->host_type, typebuf));
            break;
        }
    }

    if(len < dstlen) {
        dst[len - 1] = ':';
        p = dst + len;
        rest = dstlen - len;
    } else {
        p = NULL;
        rest = 0;
    }
    /* assumes that snprintf() is okay with p=NULL, if rest == 0 */
    len += snprintf(p, rest, "%u/%u", end->protocol, end->port);
    return len;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
