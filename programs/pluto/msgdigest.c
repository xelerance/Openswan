/* demultiplex incoming IKE messages
 * Copyright (C) 1997 Angelos D. Keromytis.
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
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "pluto/connections.h"	/* needs id.h */
#include "pluto/state.h"
#include "packet.h"
#include "md5.h"
#include "sha1.h"
#include "pluto/crypto.h" /* requires sha1.h and md5.h */
#include "pluto/ike_alg.h"
#include "log.h"
#include "demux.h"	/* needs packet.h */

/* message digest allocation and deallocation */

static struct msg_digest *md_pool = NULL;

/* free_md_pool is only used to avoid leak reports */
void
free_md_pool(void)
{

    for (;;)
    {
	struct msg_digest *md = md_pool;

	if (md == NULL)
	    break;
	passert(md_pool != md->next);
	md_pool = md->next;
	pfree(md);
    }
}

struct msg_digest *
alloc_md(void)
{
    struct msg_digest *md = md_pool;

    /* convenient initializer:
     * - all pointers NULL
     * - .note = NOTHING_WRONG
     * - .encrypted = FALSE
     */
    static const struct msg_digest blank_md;

    if (md == NULL)
	md = alloc_thing(struct msg_digest, "msg_digest");
    else
	md_pool = md->next;

    *md = blank_md;
    md->digest_roof = md->digest;

    /* note: although there may be multiple msg_digests at once
     * (due to suspended state transitions), there is a single
     * global reply_buffer.  It will need to be saved and restored.
     */
    init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer), "reply packet");

    return md;
}

struct state *looking_for_state = NULL;
struct msg_digest *looking_for_md = NULL;

void
release_md(struct msg_digest *md)
{
	if (!md)
		return;
    passert(looking_for_md == NULL || md != looking_for_md);
    passert(looking_for_state == NULL || md->st != looking_for_state);
    freeanychunk(md->raw_packet);
    pfreeany(md->packet_pbs.start);

    /* make sure we are not creating a loop */
    passert(md != md_pool);
    md->packet_pbs.start = NULL;
    md->next = md_pool;
    md_pool = md;
}

