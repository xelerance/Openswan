/* Security Policy Data Base (such as it is)
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2003-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2008 Paul Wouters <paul@xelerance.com>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>
#include "openswan/pfkeyv2.h"

#include "sysdep.h"
#include "constants.h"
#include "oswlog.h"

#include "defs.h"
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
#include "keys.h"
#include "secrets.h"
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "pluto/spdb.h"
#include "whack.h"	/* for RC_LOG_SERIOUS */
#include "pluto/plutoalg.h"

#include "sha1.h"
#include "md5.h"
#include "pluto/crypto.h" /* requires sha1.h and md5.h */

#include "alg_info.h"
#include "kernel_alg.h"
#include "pluto/ike_alg.h"
#include "db_ops.h"

#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

/*
 * empty structure, for clone use.
 */
static struct db_attr otempty[] = {
	{ .type.oakley=OAKLEY_ENCRYPTION_ALGORITHM, -1 },
	{ .type.oakley=OAKLEY_HASH_ALGORITHM,       -1 },
	{ .type.oakley=OAKLEY_AUTHENTICATION_METHOD, -1 },
	{ .type.oakley=OAKLEY_GROUP_DESCRIPTION,    -1 },
	{ .type.oakley=OAKLEY_KEY_LENGTH,    -1 },
	};

static struct db_trans oakley_trans_empty[] = {
    { AD_TR(KEY_IKE, otempty) },
};

static struct db_prop oakley_pc_empty[] =
{ { AD_PR(PROTO_ISAKMP, oakley_trans_empty) } };

static struct db_prop_conj oakley_props_empty[] = {{ AD_PC(oakley_pc_empty) }};

struct db_sa oakley_empty = { AD_SAp(oakley_props_empty) };

/*	check if IKE PRF algo is present */
extern bool ike_alg_prf_present(int prfalg);

/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * End:
 */
